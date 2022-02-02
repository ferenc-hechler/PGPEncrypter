package de.hechler.pgpencrypter;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ConcurrentHashMap;

import de.hechler.pgpencrypter.encrypt.Encrypter;
import de.hechler.pgpencrypter.encrypt.Encrypter.EncryptResult;
import de.hechler.pgpencrypter.filesystem.FileChangesCollector;
import de.hechler.pgpencrypter.filesystem.FileInfo;
import de.hechler.pgpencrypter.filesystem.FolderWatcher;
import de.hechler.pgpencrypter.pcloud.PCloudUploader;
import de.hechler.pgpencrypter.persist.Deserializer;




/**
 * https://gh.pgpainless.org/
 * https://github.com/pgpainless/pgpainless/blob/master/README.md
 * 
 * @author feri
 *
 */
public class SyncCloudEncrypted {

	private static final boolean TRUST_LAST_MODIFIED_TIMESTAMP = true;
	private static final long FULL_SAVE_INTERVAL_MS = 3600000L;   // 1h

	private Path publicKey;
	private Path inputFolder;
	private Path cloudFolder;
	private Path syncCacheCSVFile;
	private Path tempUploadFile;

	private ConcurrentHashMap<Path, FileInfo> syncedFiles;
	private long lastFullSaveSyncedFiles;
	
	private PCloudUploader uploader;
	
	public SyncCloudEncrypted(String publicKeyFilename, String inputFoldername, String cloudFoldername, String syncCacheCSVFilename, String tempUploadFilename) {
		this(Paths.get(publicKeyFilename), Paths.get(inputFoldername), Paths.get(cloudFoldername), Paths.get(syncCacheCSVFilename), Paths.get(tempUploadFilename));
	}

	public SyncCloudEncrypted(Path publicKey, Path inputFolder, Path cloudFolder, Path syncCacheCSVFile, Path tempUploadFile) {
		this.publicKey = publicKey;
		this.inputFolder = inputFolder;
		this.cloudFolder = cloudFolder;
		this.syncCacheCSVFile = syncCacheCSVFile;
		this.tempUploadFile = tempUploadFile;
		this.syncedFiles = new ConcurrentHashMap<>();
		this.lastFullSaveSyncedFiles = 0;
		this.uploader = new PCloudUploader();
	}
	
	public boolean readCache() {
		lastFullSaveSyncedFiles = System.currentTimeMillis();
		syncedFiles = new ConcurrentHashMap<>();
		if (!Files.exists(syncCacheCSVFile)) {
			return true;
		}
		try (Deserializer deser = new Deserializer(new BufferedReader(new InputStreamReader(new FileInputStream(syncCacheCSVFile.toFile()), StandardCharsets.UTF_8)))) {
			deser.nextRecord(); // skip header
			while (true) {
				FileInfo fileInfo = FileInfo.fromCSV(deser);
				if (fileInfo == null) {
					break;
				}
				syncedFiles.put(fileInfo.file, fileInfo);
			}
			return true;
		} 
		catch (IOException e) {
			System.err.println("Error reading synced files cache: "+e.toString());
			return false;
		}		
	}

	
	public boolean save(FileInfo fi) {
		boolean ok = quickSaveCache(fi);
		if (!ok) {
			return fullSaveCache();
		}
		if (System.currentTimeMillis() - lastFullSaveSyncedFiles < FULL_SAVE_INTERVAL_MS) {
			return true;
		}
		return fullSaveCache();
	}


	public boolean fullSaveCache() {
		try {
			System.out.println("FULLSAVE '"+syncCacheCSVFile+"'");
			long now = System.currentTimeMillis();
			if (Files.exists(syncCacheCSVFile)) {
				Path backupFile = syncCacheCSVFile.resolveSibling(syncCacheCSVFile.getFileName().toString()+"_BAK");
				Files.move(syncCacheCSVFile, backupFile, StandardCopyOption.REPLACE_EXISTING);
			}
			try (PrintStream out = new PrintStream(syncCacheCSVFile.toFile(), StandardCharsets.UTF_8.toString())) {
				out.println(FileInfo.headerCSV());
				syncedFiles.values().forEach(fi -> out.println(fi.toCSV()));
			} 
			lastFullSaveSyncedFiles = now;
			return true;
		}
		catch (IOException e) {
			System.err.println("Error writing synced files cache: "+e.toString());
			return false;
		}
	}
	
	public boolean quickSaveCache(FileInfo fi) {
		if (!Files.exists(syncCacheCSVFile)) {
			return false;
		}
		try (PrintStream out = new PrintStream(new FileOutputStream(syncCacheCSVFile.toFile(), true), false, StandardCharsets.UTF_8.toString())) {
			out.println(fi.toCSV());
			return true;
		}
		catch (IOException e) {
			System.err.println("Error in quicksave: "+e.toString());
			return false;
		}
	}
	
	public void startSync() {
		try {
			Files.createDirectories(inputFolder);
			Files.createDirectories(tempUploadFile.getParent());
			if (syncCacheCSVFile.getParent() != null) {
				Files.createDirectories(syncCacheCSVFile.getParent());
			}
			readCache();
			System.out.println("synced files cache entries: "+syncedFiles.size());
			Encrypter enc = new Encrypter(publicKey);
			FileChangesCollector collector = new FileChangesCollector();
			FolderWatcher fw = new FolderWatcher(inputFolder, collector);
			fw.startEventLoop();
			while (true) {
				FileInfo currentFI = collector.getNextChangedFile(60000);
				if (currentFI == FileChangesCollector.TIMEOUT_FILEINFO) {
					PCloudUploader.shutdownApiClient();
					continue;
				}
				if (currentFI == null) {
					// all watched folders got invalid (folder deleted?)
					break;
				}
				long now = System.currentTimeMillis();
				Path sourceFile = currentFI.file;
            	Path relSource = inputFolder.relativize(sourceFile);
				FileInfo existingFI = FileInfo.createCopy(syncedFiles.get(relSource));
				currentFI.lastEventTimestamp = now;
				currentFI.fileSize = Files.size(sourceFile);
				currentFI.lastModifiedTimestamp = Files.getLastModifiedTime(sourceFile).toMillis();
				currentFI.sourceHash = null;
				currentFI.targetHash = null;
				if (preCheckNoChanges(currentFI, existingFI)) {
					continue;
				}
				currentFI.sourceHash = calcSHA256(sourceFile);
				if (checkNoLocalChanges(currentFI, existingFI)) {
					continue;
				}
				String shortHash = calcShortHash(currentFI.sourceHash, currentFI.fileSize);
				String targetFilename = calcHashedFilename(sourceFile.getFileName().toString(), shortHash);
            	Path cloudTargetFile = cloudFolder.resolve(relSource).resolveSibling(targetFilename);
        		EncryptResult encryptResult = enc.encrypt(sourceFile, tempUploadFile);
        		System.out.println("ENCRYPTED: "+relSource+"  "+encryptResult);
        		if ((currentFI.fileSize != encryptResult.sourceFilesize) || (!currentFI.sourceHash.equals(encryptResult.sourceSHA256))) {
        			System.err.println("Source file '"+sourceFile+"' changed during encryption!");
        			String newShortHash = calcShortHash(encryptResult.sourceSHA256, encryptResult.sourceFilesize);
        			String newTargetFilename = calcHashedFilename(sourceFile.getFileName().toString(), newShortHash);
        			cloudTargetFile = cloudFolder.resolve(relSource).resolveSibling(newTargetFilename);
        		}
        		Path oldCloudFile = null;
        		if (existingFI == null) {
        			existingFI = new FileInfo(relSource, now, -1, -1, null, null);
        		}
        		else {
    				String oldShortHash = calcShortHash(existingFI.sourceHash, existingFI.fileSize);
    				String oldCloudFilename = calcHashedFilename(relSource.getFileName().toString(), oldShortHash); 
                	oldCloudFile = cloudFolder.resolve(relSource).resolveSibling(oldCloudFilename);
        		}
    			existingFI.lastEventTimestamp = now;
        		removeCloudFile(oldCloudFile);
        		uploadToCloud(tempUploadFile, cloudTargetFile);
        		deleteTempUploadFile();
    			existingFI.lastModifiedTimestamp = currentFI.lastModifiedTimestamp;
    			existingFI.fileSize = encryptResult.sourceFilesize;
    			existingFI.sourceHash = encryptResult.sourceSHA256;
    			existingFI.targetHash = encryptResult.targetSHA256;
    			syncedFiles.put(relSource, existingFI);
    			save(existingFI);
			}
			System.out.println("EncryptIt finished");
			PCloudUploader.shutdownApiClient();
		} catch (IOException e) {
			PCloudUploader.shutdownApiClient();
			throw new RuntimeException(e.toString(), e);
		} 
	}

	private void deleteTempUploadFile() throws IOException {
		try {
			Files.deleteIfExists(tempUploadFile);
		}
		catch (Exception e) {
			System.err.println("ERROR deleteing temp upload file "+e.toString());
		}
	}

	private void uploadToCloud(Path localFile, Path cloudTarget) {
		try (InputStream in = new FileInputStream(localFile.toFile())) {
			uploader.uploadFile(cloudTarget, in);
			System.out.println("UPLOADED "+PCloudUploader.rPath(cloudTarget));
		}
		catch (Exception e) {
			System.err.println("ERROR uploading "+PCloudUploader.rPath(cloudTarget));
		}
	}
	

	private void removeCloudFile(Path oldCloudFile) {
		if (oldCloudFile == null) {
			return;
		}
		String remotePath = PCloudUploader.rPath(oldCloudFile);
		try {
			boolean ok = PCloudUploader.getApiClient().deleteFile(remotePath).execute();
			if (ok) {
				System.out.println("REMOVED "+remotePath);
			}
		}
		catch (Exception e) {
			System.err.println("Error deleting "+remotePath);
		}
	}

	private boolean preCheckNoChanges(FileInfo currentFI, FileInfo existingFI) {
		if ((existingFI == null) || !TRUST_LAST_MODIFIED_TIMESTAMP) {
			return false;
		}
		return (currentFI.fileSize == existingFI.fileSize) && (currentFI.lastModifiedTimestamp == existingFI.lastModifiedTimestamp);
	}

	private boolean checkNoLocalChanges(FileInfo currentFI, FileInfo existingFI) {
		if (existingFI == null) {
			return false;
		}
		return currentFI.sourceHash.equals(existingFI.sourceHash);
	}

	private String calcHashedFilename(String sourceFilename, String shortHash) {
		String result = sourceFilename;
		int dotPos = result.lastIndexOf('.');
		if (dotPos == -1) {
			result = result+"-"+shortHash+".pgp";
		}
		else {
			result = result.substring(0, dotPos)+"-"+shortHash+result.substring(dotPos)+".pgp";
		}
		return result;
	}
	
	private String calcSHA256(Path file) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] buffer = new byte[32768];
			try (FileInputStream in = new FileInputStream(file.toFile())) {
				while (true) {
					int cnt = in.read(buffer);
					if (cnt <= 0) {
						break;
					}
					md.update(buffer, 0, cnt);
				}
			}
			byte[] bytes = md.digest();
	        StringBuilder result = new StringBuilder();
	        for (byte b : bytes) {
	            result.append(String.format("%02x", b));
	        }
	        return result.toString();
		} catch (NoSuchAlgorithmException | IOException e) {
			throw new RuntimeException(e.toString(), e);
		}
	}

	private String calcShortHash(String hash, long filesize) {
		String actualParameters = "calcShortHash(\""+hash+"\","+filesize+")";
		String result = calcSHA256(actualParameters);
		return result.substring(0, 8);
	}
	
	private String calcSHA256(String text) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(text.getBytes(StandardCharsets.UTF_8));
			byte[] bytes = md.digest();
	        StringBuilder result = new StringBuilder();
	        for (byte b : bytes) {
	            result.append(String.format("%02x", b));
	        }
	        return result.toString();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e.toString(), e);
		}
	}

	
}
