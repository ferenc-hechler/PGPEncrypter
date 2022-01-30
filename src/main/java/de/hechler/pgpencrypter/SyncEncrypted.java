package de.hechler.pgpencrypter;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
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
import de.hechler.pgpencrypter.persist.Deserializer;




/**
 * https://gh.pgpainless.org/
 * https://github.com/pgpainless/pgpainless/blob/master/README.md
 * 
 * @author feri
 *
 */
public class SyncEncrypted {

	private static final boolean TRUST_LAST_MODIFIED_TIMESTAMP = true;
	private static final long FULL_SAVE_INTERVAL_MS = 3600000L;   // 1h

	private Path publicKey;
	private Path inputFolder;
	private Path outputFolder;
	private Path syncCacheCSVFile;

	private ConcurrentHashMap<Path, FileInfo> syncedFiles;
	private long lastFullSaveSyncedFiles;
	
	public SyncEncrypted(String publicKeyFilename, String inputFoldername, String outputfoldername, String syncCacheCSVFilename) {
		this(Paths.get(publicKeyFilename), Paths.get(inputFoldername), Paths.get(outputfoldername), Paths.get(syncCacheCSVFilename));
	}

	public SyncEncrypted(Path publicKey, Path inputFolder, Path outputFolder, Path syncCacheCSVFile) {
		this.publicKey = publicKey;
		this.inputFolder = inputFolder;
		this.outputFolder = outputFolder;
		this.syncCacheCSVFile = syncCacheCSVFile;
		this.syncedFiles = new ConcurrentHashMap<>();
		this.lastFullSaveSyncedFiles = 0;
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
			Files.createDirectories(outputFolder);
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
				FileInfo currentFI = collector.getNextChangedFile();
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
            	Path targetFile = outputFolder.resolve(relSource).resolveSibling(targetFilename);
            	Files.createDirectories(targetFile.getParent());
        		EncryptResult encryptResult = enc.encrypt(sourceFile, targetFile);
        		System.out.println("ENCRYPTED: "+targetFile+"  "+encryptResult);
        		if ((currentFI.fileSize != encryptResult.sourceFilesize) || (!currentFI.sourceHash.equals(encryptResult.sourceSHA256))) {
        			System.err.println("Source file '"+sourceFile+"' changed during encryption!");
        			renameTargetFileHash(currentFI, existingFI, targetFile, encryptResult);
        		}
        		if (existingFI == null) {
        			existingFI = new FileInfo(relSource, now, -1, -1, null, null);
        		}
        		else {
    				String oldShortHash = calcShortHash(existingFI.sourceHash, existingFI.fileSize);
    				String oldTargetFilename = calcHashedFilename(relSource.getFileName().toString(), oldShortHash); 
                	Path oldTargetFile = outputFolder.resolve(relSource).resolveSibling(oldTargetFilename);
                	removeOutdatedTargetFile(oldTargetFile);
        		}
    			existingFI.lastEventTimestamp = now;
    			existingFI.lastModifiedTimestamp = currentFI.lastModifiedTimestamp;
    			existingFI.fileSize = encryptResult.sourceFilesize;
    			existingFI.sourceHash = encryptResult.sourceSHA256;
    			existingFI.targetHash = encryptResult.targetSHA256;
    			syncedFiles.put(relSource, existingFI);
    			save(existingFI);
			}
			System.out.println("EncryptIt finished");
		} catch (IOException e) {
			throw new RuntimeException(e.toString(), e);
		} 
	}

	private void removeOutdatedTargetFile(Path oldTargetFile) throws IOException {
		if (Files.deleteIfExists(oldTargetFile)) {
			System.out.println("REMOVED "+oldTargetFile.toString());
		}
	}

	private void renameTargetFileHash(FileInfo currentFI, FileInfo existingFI, Path expectedTargetFile, EncryptResult encResult) throws IOException {
		String newShortHash = calcShortHash(encResult.sourceSHA256, encResult.sourceFilesize);
		String newTargetFilename = calcHashedFilename(currentFI.file.getFileName().toString(), newShortHash);
		Path newTargetFile = expectedTargetFile.resolveSibling(newTargetFilename);
		Files.move(expectedTargetFile, newTargetFile, StandardCopyOption.REPLACE_EXISTING);
		if ((existingFI != null) && existingFI.sourceHash.equals(encResult.sourceSHA256)) {
			// do not remove newly created file, because oldTargetFile matches newTargetFile
			existingFI.sourceHash = "";
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
