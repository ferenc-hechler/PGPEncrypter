package de.hechler.pgpencrypter;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Map;

import de.hechler.pgpencrypter.encrypt.Encrypter;
import de.hechler.pgpencrypter.encrypt.Encrypter.EncryptResult;
import de.hechler.pgpencrypter.filesystem.FileChangesCollector;
import de.hechler.pgpencrypter.filesystem.FileInfo;
import de.hechler.pgpencrypter.filesystem.FolderWatcher;




/**
 * https://gh.pgpainless.org/
 * https://github.com/pgpainless/pgpainless/blob/master/README.md
 * 
 * @author feri
 *
 */
public class SyncEncrypted {

	private static boolean TRUST_LAST_MODIFIED_TIMESTAMP = true;

	private Path publicKey;
	private Path inputFolder;
	private Path outputFolder;
	

	private Map<Path, FileInfo> syncedFiles;

	
	public SyncEncrypted(String publicKeyFilename, String inputFoldername, String outputfoldername) {
		this(Paths.get(publicKeyFilename), Paths.get(inputFoldername), Paths.get(outputfoldername));
	}

	public SyncEncrypted(Path publicKey, Path inputFolder, Path outputFolder) {
		this.publicKey = publicKey;
		this.inputFolder = inputFolder;
		this.outputFolder = outputFolder;
		this.syncedFiles = new LinkedHashMap<>();
	}
	
	public void startSync() {
		try {
			Files.createDirectories(inputFolder);
			Files.createDirectories(outputFolder);
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
				FileInfo existingFI = syncedFiles.get(relSource);
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
        			syncedFiles.put(relSource, existingFI);
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
			}
			System.out.println("EncryptIt finished");
		} catch (IOException e) {
			throw new RuntimeException(e.toString(), e);
		} 
	}

	private void removeOutdatedTargetFile(Path oldTargetFile) throws IOException {
		Files.deleteIfExists(oldTargetFile);
		System.out.println("REMOVED "+oldTargetFile.toString());
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
			FileInputStream in = new FileInputStream(file.toFile());
			while (true) {
				int cnt = in.read(buffer);
				if (cnt <= 0) {
					break;
				}
				md.update(buffer, 0, cnt);
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
