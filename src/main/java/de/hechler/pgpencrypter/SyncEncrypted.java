package de.hechler.pgpencrypter;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Map;

import de.hechler.pgpencrypter.Encrypter.EncryptResult;




/**
 * https://gh.pgpainless.org/
 * https://github.com/pgpainless/pgpainless/blob/master/README.md
 * 
 * @author feri
 *
 */
public class SyncEncrypted {

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
				FileInfo fi = collector.getNextChangedFile();
				if (fi == null) {
					break;
				}
				long now = System.currentTimeMillis();
				Path sourceFile = fi.file;
            	Path relSource = inputFolder.relativize(sourceFile);
				FileInfo existingFI = syncedFiles.get(relSource);
				String sourceSHA256 = calcSHA256(sourceFile);
				String shortHash = calcShortHash(sourceSHA256);
				String targetFilename = sourceFile.getFileName().toString();
				int dotPos = targetFilename.lastIndexOf('.');
				if (dotPos == -1) {
					targetFilename = targetFilename+"-"+shortHash+".pgp";
				}
				else {
					targetFilename = targetFilename.substring(0, dotPos)+"-"+shortHash+targetFilename.substring(dotPos)+".pgp";
				}
            	Path targetFile = outputFolder.resolve(inputFolder.relativize(sourceFile.resolveSibling(targetFilename)));
            	if (existingFI != null) {
            		if (existingFI.sourceHash.equalsIgnoreCase(sourceSHA256)) {
            			// TODO: verify in filesystem / remote
            			System.out.println("NO CHANGES IN "+relSource);
            			continue;
            		}
            	}
            	
            	Files.createDirectories(targetFile.getParent());
        		EncryptResult encryptResult = enc.encrypt(sourceFile, targetFile);
        		System.out.println("ENCRYPTED: "+targetFile+"  SHA-256(source):"+encryptResult.sourceSHA256+"  SHA-256(target):"+encryptResult.targetSHA256);
        		if (existingFI == null) {
        			existingFI = new FileInfo(relSource, now, -1, -1, null, null);
        			syncedFiles.put(relSource, existingFI);
        		}
        		else {
        			String oldSourceHash = existingFI.sourceHash;
    				String oldShortHash = calcShortHash(oldSourceHash);
    				String oldTargetFilename = calcHashedFilename(relSource.getFileName().toString(), oldShortHash); 
                	Path oldTargetFile = outputFolder.resolve(inputFolder.relativize(sourceFile.resolveSibling(oldTargetFilename)));
                	Files.deleteIfExists(oldTargetFile);
                	System.out.println("REMOVED "+oldTargetFile.toString());
        		}
    			long lastModified = Files.getLastModifiedTime(sourceFile).toMillis();
    			long fileSize = Files.size(sourceFile);
    			existingFI.lastEventTimestamp = now;
    			existingFI.lastModifiedTimestamp = lastModified;
    			existingFI.fileSize = fileSize;
    			existingFI.sourceHash = encryptResult.sourceSHA256;
    			existingFI.targetHash = encryptResult.targetSHA256;
			}
			System.out.println("EncryptIt finished");
		} catch (IOException e) {
			throw new RuntimeException(e.toString(), e);
		} 
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

	private String calcShortHash(String text) {
		String result = calcSHA256("SHORT-"+text);
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
