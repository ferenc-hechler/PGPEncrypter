package de.hechler.pgpencrypter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import de.hechler.pgpencrypter.FileChangesCollector.FileInfo;




/**
 * https://gh.pgpainless.org/
 * https://github.com/pgpainless/pgpainless/blob/master/README.md
 * 
 * @author feri
 *
 */
public class PGPEncrypterMain {

	private final static String DEFAULT_PUBLIC_KEY = "./testdata/keys/encryptittest.pub";
	private final static String DEFAULT_INPUT_FOLDER = "C:\\DEV\\NEXTCLOUD\\DATA";
	private final static String DEFAULT_OUTPUT_FOLDER = "C:\\DEV\\NEXTCLOUD\\ENCDATA";
	
	
	
	public static void main(String[] args) {
		try {
			System.out.println("EncryptIt start");
			String publicKeyFilename = DEFAULT_PUBLIC_KEY;
			String inputFolder = DEFAULT_INPUT_FOLDER;
			String outputFolder = DEFAULT_OUTPUT_FOLDER;
			
			if (args.length>=1) {
				publicKeyFilename = args[0];
			}
			if (args.length>=2) {
				inputFolder = args[1];
			}
			if (args.length>=3) {
				outputFolder = args[2];
			}
			Path publicKey = Paths.get(publicKeyFilename);
			Path sourceFolder = Paths.get(inputFolder);
			Path targetFolder = Paths.get(outputFolder);
			Files.createDirectories(sourceFolder);
			Files.createDirectories(targetFolder);
			Encrypter enc = new Encrypter(publicKey);
			FileChangesCollector collector = new FileChangesCollector();
			FolderWatcher fw = new FolderWatcher(Paths.get(inputFolder), collector);
			fw.startEventLoop();
			while (true) {
				FileInfo fi = collector.getNextChangedFile();
				if (fi == null) {
					break;
				}
				Path sourceFile = fi.file;
            	Path targetFile = targetFolder.resolve(sourceFolder.relativize(sourceFile.resolveSibling(fi.file.getFileName() + ".pgp")));
            	Files.createDirectories(targetFile.getParent());
        		enc.encrypt(sourceFile, targetFile);
        		System.out.println("ENCRYPTED: "+targetFile);
			}
			System.out.println("EncryptIt finished");
		} catch (IOException e) {
			throw new RuntimeException(e.toString(), e);
		} 
			
	}

	
}
