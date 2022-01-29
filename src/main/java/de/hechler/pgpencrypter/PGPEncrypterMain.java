package de.hechler.pgpencrypter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import de.hechler.pgpencrypter.Encrypter.EncryptResult;
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
		SyncEncrypted sync = new SyncEncrypted(publicKey, sourceFolder, targetFolder);
		sync.startSync();
		System.out.println("EncryptIt finished");
	}

	
}
