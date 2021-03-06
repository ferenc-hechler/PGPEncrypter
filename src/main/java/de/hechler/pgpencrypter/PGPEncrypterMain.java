package de.hechler.pgpencrypter;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

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
	private final static String DEFAULT_SYNC_CACHE_CSV_FILE = "./testdata/cache/sync-cache.csv";
	
	
	
	public static void main(String[] args) {
		System.out.println("EncryptIt start");
		String publicKeyFilename = DEFAULT_PUBLIC_KEY;
		String inputFolder = DEFAULT_INPUT_FOLDER;
		String outputFolder = DEFAULT_OUTPUT_FOLDER;
		String syncCacheCSVFilename = DEFAULT_SYNC_CACHE_CSV_FILE;
		
		if (args.length>=1) {
			publicKeyFilename = args[0];
		}
		if (args.length>=2) {
			inputFolder = args[1];
		}
		if (args.length>=3) {
			outputFolder = args[2];
		}
		if (args.length>=4) {
			syncCacheCSVFilename = args[3];
		}
		Path publicKey = Paths.get(publicKeyFilename);
		Path sourceFolder = Paths.get(inputFolder);
		Path targetFolder = Paths.get(outputFolder);
		Path syncCacheCSVFile = Paths.get(syncCacheCSVFilename);
		while (true) {
			SyncEncrypted sync = new SyncEncrypted(publicKey, sourceFolder, targetFolder, syncCacheCSVFile);
			sync.startSync();
			System.err.println("DISCONNECTED, waiting for folder "+sourceFolder);
			// MAYBE a good idea to have this outside of Java (restart java program)?
			while (true) {
				try {
					Thread.sleep(60000);
				} catch (InterruptedException e) {
					System.out.println("EncryptIt finished");
					return;
				}
				if (Files.isDirectory(sourceFolder)) {
					break;
				}
			}				
			System.out.println("RECONNECTING");
		}
	}

	
}
