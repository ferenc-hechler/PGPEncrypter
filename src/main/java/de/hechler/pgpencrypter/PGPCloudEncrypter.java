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
public class PGPCloudEncrypter {

	private final static String DEFAULT_PUBLIC_KEY = "./local/appdata/encrypt-key.pub";
	private final static String DEFAULT_INPUT_FOLDER = "./local/input";
	private final static String DEFAULT_CLOUD_FOLDERNAME = "/crypt";
	private final static String DEFAULT_SYNC_CACHE_CSV_FILE = "./local/appdata/synced-files.csv";
	private final static String DEFAULT_TEMP_UPLOAD_FILE = "./local/appdata/upload-file.tmp";
	
	
	public static void main(String[] args) {
		System.out.println("EncryptIt start");
		String publicKeyFilename = DEFAULT_PUBLIC_KEY;
		String inputFolder = DEFAULT_INPUT_FOLDER;
		String cloudFoldername = DEFAULT_CLOUD_FOLDERNAME;
		String syncCacheCSVFilename = DEFAULT_SYNC_CACHE_CSV_FILE;
		String tempUploadFilename = DEFAULT_TEMP_UPLOAD_FILE;
		
		if (args.length>=1) {
			publicKeyFilename = args[0];
		}
		if (args.length>=2) {
			inputFolder = args[1];
		}
		if (args.length>=3) {
			cloudFoldername = args[2];
		}
		if (args.length>=4) {
			syncCacheCSVFilename = args[3];
		}
		if (args.length>=5) {
			tempUploadFilename = args[4];
		}
		Path publicKey = Paths.get(publicKeyFilename);
		Path sourceFolder = Paths.get(inputFolder);
		Path cloudFolder = Paths.get(cloudFoldername);
		Path syncCacheCSVFile = Paths.get(syncCacheCSVFilename);
		Path tempUploadFile = Paths.get(tempUploadFilename);
		while (true) {
			SyncCloudEncrypted sync = new SyncCloudEncrypted(publicKey, sourceFolder, cloudFolder, syncCacheCSVFile, tempUploadFile);
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
