package de.hechler.pgpencrypter.pcloud;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import com.pcloud.sdk.ApiClient;
import com.pcloud.sdk.ApiError;
import com.pcloud.sdk.Authenticators;
import com.pcloud.sdk.DataSource;
import com.pcloud.sdk.PCloudSdk;
import com.pcloud.sdk.RemoteFile;
import com.pcloud.sdk.RemoteFolder;
import com.pcloud.sdk.UploadOptions;

import okio.BufferedSink;

/**
 * Test using pCloud API - Java SDK https://github.com/pCloud/pcloud-sdk-java
 * 
 * SDK docu: https://pcloud.github.io/pcloud-sdk-java/
 * 
 * API docu: https://docs.pcloud.com/
 * 
 * @author feri
 */

public class PCloudUploader {

	private final static String CONFIG_FILENAME = ".env";
	private final static String TEMP_UPLOAD_FILENAME = "pclouduploader_file.tmp";


	private static PCloudConfig config;
	public static PCloudConfig getConfig() {
		if (config == null) {
			config = new PCloudConfig(CONFIG_FILENAME);
		}
		return config;
	}


	private static ApiClient internApiClient;
	public static ApiClient getApiClient() {
		if (internApiClient == null) {
			internApiClient = PCloudSdk.newClientBuilder()
					.authenticator(Authenticators.newOAuthAuthenticator(getConfig().getAccessToken()))
					.apiHost(getConfig().getApiHost())
					// Other configuration...
					.create();
		}
		return internApiClient;
	}
	public static void shutdownApiClient() {
		if (internApiClient == null) {
			return;
		}
		internApiClient.shutdown();
		internApiClient = null;
	}
	
	
	/**
	 * 
	 * @param relPath
	 * @param in
	 * @return file id or -1 on error
	 */
	public long uploadFile(Path relPath, InputStream in)  {
		ApiClient apiClient = getApiClient();
		String filename = relPath.getFileName().toString();
		long result = -1;
		try {
			File tempFile = in2tempFile(in);
			long folderId = recursiveCreateFolder(apiClient, relPath.getParent());
			RemoteFile rFile = apiClient.createFile(rPath(relPath.getParent()), filename, DataSource.create(tempFile), UploadOptions.OVERRIDE_FILE).execute();
//			RemoteFile rFile = apiClient.createFile(folderId, filename, DataSource.create(tempFile), UploadOptions.OVERRIDE_FILE).execute();
			result = rFile.fileId();
        } catch (IOException | ApiError e) {
        	e.printStackTrace();
            System.err.println("Error upload file '"+relPath+"': "+e.toString());
        }
		removeTempFile();
        shutdownApiClient();
        return result;
	}

	private static File in2tempFile(InputStream in) {
		try {
			File tempFile = new File(TEMP_UPLOAD_FILENAME); 
			try (OutputStream out = new FileOutputStream(tempFile)) {
				byte[] buf = new byte[4096];
				while (true) {
					int cnt = in.read(buf);
					if (cnt <= 0) {
						break;
					}
					out.write(buf, 0, cnt);
				}
			}
			tempFile.deleteOnExit();
			return tempFile; 
		}
		catch (IOException e) {
			throw new RuntimeException(e.toString(), e);
		}
	}
	private static void removeTempFile() {
		try {
			Files.deleteIfExists(Paths.get(TEMP_UPLOAD_FILENAME));
		} catch (IOException e) { }
	}
	
	public long recursiveCreateFolder(ApiClient apiClient, Path folder) {
		try {
			if (folder == null) {
				return RemoteFolder.ROOT_FOLDER_ID;
			}
			try {
				RemoteFolder fetchedFolder = apiClient.loadFolder(rPath(folder)).execute();
				return fetchedFolder.folderId();
			}
			catch (ApiError e) {
				if (e.errorCode() != 2005) { // Directory does not exist.
					throw e;
				}
			}
			long parentID = recursiveCreateFolder(apiClient, folder.getParent());
			// https://github.com/pCloud/pcloud-sdk-java/issues/29
			RemoteFolder newFolder = apiClient.createFolder(rPath(folder)).execute();
			return newFolder.folderId();
		} catch (IOException | ApiError e) {
			throw new RuntimeException("Error creating folder '"+folder+"': "+e.toString(), e);
		}
	}

	
	private String rPath(Path folder) {
		String result = folder.toString().replace('\\', '/');
		if (!result.startsWith("/")) {
			result = "/"+result;
		}
		return result;
	}

}
