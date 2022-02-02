package de.hechler.pgpencrypter.pcloud;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.jupiter.api.Test;

import com.pcloud.sdk.ApiClient;
import com.pcloud.sdk.RemoteFolder;

class PCloudUploaderTest {


	@Test
	void testUploadFile() throws Exception {
		try {
			PCloudUploader uploader = new PCloudUploader();
			Path path = Paths.get("src/test/java/de/hechler/pgpencrypter/pcloud/PCloudUploaderTest.java");
			try (InputStream in = new FileInputStream(path.toFile())) {
				uploader.uploadFile(path, in);
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	//@Test
	void testRecursiveCreateFolder() throws Exception {
		try {
			ApiClient apiClient = PCloudUploader.getApiClient();
			
			RemoteFolder remFolderTEST = apiClient.createFolder("/test").execute();
			RemoteFolder remFolderFOLDER1 = apiClient.createFolder("/test/folder3").execute();
			long folder1ID = remFolderFOLDER1.folderId();
			System.out.println("folder1-ID: "+folder1ID);
			RemoteFolder remFolderFOLDER1a = apiClient.createFolder("/test/folder3/folder3a").execute();
			RemoteFolder remFolderFOLDER1b = apiClient.createFolder(folder1ID, "folder3b").execute();
			
			PCloudUploader.shutdownApiClient();
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

}
