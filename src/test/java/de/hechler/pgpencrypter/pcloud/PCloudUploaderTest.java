package de.hechler.pgpencrypter.pcloud;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.jupiter.api.Test;

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

}
