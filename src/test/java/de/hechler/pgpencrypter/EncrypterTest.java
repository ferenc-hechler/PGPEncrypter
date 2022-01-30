package de.hechler.pgpencrypter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.jupiter.api.Test;

import de.hechler.pgpencrypter.encrypt.Encrypter;

class EncrypterTest {

	private static final String TESTDATA_FOLDER = "./testdata"; 
	
	@Test
	void testEncryper() throws IOException {
		Path inputFile = Paths.get(TESTDATA_FOLDER).resolve("input/testdatei.txt");
		Path publicKeyFile = Paths.get(TESTDATA_FOLDER).resolve("keys/encryptittest.pub");
		Path outputFile = Paths.get(TESTDATA_FOLDER).resolve("output/testdatei.txt.pgp");
		Files.createDirectories(outputFile.getParent());
		Encrypter enc = new Encrypter(publicKeyFile);
		enc.encrypt(inputFile, outputFile);
	}

}
