package de.hechler.pgpencrypter;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionResult;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;

public class Encrypter {

	private PGPPublicKeyRing publicKey;
	
	public Encrypter(Path publicKeyFilename) { 
		try {
			String publicKeyText = new String(Files.readAllBytes(publicKeyFilename));
			this.publicKey = PGPainless.readKeyRing().publicKeyRing(publicKeyText);
		} catch (IOException e) {
			throw new RuntimeException(e.toString(), e);
		}
	}

	public Encrypter(String publicKeyText) {
		try {
			this.publicKey = PGPainless.readKeyRing().publicKeyRing(publicKeyText);
		} catch (IOException e) {
			throw new RuntimeException(e.toString(), e);
		}
	}

	public void encrypt(Path inputFilename, Path outputFilename) {
		try {
			try (InputStream in = new FileInputStream(inputFilename.toFile())) {
				try (OutputStream out = new FileOutputStream(outputFilename.toFile())) {
					encrypt(in, out);
				}
			}
		} catch (Exception e) {
			throw new RuntimeException(e.toString(), e);
		}
		
	}

	
	public void encrypt(InputStream plaintextInputStream, OutputStream outputStream) {
		try {
	        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
	                .onOutputStream(outputStream)
	                .withOptions(
	                        ProducerOptions.encrypt(
	                        		new EncryptionOptions()
	                                        .addRecipient(publicKey)
	                                        //// optionally override symmetric encryption algorithm
	                                        //.overrideEncryptionAlgorithm(SymmetricKeyAlgorithm.AES_256)
	                        ).setAsciiArmor(true) // Ascii armor or not
	                );
	
	        Streams.pipeAll(plaintextInputStream, encryptionStream);
	        encryptionStream.close();
	
	        // Information about the encryption (algorithms, detached signatures etc.)
	        EncryptionResult result = encryptionStream.getResult();
	        System.out.println(result.getEncryptionAlgorithm());
		} catch (IOException | PGPException e) {
			throw new RuntimeException(e.toString(), e);
		}

	}
	
}
