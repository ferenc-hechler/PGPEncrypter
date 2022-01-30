package de.hechler.pgpencrypter.encrypt;

import java.io.FileInputStream;
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
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;

import de.hechler.pgpencrypter.utils.ChecksumInputStream;
import de.hechler.pgpencrypter.utils.ChecksumOutputStream;

public class Encrypter {

	private PGPPublicKeyRing publicKey;
	
	public static class EncryptResult {
		public long sourceFilesize;
		public String sourceSHA256;
		public long targetFilesize;
		public String targetSHA256;
		public EncryptResult(long sourceFilesize, String sourceSHA256, long targetFilesize, String targetSHA256) {
			this.sourceFilesize = sourceFilesize;
			this.sourceSHA256 = sourceSHA256;
			this.targetFilesize = targetFilesize;
			this.targetSHA256 = targetSHA256;
		}
		@Override
		public String toString() {
			return "EncryptResult [sourceFilesize=" + sourceFilesize + ", sourceSHA256=" + sourceSHA256
					+ ", targetFilesize=" + targetFilesize + ", targetSHA256=" + targetSHA256 + "]";
		}
		
	}
	
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

	public EncryptResult encrypt(Path inputFilename, Path outputFilename) {
		try {
			try (InputStream in = new FileInputStream(inputFilename.toFile())) {
				try (OutputStream out = new FileOutputStream(outputFilename.toFile())) {
					return encrypt(in, out);
				}
			}
		} catch (Exception e) {
			throw new RuntimeException(e.toString(), e);
		}
		
	}

	
	public EncryptResult encrypt(InputStream plaintextInputStream, OutputStream outputStream) {
		try {
			ChecksumInputStream cin = new ChecksumInputStream("SHA-256", plaintextInputStream);
			ChecksumOutputStream cout = new ChecksumOutputStream("SHA-256", outputStream);
			
	        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
	                .onOutputStream(cout)
	                .withOptions(
	                        ProducerOptions.encrypt(
	                        		new EncryptionOptions()
	                                        .addRecipient(publicKey)
	                                        // optionally override symmetric encryption algorithm
	                                        .overrideEncryptionAlgorithm(SymmetricKeyAlgorithm.AES_256)
	                        ).setAsciiArmor(true) // Ascii armor or not
	                );
	
	        Streams.pipeAll(cin, encryptionStream);
	        encryptionStream.close();
	        long sourceFilesize = cin.getSize();
	        String sourceSHA256 = cin.getMD();
	        long targetFilesize = cout.getSize();
	        String targetSHA256 = cout.getMD();
	        return new EncryptResult(sourceFilesize, sourceSHA256, targetFilesize, targetSHA256);
	        // Information about the encryption (algorithms, detached signatures etc.)
//	        EncryptionResult result = encryptionStream.getResult();
//	        System.out.println(result.getEncryptionAlgorithm());
		} catch (IOException | PGPException e) {
			throw new RuntimeException(e.toString(), e);
		}

	}
	
}
