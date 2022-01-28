package de.hechler.pgpencrypter;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionResult;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.Passphrase;




/**
 * https://gh.pgpainless.org/
 * https://github.com/pgpainless/pgpainless/blob/master/README.md
 * 
 * @author feri
 *
 */
public class PGPEncrypterMain {

	private final static String DEFAULT_PRIVATE_KEY = "./testdata/keys/encryptittest.key";
	private final static String DEFAULT_PUBLIC_KEY = "./testdata/keys/encryptittest.pub";
	private final static String DEFAULT_INPUT_FILE_UNENCRYPTED = "./testdata/input/testdatei.txt";
	private final static String DEFAULT_INPUT_FILE_ENCRYPTED = "./testdata/input/testdatei.txt.pgp";
	private final static String DEFAULT_OUTPUT_FOLDER = "./testdata/output";
	
	
	
	public static void main(String[] args) {
		try {
			System.out.println("EncryptIt start");
			String privateKeyFile = DEFAULT_PRIVATE_KEY;
			String publicKeyFile = DEFAULT_PUBLIC_KEY;
			String inputFileUnencrypted = DEFAULT_INPUT_FILE_UNENCRYPTED;
			String inputFileEncrypted = DEFAULT_INPUT_FILE_ENCRYPTED;
			String outputFolder = DEFAULT_OUTPUT_FOLDER;
			Files.createDirectories(Paths.get(outputFolder));
			String privateAsciiKey;
			privateAsciiKey = new String(Files.readAllBytes(Paths.get(privateKeyFile)));
			PGPSecretKeyRing secretKey = PGPainless.readKeyRing().secretKeyRing(privateAsciiKey);
			// String armored = PGPainless.asciiArmor(secretKey);
			// System.out.println(armored);
			// PGPPublicKeyRing certificate = PGPainless.extractCertificate(secretKey);
			// String armored = PGPainless.asciiArmor(certificate);
			// System.out.println(armored);
			String publicAsciiKey = new String(Files.readAllBytes(Paths.get(publicKeyFile)));
			PGPPublicKeyRing publicKey = PGPainless.readKeyRing().publicKeyRing(publicAsciiKey);
			String outputFile = outputFolder+"/"+Paths.get(inputFileUnencrypted).getFileName().toString()+".pgp";
			encrypt(inputFileUnencrypted, publicKey, outputFile);
			
			outputFile = outputFolder+"/"+Paths.get(inputFileEncrypted).getFileName().toString().replace(".pgp", "");
			decrypt(inputFileEncrypted, secretKey, outputFile);
			System.out.println("EncryptIt finished");
		} catch (IOException e) {
			throw new RuntimeException(e.toString(), e);
		} 
			
	}

	public static void encrypt(String inputFilename, PGPPublicKeyRing publicKey, String outputFilename) {
		try {
	        FileInputStream plaintextInputStream = new FileInputStream(inputFilename);
			FileOutputStream outputStream = new FileOutputStream(outputFilename);
	        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
	                .onOutputStream(outputStream)
	                .withOptions(
	                        ProducerOptions.encrypt(
	                        		new EncryptionOptions()
	                                        .addRecipient(publicKey)
	                                        // optionally encrypt to a passphrase
	                                        .addPassphrase(Passphrase.fromPassword("EncryptItPassword"))
	                                        // optionally override symmetric encryption algorithm
	                                        .overrideEncryptionAlgorithm(SymmetricKeyAlgorithm.AES_256)
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
	
	public static void decrypt(String encryptedInputFilename, PGPSecretKeyRing secretKey, String outputFilename) {
		try {
			FileInputStream encryptedInputStream = new FileInputStream(encryptedInputFilename);
		FileOutputStream outputStream = new FileOutputStream(outputFilename);
		
//		SecretKeyRingProtector secretKeyProtector = PasswordBasedSecretKeyRingProtector.forKey(secretKey.getSecretKey(), Passphrase.fromPassword("EncryptItPassword"));
		SecretKeyRingProtector secretKeyProtector = SecretKeyRingProtector.unprotectedKeys();
		
		DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
	            .onInputStream(encryptedInputStream)
	            .withOptions(new ConsumerOptions()
	                    .addDecryptionKey(secretKey, secretKeyProtector)
	                    .addDecryptionPassphrase(Passphrase.fromPassword("EncryptItPassword"))
	            );
	
	    Streams.pipeAll(decryptionStream, outputStream);
	    decryptionStream.close();

	    // Result contains information like signature status etc.
	    OpenPgpMetadata metadata = decryptionStream.getResult();
	    System.out.println(metadata.getCompressionAlgorithm());
		} catch (IOException | PGPException e) {
			throw new RuntimeException(e.toString(), e);
		}
	}
	
}
