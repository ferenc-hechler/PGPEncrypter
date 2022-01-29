package de.hechler.pgpencrypter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ChecksumOutputStream extends OutputStream {
	
	private OutputStream delegte;

	private MessageDigest md;

	public ChecksumOutputStream(String algorithm, OutputStream delegte) {
		this.delegte = delegte;
		try {
			this.md = MessageDigest.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e.toString());
		}
	}

	public String getMD() {
		byte[] bytes = md.digest();
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
	}
	
	public void write(int b) throws IOException {
		delegte.write(b);
		md.update((byte)b);
	}

	public void write(byte[] b) throws IOException {
		delegte.write(b);
		md.update(b);
	}

	public void write(byte[] b, int off, int len) throws IOException {
		delegte.write(b, off, len);
		md.update(b, off, len);
	}

	public void flush() throws IOException {
		delegte.flush();
	}

	public void close() throws IOException {
		delegte.close();
	}

	public static void main(String[] args) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ChecksumOutputStream cout = new ChecksumOutputStream("SHA-256", out);
		cout.write("TESTTEXT".getBytes());
		cout.close();
		System.out.println(cout.getMD());
	}

}
