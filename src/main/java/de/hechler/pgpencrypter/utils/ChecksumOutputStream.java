package de.hechler.pgpencrypter.utils;

import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ChecksumOutputStream extends OutputStream {
	
	private OutputStream delegte;

	private MessageDigest md;
	private long size;

	public ChecksumOutputStream(String algorithm, OutputStream delegte) {
		this.delegte = delegte;
		try {
			this.md = MessageDigest.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e.toString());
		}
		this.size = 0;
	}

	public String getMD() {
		byte[] bytes = md.digest();
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
	}
	
	public long getSize() {
		return size;
	}

	public void write(int b) throws IOException {
		delegte.write(b);
		md.update((byte)b);
		size += 1;
	}

	public void write(byte[] b) throws IOException {
		delegte.write(b);
		md.update(b);
		size += b.length;
	}

	public void write(byte[] b, int off, int len) throws IOException {
		delegte.write(b, off, len);
		md.update(b, off, len);
		size += len;
	}

	public void flush() throws IOException {
		delegte.flush();
	}

	public void close() throws IOException {
		delegte.close();
	}

}
