package de.hechler.pgpencrypter;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ChecksumOutputStreamTest {

	@Test
	void testByteArr() throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ChecksumOutputStream cout = new ChecksumOutputStream("SHA-256", out);
		cout.write("TESTTEXT".getBytes());
		cout.close();
		assertEquals("46e33ffc6555cd559d7fc89e339ccd52d3bacb20153a3db7c650419d594f11e8", cout.getMD());
	}

	@Test
	void testByte() throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ChecksumOutputStream cout = new ChecksumOutputStream("SHA-256", out);
		for (byte b:"TESTTEXT".getBytes()) {
			cout.write(b);
		}
		cout.close();
		assertEquals("46e33ffc6555cd559d7fc89e339ccd52d3bacb20153a3db7c650419d594f11e8", cout.getMD());
	}

	@Test
	void testBytesOffset() throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ChecksumOutputStream cout = new ChecksumOutputStream("SHA-256", out);
		cout.write("PREFIX-TESTTEXT-SUFFIX".getBytes(), 7, 8);
		cout.close();
		assertEquals("46e33ffc6555cd559d7fc89e339ccd52d3bacb20153a3db7c650419d594f11e8", cout.getMD());
	}


	@Test
	void testMix() throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ChecksumOutputStream cout = new ChecksumOutputStream("SHA-256", out);
		cout.write("TESTTEXT".getBytes());
		for (byte b:"TESTTEXT".getBytes()) {
			cout.write(b);
		}
		cout.write("PREFIX-TESTTEXT-SUFFIX".getBytes(), 7, 8);
		cout.close();
		assertEquals("7921b521c7ead7519296d8d3c2a2df0bd34b659bd639dd79448d6b50e1e2102a", cout.getMD());
	}
	
	
}
