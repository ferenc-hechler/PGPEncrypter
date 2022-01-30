package de.hechler.pgpencrypter.persist;

import java.text.SimpleDateFormat;
import java.util.Date;

public class Serializer {

	private final static String DELIMITER = "\"";
	private final static char   DELIMITER_CHAR = DELIMITER.charAt(0);
	private final static String ESCAPED_DELIMITER = "\"";
	private final static String RECORDEND = "\r\n";
	private final static String SEPERATOR = ";";
	private final static char   SEPERATOR_CHAR = SEPERATOR.charAt(0);
//	private final static SimpleDateFormat ISO8601 =  new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
	/** not threadsafe */	
	private final static SimpleDateFormat EXCELDATE =  new SimpleDateFormat("dd.MM.yyyy HH:mm:ss");
	
	private StringBuilder sb;
	private boolean recordStarted;
	
	public Serializer() { this(new StringBuilder()); }
	public Serializer(StringBuilder sb) { this.sb = sb; recordStarted = true; }

	public void writeHeader(String txt) {
		writeSeperator();
		directWrite(txt.replace(DELIMITER, ESCAPED_DELIMITER));
	}
	public void writeString(String txt) {
		writeSeperator();
		if (txt != null) {
			boolean doQuote = (txt.indexOf(DELIMITER_CHAR) != -1) || (txt.indexOf(SEPERATOR_CHAR) != -1) || txt.isEmpty();
			if (doQuote) {
				directWrite(DELIMITER);
				directWrite(txt.replace(DELIMITER, ESCAPED_DELIMITER));
				directWrite(DELIMITER);
			}
			else {
				directWrite(txt);
			}
		}
	}
	public void writeLong(Long n) {
		writeSeperator();
		if (n != null) {
			directWrite(Long.toString(n));
		}
	}
	public void writeDate(Date date) {
		writeSeperator();
		if (date != null) {
			directWrite(EXCELDATE.format(date));
		}
	}
	public void writeBoolean(Boolean b) {
		writeSeperator();
		if (b != null) {
			directWrite(b ? "1" : "0");
		}
	}
	public void writeCharacter(Character c) {
		writeSeperator();
		if (c != null) {
			directWrite(c.toString());
		}
	}
	
	public void writeRecordEnd() {
		directWrite(RECORDEND);
		recordStarted = true;
	}
	
	private void writeSeperator() {
		if (recordStarted) {
			recordStarted=false;
		}
		else {
			directWrite(SEPERATOR);
		}
	}
	private void directWrite(String txt) {
		sb.append(txt);
	}

	@Override
	public String toString() {
		return sb.toString();
	}
}
