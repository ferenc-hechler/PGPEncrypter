package de.hechler.pgpencrypter.persist;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class Deserializer implements AutoCloseable {

	private final static String DELIMITER = "\"";
	private final static char DELIMITER_CHAR = DELIMITER.charAt(0);
	private final static String ESCAPED_DELIMITER = "\"";
	private final static String SEPERATOR = ";";
	private final static char SEPERATOR_CHAR = SEPERATOR.charAt(0);
	/** not threadsafe */	
	private final static SimpleDateFormat EXCELDATE =  new SimpleDateFormat("dd.MM.yyyy HH:mm:ss");
	
	public final static int NO_MORE_RECORDS = -1;
	
	private BufferedReader in;
	private List<String> fields;
	private int nextField;
	
	public Deserializer(String inputText) {
		this(new BufferedReader(new StringReader(inputText)));
	}
	public Deserializer(BufferedReader in) { 
		this.in = in; 
		this.fields=null;
		this.nextField = 0;
	}
	
	public int nextRecord() {
		String record = readLine();
		if (record == null) {
			return NO_MORE_RECORDS;
		}
		fields = new ArrayList<>();
		int startPos = 0;
		int endPos = 0;
		boolean startsWithQuote = false;
		int cntQuote = 0;
		while (endPos < record.length()) {
			char c = record.charAt(endPos); 
			if ((startPos==endPos) && (c==DELIMITER_CHAR)) {
				startsWithQuote = true;
			}
			if (c == DELIMITER_CHAR) {
				cntQuote++;
			}
			if (c == SEPERATOR_CHAR) {
				if ((!startsWithQuote) || ((cntQuote & 0x01) == 0)) {
					fields.add(record.substring(startPos, endPos));
					startPos = endPos+1;
				}
			}
			endPos++;
		}
		fields.add(record.substring(startPos, endPos));
		nextField = 0;
		return fields.size();
	}
	
	public String nextString() {
		String result = nextRawString();
		if (result.isEmpty()) {
			return null;
		}
		if (result.startsWith("\"")) {
			if (!result.endsWith("\"")) {
				throw new RuntimeException("invalid string format '"+result+"'");
			}
			result = result.substring(1, result.length()-1).replace(ESCAPED_DELIMITER, DELIMITER); 
		}
		return result;
	}
	public Long nextLong() {
		String raw = nextRawString();
		if (raw.isEmpty()) {
			return null;
		}
		return Long.parseLong(raw);
	}
	public Date nextDate() {
		try {
			String raw = nextRawString();
			if (raw.isEmpty()) {
				return null;
			}
			return EXCELDATE.parse(raw);
		} catch (ParseException e) {
			throw new RuntimeException(e.toString(),e);
		}
	}
	public Boolean nextBoolean() {
		String raw = nextRawString();
		if (raw.isEmpty()) {
			return null;
		}
		return raw.equals("1");
	}
	public Character nextCharacter() {
		String raw = nextRawString();
		if (raw.isEmpty()) {
			return null;
		}
		return raw.charAt(0);
	}
	
	private String nextRawString() {
		if (nextField>=fields.size()) {
			return null;
		}
		String result = fields.get(nextField);
		nextField++;
		return result;
	}

	private String readLine() {
		String result = null;
		try {
			while (true) {
				result = in.readLine();
				if (result == null) {
					return null;
				}
				if (!result.trim().isEmpty()) {
					return result;
				}
			}
		} catch (IOException e) {
			throw new RuntimeException(e.toString(), e);
		}
	}
	@Override
	public void close() {
		try {
			in.close();
		}
		catch (Exception e) {
			throw new RuntimeException(e.toString(), e);
		}
	}
}
