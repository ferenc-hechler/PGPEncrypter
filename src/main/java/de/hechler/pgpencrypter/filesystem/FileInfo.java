package de.hechler.pgpencrypter.filesystem;

import java.io.BufferedReader;
import java.nio.file.Path;
import java.nio.file.Paths;

import de.hechler.pgpencrypter.persist.Deserializer;
import de.hechler.pgpencrypter.persist.Serializer;

public class FileInfo {

	public Path file;
	public long lastEventTimestamp;
	public long lastModifiedTimestamp;
	public long fileSize;
	public String sourceHash;
	public String targetHash;

	public FileInfo(Path file, long lastEventTimestamp, long lastModifiedTimestamp, long fileSize, String sourceHash,
			String targetHash) {
		this.file = file;
		this.lastEventTimestamp = lastEventTimestamp;
		this.lastModifiedTimestamp = lastModifiedTimestamp;
		this.fileSize = fileSize;
		this.sourceHash = sourceHash;
		this.targetHash = targetHash;
	}

	public static FileInfo createCopy(FileInfo other) {
		if (other == null) {
			return null;
		}
		return new FileInfo(other.file, other.lastEventTimestamp, other.lastModifiedTimestamp, other.fileSize, other.sourceHash, other.targetHash);
	}

	public static String headerCSV() {
		Serializer ser = new Serializer();
		headerCSV(ser);
		return ser.toString();
	}
	public static void headerCSV(Serializer serializer) {
		serializer.writeHeader("file");
		serializer.writeHeader("lastEventTimestamp");
		serializer.writeHeader("lastModifiedTimestamp");
		serializer.writeHeader("fileSize");
		serializer.writeHeader("sourceHash");
		serializer.writeHeader("targetHash");
	}
	public static void headerCSVRecord(Serializer ser) {
		headerCSV(ser);
		ser.writeRecordEnd();
	}
	

	public String toCSV() {
		Serializer ser = new Serializer();
		toCSV(ser);
		return ser.toString();
	}
	public void toCSV(Serializer serializer) {
		serializer.writeString(file.toString());
		serializer.writeLong(lastEventTimestamp);
		serializer.writeLong(lastModifiedTimestamp);
		serializer.writeLong(fileSize);
		serializer.writeString(sourceHash);
		serializer.writeString(targetHash);
	}
	public void toCSVRecord(Serializer ser) {
		toCSV(ser);
		ser.writeRecordEnd();
	}
	

	public static FileInfo fromCSV(String text) { return fromCSV(new Deserializer(text)); }
	public static FileInfo fromCSV(BufferedReader in) { return fromCSV(new Deserializer(in)); }
	public static FileInfo fromCSV(Deserializer deserializer) {
		if (deserializer.nextRecord() == Deserializer.NO_MORE_RECORDS) {
			return null;
		}
		Path file = Paths.get(deserializer.nextString());
		long lastEventTimestamp = deserializer.nextLong();
		long lastModifiedTimestamp = deserializer.nextLong();
		long fileSize = deserializer.nextLong();
		String sourceHash = deserializer.nextString();
		String targetHash = deserializer.nextString();
		FileInfo result = new FileInfo(file, lastEventTimestamp, lastModifiedTimestamp, fileSize, sourceHash, targetHash);
		return result;
	}
	
	
	
	@Override
	public String toString() {
		return "FileInfo [file=" + file + ", lastEventTimestamp=" + lastEventTimestamp + ", lastModifiedTimestamp="
				+ lastModifiedTimestamp + ", fileSize=" + fileSize + ", sourceHash=" + sourceHash + ", targetHash="
				+ targetHash + "]";
	}


}
