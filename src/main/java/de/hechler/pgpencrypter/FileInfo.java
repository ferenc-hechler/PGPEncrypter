package de.hechler.pgpencrypter;

import java.nio.file.Path;

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

	@Override
	public String toString() {
		return "FileInfo [file=" + file + ", lastEventTimestamp=" + lastEventTimestamp + ", lastModifiedTimestamp="
				+ lastModifiedTimestamp + ", fileSize=" + fileSize + ", sourceHash=" + sourceHash + ", targetHash="
				+ targetHash + "]";
	}

}
