package de.hechler.pgpencrypter;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * https://docs.oracle.com/javase/tutorial/essential/io/notification.html
 * 
 * @author feri
 */
public class FileChangesCollector {

	public static class FileInfo {
		public Path file;
		public long lastEventTimestamp;
		public long lastModifiedTimestamp;
		public long fileSize;
		public String sourceHash;
		public String targetHash;
		public FileInfo(Path file, long lastEventTimestamp, long lastModifiedTimestamp, long fileSize, String sourceHash, String targetHash) {
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
	
	private ConcurrentMap<Path, FileInfo> updatedFiles;
	private boolean shutdown;
	
	public FileChangesCollector() {
		this.updatedFiles = new ConcurrentHashMap<>();
		this.shutdown = false;
	}

	public void fileChanged(Path file) {
		try {
			long now = System.currentTimeMillis();
//			 System.out.println("FILECHANGED: "+file + " at "+now);
			FileInfo fileInfo = updatedFiles.get(file);
			if (fileInfo == null) {
				fileInfo = new FileInfo(file, now, 0, 0, null, null);
				updatedFiles.put(file, fileInfo);
			}
			fileInfo.lastEventTimestamp = now;
			fileInfo.lastModifiedTimestamp = Files.getLastModifiedTime(file).toMillis();
			fileInfo.fileSize = Files.size(file);
		}
		catch (Exception e) {
			System.err.println(e.toString());
			return;
		}
	}
	
	public void rescanAll() {
		System.err.println("TODO: rescanAll() - check all files for changes");
	}

	public FileInfo getNextChangedFile() {
		return getNextChangedFile(5000);
	}

	
	public FileInfo getNextChangedFile(long fileUnchangedMS) {
		FileInfo result = null;
		while (result == null) {
			while (updatedFiles.isEmpty()) {
				try {
					Thread.sleep(fileUnchangedMS);
				} catch (InterruptedException e) {
					return null;
				}
				if (shutdown) {
					return null;
				}
			}
			long now = System.currentTimeMillis();
			long maxTime = now-fileUnchangedMS;
			Iterator<Entry<Path, FileInfo>> iterator = updatedFiles.entrySet().iterator();
			while (iterator.hasNext()) {
				Entry<Path, FileInfo> entry = iterator.next();
				try {
					FileInfo fi = entry.getValue();
					if (fi.lastEventTimestamp>maxTime) {
						continue;
					}
					long lastModifiedTime = Files.getLastModifiedTime(fi.file).toMillis();
					long fileSize = Files.size(fi.file);
					if ((lastModifiedTime != fi.lastModifiedTimestamp) || (fileSize != fi.fileSize)) {
						fi.lastEventTimestamp = now;
						continue;
					}
					iterator.remove();
					result = fi;
					break;
				}
				catch (Exception e) {
					iterator.remove();
				}
			}
			if (result == null) {
				try {
					Thread.sleep(fileUnchangedMS);
				} catch (InterruptedException e) {
					return null;
				}
			}
		}
		return result;
	}


	public FileInfo getUpdatedFileInfo(long waitTime) {
		long now = System.currentTimeMillis();
		long maxTime = now-waitTime;
		FileInfo result = null;
		Iterator<Entry<Path, FileInfo>> iterator = updatedFiles.entrySet().iterator();
		while (iterator.hasNext()) {
			Entry<Path, FileInfo> entry = iterator.next();
			FileInfo fi = entry.getValue();
			if (fi.lastEventTimestamp>maxTime) {
				continue;
			}
			try {
				long lastModifiedTime = Files.getLastModifiedTime(fi.file).toMillis();
				long fileSize = Files.size(fi.file);
				if ((lastModifiedTime != fi.lastModifiedTimestamp) || (fileSize != fi.fileSize)) {
					fi.lastEventTimestamp = now;
				}
				result = fi;
				break;
			}
			catch (Exception e) {
				iterator.remove();
			}
		}
		return result;
	}

	public void shutdown() {
		System.err.println("SHUTDOWN");
		shutdown = true;
	}

}
