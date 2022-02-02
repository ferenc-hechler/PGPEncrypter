package de.hechler.pgpencrypter.filesystem;

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
		return getNextChangedFile(-1);
	}

	
	public static final FileInfo TIMEOUT_FILEINFO = new FileInfo(null, 0, 0, 0, null, null);
	
	private final static long FILE_UNCHANGED_MILLIS = 5000;
	
	public FileInfo getNextChangedFile(long timeout) {
		long timeoutTimeMillis = (timeout == -1) ? Long.MAX_VALUE : System.currentTimeMillis() + timeout;
		FileInfo result = null;
		while (result == null) {
			while (updatedFiles.isEmpty()) {
				if (timeoutTimeMillis <= System.currentTimeMillis()) {
					return TIMEOUT_FILEINFO;
				}
				try {
					Thread.sleep(FILE_UNCHANGED_MILLIS);
				} catch (InterruptedException e) {
					return null;
				}
				if (shutdown) {
					return null;
				}
			}
			long now = System.currentTimeMillis();
			long maxTime = now-FILE_UNCHANGED_MILLIS;
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
					Thread.sleep(FILE_UNCHANGED_MILLIS);
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
