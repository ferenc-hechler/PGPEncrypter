package de.hechler.pgpencrypter;

import static java.nio.file.StandardWatchEventKinds.ENTRY_CREATE;
import static java.nio.file.StandardWatchEventKinds.ENTRY_DELETE;
import static java.nio.file.StandardWatchEventKinds.ENTRY_MODIFY;
import static java.nio.file.StandardWatchEventKinds.OVERFLOW;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.HashMap;
import java.util.Map;

/**
 * https://docs.oracle.com/javase/tutorial/essential/io/notification.html
 * 
 * @author feri
 */
public class FolderEncrypter {

	private Path sourceFolder;
	private Path targetFolder;
	private WatchService watcher;
	private Map<WatchKey, Path> wk2folder;
	private Encrypter enc;
	
	public FolderEncrypter(Path sourceFolder, Path targetFolder, Encrypter enc) {
		try {
			System.out.println("preparing encrypting files from '"+sourceFolder+"' to '"+targetFolder+"'");
			this.sourceFolder = sourceFolder;
			this.targetFolder = targetFolder;
			this.enc = enc;
			this.wk2folder = new HashMap<>();
			this.watcher = FileSystems.getDefault().newWatchService();
			registerAll(sourceFolder);
		} catch (IOException e) {
			throw new RuntimeException(e.toString(), e);
		}
	}

	private void registerAll(Path folder) throws IOException {
		register(folder);
		Files.walkFileTree(folder, new SimpleFileVisitor<Path>() {
			@Override
	        public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
				register(dir);
				return FileVisitResult.CONTINUE;
			}
		});
	}
	
	/**
     * Process all events for keys queued to the watcher
     */
    void processEvents() {
		System.out.println("ready");
        WatchKey key;
        while (true) {
            // wait for key to be signalled
            try {
                key = watcher.take();
            } catch (InterruptedException x) {
                return;
            }
            Path dir = wk2folder.get(key);
            if (dir == null) {
                // System.err.println("WatchKey not recognized!!");
                continue;
            }
            for (WatchEvent<?> event: key.pollEvents()) {
                WatchEvent.Kind<?> kind = event.kind();
                if (kind == OVERFLOW) {
                    rescanAllFiles();
                    break;
                }
                // Context for directory entry event is the file name of entry
                @SuppressWarnings("unchecked")
				WatchEvent<Path> ev = (WatchEvent<Path>)event;
                Path name = ev.context();
                Path child = dir.resolve(name);
                System.out.format("%s: %s\n", event.kind().name(), child);
                if ((kind == ENTRY_MODIFY) || (kind == ENTRY_CREATE)) {
                	if (Files.isRegularFile(child)) {
	                	Path target = targetFolder.resolve(sourceFolder.relativize(child.resolveSibling(child.getFileName() + ".pgp")));
                		processFile(child, target);
                	}
                }
                // if directory is created, and watching recursively, then
                // register it and its sub-directories
                if (kind == ENTRY_CREATE) {
                    try {
                        if (Files.isDirectory(child, LinkOption.NOFOLLOW_LINKS)) {
                            registerAll(child);
                        }
                    } catch (IOException ignore) {}
                }
            }
            // reset key and remove from set if directory no longer accessible
            boolean valid = key.reset();
            if (!valid) {
                wk2folder.remove(key);
                if (wk2folder.isEmpty()) {
                    // all directories are inaccessible
                    break;
                }
            }
        }
    }
    
	private boolean checkModified(Path source) {
		return true;
	}

	private void register(Path folder) throws IOException {
		WatchKey key = folder.register(watcher,
				 ENTRY_CREATE,
				 ENTRY_DELETE,
				 ENTRY_MODIFY);
		wk2folder.put(key, folder);
	}

	
	private void rescanAllFiles() {
		try {
			System.out.println("RESCANALLFILES");
    	}
    	catch (Exception e) {
    		System.err.println("ERROR rescanning all files: "+e.toString());
		}
	}

	private void processFile(Path source, Path target) {
    	try {
			System.out.println("checking for changes '"+source+"' and '"+target+"'");
			if (!Files.isRegularFile(source)) {
				return;
			}
			if (!checkModified(source)) {
				return;
			}
			// asynchronous check size after delay
			Files.createDirectories(target.getParent());
			enc.encrypt(source, target);
    	}
    	catch (Exception e) {
    		System.err.println("ERROR processing '"+source+"': "+e.toString());
		}
	}

	public static void main(String[] args) {
		Encrypter enc = new Encrypter(Paths.get("C:\\DEV\\NEXTCLOUD\\KEYS\\encryptittest.pub"));
		FolderEncrypter fe = new FolderEncrypter(Paths.get("C:\\DEV\\NEXTCLOUD\\DATA"), Paths.get("C:\\DEV\\NEXTCLOUD\\ENCDATA"), enc);
		fe.processEvents();
	}
	
}
