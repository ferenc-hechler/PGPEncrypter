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
import java.nio.file.SimpleFileVisitor;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;

/**
 * https://docs.oracle.com/javase/tutorial/essential/io/notification.html
 * 
 * @author feri
 */
public class FolderWatcher {

	private Path sourceFolder;
	private FileChangesCollector collector;
	private WatchService watcher;
	private Map<WatchKey, Path> wk2folder;
	
	public FolderWatcher(Path sourceFolder, FileChangesCollector collector) {
		try {
			System.out.println("watching source folder '"+sourceFolder+"'");
			this.sourceFolder = sourceFolder;
			this.collector = collector;
			this.wk2folder = new HashMap<>();
			this.watcher = FileSystems.getDefault().newWatchService();
			registerAll(this.sourceFolder);
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

	private void register(Path folder) throws IOException {
		WatchKey key = folder.register(watcher,
				 ENTRY_CREATE,
				 ENTRY_DELETE,
				 ENTRY_MODIFY);
		wk2folder.put(key, folder);
	}

	public void startEventLoop() {
		Executors.newSingleThreadExecutor().submit(this::eventLoop);
	}
	
	/**
     * asynchronous collect events
     */
    void eventLoop() {
    	System.out.println("EVENTLOOP STARTED IN THREAD "+ Thread.currentThread().getId());
    	// Thread.currentThread().setDaemon(true);
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
                    collector.rescanAll();
                    break;
                }
                // Context for directory entry event is the file name of entry
                @SuppressWarnings("unchecked")
				WatchEvent<Path> ev = (WatchEvent<Path>)event;
                Path name = ev.context();
                Path child = dir.resolve(name);
                // System.out.format("%s: %s\n", event.kind().name(), child);
                if ((kind == ENTRY_MODIFY) || (kind == ENTRY_CREATE)) {
                	if (Files.isRegularFile(child)) {
                		collector.fileChanged(child);
//	                	Path target = targetFolder.resolve(sourceFolder.relativize(child.resolveSibling(child.getFileName() + ".pgp")));
//                		processFile(child, target);
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
        collector.shutdown();
    }
    
	
}
