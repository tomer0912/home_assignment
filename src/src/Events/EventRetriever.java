package src.Events;

import java.io.*;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class EventRetriever  implements Iterator<FirewallEvent>, AutoCloseable{
    private BufferedReader reader;
    private String nextLine;

    public EventRetriever()  throws IOException {
        EventRetriever.unzip(Config.EVENTS_ZIP_FILE_PATH, System.getProperty("user.dir") + "/instructions");
        this.reader = new BufferedReader(new FileReader(Config.EVENTS_FILE_PATH));
        advance();
    }

    private void advance() {
        try {
            nextLine = reader.readLine();
            if (nextLine == null) {
                close(); // Auto-close at end of file
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void close() throws Exception {
        try {
            reader.close();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public boolean hasNext() {
        return nextLine != null;
    }

    @Override
    public FirewallEvent next() {
        if (!hasNext()) {
            throw new NoSuchElementException("No more lines");
        }
        String lineToReturn = nextLine;
        advance();
        return new FirewallEvent(lineToReturn);
    }

    public static void unzip(String zipFilePath, String destDirectory) throws IOException {
        File destDir = new File(destDirectory);
        if (!destDir.exists()) {
            destDir.mkdirs(); // Create destination directory if it doesn't exist
        }

        try (ZipInputStream zipIn = new ZipInputStream(new FileInputStream(zipFilePath))) {
            ZipEntry entry = zipIn.getNextEntry();
            while (entry != null) {
                File filePath = new File(destDirectory, entry.getName());

                if (entry.isDirectory()) {
                    filePath.mkdirs();
                } else {
                    // Create parent directories
                    new File(filePath.getParent()).mkdirs();

                    // Write file content
                    try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(filePath))) {
                        byte[] buffer = new byte[4096];
                        int bytesRead;
                        while ((bytesRead = zipIn.read(buffer)) != -1) {
                            bos.write(buffer, 0, bytesRead);
                        }
                    }
                }
                zipIn.closeEntry();
                entry = zipIn.getNextEntry();
            }
        }
    }
}


