package com.webkillerai.core.util;

import java.io.IOException;
import java.nio.file.*;
import java.util.logging.*;

public final class LoggingConfigurator {
    private LoggingConfigurator() {}

    public static void init(String logDir, Level rootLevel, int maxBytes, int fileCount) {
        try { Files.createDirectories(Paths.get(logDir)); } catch (IOException ignore) {}

        Logger root = LogManager.getLogManager().getLogger("");
        for (Handler h : root.getHandlers()) root.removeHandler(h);

        ConsoleHandler console = new ConsoleHandler();
        console.setLevel(rootLevel);
        console.setFormatter(new Formatter() {
            @Override public String format(LogRecord r) { return r.getMessage() + System.lineSeparator(); }
        });
        root.addHandler(console);

        try {
            String pattern = Paths.get(logDir, "app-%g.log").toString();
            FileHandler file = new FileHandler(pattern, maxBytes, fileCount, true);
            file.setLevel(rootLevel);
            file.setFormatter(console.getFormatter()); // 같은 포맷
            root.addHandler(file);
        } catch (IOException e) {
            System.err.println("Failed to init file handler: " + e.getMessage());
        }

        root.setLevel(rootLevel);
    }
}
