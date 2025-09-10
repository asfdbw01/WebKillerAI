package com.webkillerai.app.app;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.webkillerai.app.logging.LogSetup;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class App extends Application {
    private static final Logger LOG = Logger.getLogger(App.class.getName());

    @Override
    public void start(Stage stage) throws Exception {
        // 로그 초기화 (-Dwk.out.dir 없으면 "out")
        Path outRoot = Paths.get(System.getProperty("wk.out.dir", "out"));
        Path logDir  = outRoot.resolve("logs");
        LogSetup.init(logDir);
        LOG.info(() -> "Log initialized at: " + logDir.toAbsolutePath());

        // 전역 uncaught 핸들러
        Thread.setDefaultUncaughtExceptionHandler((t, e) ->
                LOG.log(Level.SEVERE, "\n==== Uncaught: " + t.getName() + " ====", e));
        Thread.currentThread().setUncaughtExceptionHandler((t, e) ->
                LOG.log(Level.SEVERE, "\n==== Uncaught FX: " + t.getName() + " ====", e));

        // FXML 로드 (컨트롤러 바인딩 호출 없음)
        Parent root = FXMLLoader.load(App.class.getResource("/com/webkillerai/app/ui/MainView.fxml"));

        // 씬/스타일
        Scene scene = new Scene(root, 800, 500);
        var css = App.class.getResource("/com/webkillerai/app/ui/app.css");
        if (css != null) scene.getStylesheets().add(css.toExternalForm());

        stage.setTitle("WebKillerAI");
        stage.setScene(scene);
        stage.setOnCloseRequest(e -> javafx.application.Platform.exit());
        stage.show();

        LOG.info("WebKillerAI UI shown.");
    }

    public static void main(String[] args) {
        launch(args);
    }
}
