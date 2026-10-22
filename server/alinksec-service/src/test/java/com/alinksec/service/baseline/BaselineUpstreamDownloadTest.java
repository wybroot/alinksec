package com.alinksec.service.baseline;

import com.alinksec.service.library.*;
import com.alinksec.service.config.AlinkSecProperties;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.net.InetSocketAddress;
import java.nio.file.*;
import java.util.Map;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;

class BaselineUpstreamDownloadTest {
    @TempDir Path root;
    @Test void absoluteDeadlineBodyCapAndRedirectDoNotLeaveTemporaryFiles()throws Exception{
        var props=new LibraryProperties();props.setWorkDir(root.toString());var download=new FeedDownload(new LibraryFiles(props,new AlinkSecProperties()),props);
        var http=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);var executor=Executors.newCachedThreadPool();http.setExecutor(executor);
        http.createContext("/slow",request->{try{Thread.sleep(1000);request.sendResponseHeaders(200,1);request.getResponseBody().write(1);}catch(Exception ignored){}finally{request.close();}});
        http.createContext("/oversize",request->{try{request.sendResponseHeaders(200,0);request.getResponseBody().write(new byte[8192]);}finally{request.close();}});
        http.createContext("/redirect",request->{request.getResponseHeaders().set("Location","http://example.invalid/");request.sendResponseHeaders(302,-1);request.close();});
        http.start();String base="http://127.0.0.1:"+http.getAddress().getPort();
        try{
            long start=System.nanoTime();assertThrows(java.io.IOException.class,()->download.fetchBounded(base+"/slow",Map.of(),100,200));assertTrue(System.nanoTime()-start<2_000_000_000L);
            assertThrows(java.io.IOException.class,()->download.fetchBounded(base+"/oversize",Map.of(),100,2000));assertThrows(java.io.IOException.class,()->download.fetchBounded(base+"/redirect",Map.of(),100,2000));
            try(var files=Files.list(root.resolve("tmp"))){assertEquals(0,files.count());}
        }finally{http.stop(0);executor.shutdownNow();}
    }
}
