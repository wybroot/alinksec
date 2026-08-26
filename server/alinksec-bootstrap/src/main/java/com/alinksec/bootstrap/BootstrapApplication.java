package com.alinksec.bootstrap;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * ALinkSec 服务端入口（M1：gRPC 通道 + PG 落库）。
 * 扫描范围覆盖全部模块。
 */
@SpringBootApplication(scanBasePackages = "com.alinksec")
@EnableScheduling
@EnableAsync
public class BootstrapApplication {

    public static void main(String[] args) {
        SpringApplication.run(BootstrapApplication.class, args);
    }
}
