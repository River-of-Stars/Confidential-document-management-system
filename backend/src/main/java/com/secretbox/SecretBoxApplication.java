package com.secretbox;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.transaction.annotation.EnableTransactionManagement;

/**
 * 项目主启动类
 * - @SpringBootApplication 开启自动配置
 * - @MapperScan 扫描所有Mapper接口（MyBatis-Plus）
 * - @EnableTransactionManagement 开启事务管理
 * - @EnableScheduling 启用定时任务（后续备份/监控使用）
 */
@SpringBootApplication
@MapperScan("com.secretbox.*.mapper")   // 扫描所有mapper包
@EnableTransactionManagement
@EnableScheduling
public class SecretBoxApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecretBoxApplication.class, args);
        System.out.println("✅ 保密文件管理系统启动成功！");
        System.out.println("🔐 默认超级管理员: admin / admin123 (若DataInitializer已启用)");
    }
}