package com.secretbox.config;

import com.baomidou.mybatisplus.annotation.DbType;
import com.baomidou.mybatisplus.extension.plugins.MybatisPlusInterceptor;
import com.baomidou.mybatisplus.extension.plugins.inner.PaginationInnerInterceptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * MyBatis-Plus 分页插件配置（兼容 SQLite / MySQL）
 */
@Configuration
public class DatabaseConfig {

    @Bean
    public MybatisPlusInterceptor mybatisPlusInterceptor() {
        MybatisPlusInterceptor interceptor = new MybatisPlusInterceptor();
        // 自动适配数据库类型（SQLite / MySQL 均支持）
        interceptor.addInnerInterceptor(new PaginationInnerInterceptor(DbType.OTHER));
        return interceptor;
    }
}