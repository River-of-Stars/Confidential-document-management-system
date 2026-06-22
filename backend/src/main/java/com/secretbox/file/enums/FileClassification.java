package com.secretbox.file.enums;

import lombok.Getter;

@Getter
public enum FileClassification {
    PUBLIC("公开", 0),
    INTERNAL("内部", 1),
    SECRET("秘密", 2),
    CONFIDENTIAL("机密", 3),
    TOP_SECRET("绝密", 4);

    private final String name;
    private final int level;

    FileClassification(String name, int level) {
        this.name = name;
        this.level = level;
    }

    public static FileClassification fromLevel(int level) {
        for (FileClassification c : values()) {
            if (c.level == level) {
                return c;
            }
        }
        return INTERNAL;
    }
}