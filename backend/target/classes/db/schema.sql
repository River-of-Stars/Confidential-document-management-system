-- 用户表
CREATE TABLE IF NOT EXISTS `user` (
    `id` INTEGER PRIMARY KEY AUTOINCREMENT,
    `username` VARCHAR(50) NOT NULL UNIQUE,
    `password` VARCHAR(255) NOT NULL,
    `real_name` VARCHAR(50),
    `email` VARCHAR(100),
    `phone` VARCHAR(20),
    `role_code` VARCHAR(20) NOT NULL,  -- SUPER_ADMIN, DEPT_SECRETARY, EMPLOYEE
    `department` VARCHAR(50),
    `status` TINYINT DEFAULT 1,        -- 1启用 0禁用
    `locked_until` DATETIME,            -- 锁定到期时间（NULL表示未锁定）
    `login_fail_count` INT DEFAULT 0,   -- 连续失败次数
    `last_login_time` DATETIME,
    `created_by` VARCHAR(50),
    `created_time` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `updated_time` DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 角色表（实际可用枚举硬编码，但为扩展性保留）
CREATE TABLE IF NOT EXISTS `role` (
    `id` INTEGER PRIMARY KEY AUTOINCREMENT,
    `role_code` VARCHAR(20) NOT NULL UNIQUE,
    `role_name` VARCHAR(50) NOT NULL,
    `description` VARCHAR(255)
);

-- 初始化角色数据
INSERT OR IGNORE INTO `role` (`role_code`, `role_name`, `description`) VALUES
('SUPER_ADMIN', '超级管理员', '所有权限'),
('DEPT_SECRETARY', '部门保密员', '管理本部门文件和人员'),
('EMPLOYEE', '普通员工', '仅访问被授权的文件');