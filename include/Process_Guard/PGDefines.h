/**
 * @file PGDefines.h
 * @brief ProcessGuard 全局定义和常量
 * @version 2.0
 *
 * 仅保留仍被使用的全局定义（LogLevel）。历史遗留的 GuardConfig / ProcessMode /
 * RestartPolicy 枚举与 PG_DEBUG/PG_INFO/PG_WARN/PG_ERROR 宏、未引用的版本号与
 * 互斥体/事件前缀常量已移除（无消费者）。
 */
#ifndef PG_DEFINES_H
#define PG_DEFINES_H

#include <windows.h>

/**
 * 日志级别
 */
enum class LogLevel
{
    DEBUG,
    INFO,
    WARNING,
    ERROR_LEVEL,
    CRITICAL
};

#endif // PG_DEFINES_H
