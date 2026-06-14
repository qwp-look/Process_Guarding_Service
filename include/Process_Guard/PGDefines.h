/**
 * @file PGDefines.h
 * @brief ProcessGuard 全局定义和常量
 * @version 2.0
 *
 * 定义了整个守护系统的常量、类型和宏定义
 */

#ifndef PG_DEFINES_H
#define PG_DEFINES_H

#include <string>
#include <windows.h>

// ============================================================================
// 版本信息
// ============================================================================

#define PG_VERSION_MAJOR 2
#define PG_VERSION_MINOR 0
#define PG_VERSION_PATCH 0

// ============================================================================
// 配置常量
// ============================================================================

/** 进程重启最大尝试次数 */
constexpr int PG_MAX_RESTART_ATTEMPTS = 5;

/** 重启延迟（毫秒）*/
constexpr DWORD PG_RESTART_DELAY_MS = 100;

/** 互斥体前缀 */
constexpr const char *PG_MUTEX_PREFIX = "Global\\ProcessGuard_";

/** 退出事件前缀 */
constexpr const char *PG_EVENT_PREFIX = "Global\\ProcessGuardExit_";

/** 监控循环检查间隔（毫秒）*/
constexpr DWORD PG_MONITOR_INTERVAL_MS = 1000;

// ============================================================================
// 枚举类型
// ============================================================================

/**
 * 进程模式
 */
enum class ProcessMode
{
    MAIN,     ///< 主进程（被守护）
    GUARDIAN, ///< 守护进程
    SERVICE   ///< Windows 服务模式
};

/**
 * 重启策略
 */
enum class RestartPolicy
{
    ALWAYS,          ///< 崩溃时总是重启
    NEVER,           ///< 不重启
    LIMITED_ATTEMPTS ///< 有限次数重启
};

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

// ============================================================================
// 结构体定义
// ============================================================================

/**
 * 守护配置信息
 */
struct GuardConfig
{
    std::string appName;         ///< 应用名称
    std::string appVersion;      ///< 应用版本
    RestartPolicy restartPolicy; ///< 重启策略
    int maxRestartAttempts;      ///< 最大重启次数
    DWORD restartDelayMs;        ///< 重启延迟（毫秒）
    DWORD monitorIntervalMs;     ///< 监控间隔（毫秒）
    bool enableLogging;          ///< 是否启用日志
    std::string logFilePath;     ///< 日志文件路径（可选）

    GuardConfig()
        : appName("ProcessGuard"), appVersion("2.0.0"), restartPolicy(RestartPolicy::ALWAYS), maxRestartAttempts(PG_MAX_RESTART_ATTEMPTS), restartDelayMs(PG_RESTART_DELAY_MS), monitorIntervalMs(PG_MONITOR_INTERVAL_MS), enableLogging(true), logFilePath("")
    {
    }
};

// ============================================================================
// 宏定义
// ============================================================================

#ifdef _DEBUG
#define PG_DEBUG(msg) std::cerr << "[DEBUG] " << msg << std::endl
#else
#define PG_DEBUG(msg)
#endif

#define PG_INFO(msg) std::cout << "[INFO] " << msg << std::endl
#define PG_WARN(msg) std::cerr << "[WARN] " << msg << std::endl
#define PG_ERROR(msg) std::cerr << "[ERROR] " << msg << std::endl

#endif // PG_DEFINES_H
