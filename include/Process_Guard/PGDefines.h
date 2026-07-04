/**
 * @file PGDefines.h
 * @brief ProcessGuard 全局定义和常量
 * @version 2.0
 *
 * 仅保留仍被使用的全局定义（LogLevel）。历史遗留的 GuardConfig / ProcessMode /
 * RestartPolicy 枚举与 PG_DEBUG/PG_INFO/PG_WARN/PG_ERROR 宏、未引用的版本号与
 * 互斥体/事件前缀常量已移除（无消费者）。
 *
 * v3 hardening 新增 AppKind：区分普通 Win32 进程与 WindowsApps（UWP/Store
 * 打包应用）。WindowsApps 无法用 CreateProcessW 直接启动，必须经 AUMID 调
 * IApplicationActivationManager 激活，因此守护恢复路径需要按 kind 分流。
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

/**
 * @brief 被守护进程的启动方式分类。
 *
 * AppKind::Win32  —— 传统可执行镜像，用 CreateProcessW / CreateProcessAsUserW
 *                    启动（PGS 原有能力）。
 * AppKind::WinApp —— WindowsApps（UWP / Store）打包应用，必须经 AUMID 调
 *                    IApplicationActivationManager::ActivateApplication 激活。
 *                    其可执行路径仍会记录用于 hash 校验与人读，但重启不走
 *                    CreateProcess*，而走 restartAppGuard()。
 *
 * 持久化为归档中的 GUARD 行字段（见 PGS.cpp persistState/loadPersistedState），
 * v2 归档缺省值为 Win32，保证旧档平滑迁移到 v3。
 */
enum class AppKind
{
    Win32 = 0,
    WinApp = 1
};

#endif // PG_DEFINES_H