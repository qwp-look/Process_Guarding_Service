/**
 * @file PGLogger.h
 * @brief ProcessGuard 日志系统
 * @version 2.0
 *
 * 提供轻量级的日志记录功能
 */

#ifndef PG_LOGGER_H
#define PG_LOGGER_H

#include "PGDefines.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <ctime>
#include <filesystem>
#include <vector>

namespace ProcessGuard
{

    /**
     * @class Logger
     * @brief 日志记录器
     */
    class Logger
    {
    public:
        /**
         * 初始化日志系统
         * @param logFilePath 日志文件路径（为空则仅输出到控制台）
         */
        static void initialize(const std::string &logFilePath = "")
        {
            std::lock_guard<std::mutex> lock(m_mutex);

            if (m_logFile.is_open())
            {
                m_logFile.close();
            }

            if (!logFilePath.empty())
            {
                std::filesystem::path p(logFilePath);
                if (!p.parent_path().empty())
                {
                    std::error_code ec;
                    std::filesystem::create_directories(p.parent_path(), ec);
                }
                m_logFile.open(logFilePath, std::ios::app);
            }
        }

        /**
         * 关闭日志系统
         */
        static void shutdown()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_logFile.is_open())
            {
                m_logFile.close();
            }
        }

        /**
         * 记录日志
         */
        static void log(LogLevel level, const std::string &msg)
        {
            std::lock_guard<std::mutex> lock(m_mutex);

            std::string timestamp = getTimestamp();
            std::string levelStr = levelToString(level);
            std::string formattedMsg = "[" + timestamp + "] [" + levelStr + "] " + msg;

            // 控制台输出
            const bool toStdErr = (level == LogLevel::ERROR_LEVEL || level == LogLevel::CRITICAL);
            if (!writeConsoleUtf8(formattedMsg, toStdErr))
            {
                SetConsoleOutputCP(CP_UTF8);
                if (toStdErr)
                {
                    std::cerr << formattedMsg << std::endl;
                }
                else
                {
                    std::cout << formattedMsg << std::endl;
                }
            }

            // 文件输出
            if (m_logFile.is_open())
            {
                m_logFile << formattedMsg << std::endl;
                m_logFile.flush();
            }
        }

        static void info(const std::string &msg) { log(LogLevel::INFO, msg); }
        static void warning(const std::string &msg) { log(LogLevel::WARNING, msg); }
        static void error(const std::string &msg) { log(LogLevel::ERROR_LEVEL, msg); }
        static void critical(const std::string &msg) { log(LogLevel::CRITICAL, msg); }
        static void debug(const std::string &msg)
        {
#ifdef _DEBUG
            log(LogLevel::DEBUG, msg);
#else
            (void)msg;
#endif
        }

    private:
        static std::mutex m_mutex;
        static std::ofstream m_logFile;

        static std::string getTimestamp()
        {
            SYSTEMTIME st;
            GetLocalTime(&st);

            std::stringstream ss;
            ss << std::setfill('0') << std::setw(4) << st.wYear << "-"
               << std::setfill('0') << std::setw(2) << st.wMonth << "-"
               << std::setfill('0') << std::setw(2) << st.wDay << " "
               << std::setfill('0') << std::setw(2) << st.wHour << ":"
               << std::setfill('0') << std::setw(2) << st.wMinute << ":"
               << std::setfill('0') << std::setw(2) << st.wSecond << "."
               << std::setfill('0') << std::setw(3) << st.wMilliseconds;
            return ss.str();
        }

        static std::string levelToString(LogLevel level)
        {
            switch (level)
            {
            case LogLevel::DEBUG:
                return "DEBUG";
            case LogLevel::INFO:
                return "INFO";
            case LogLevel::WARNING:
                return "WARN";
            case LogLevel::ERROR_LEVEL:
                return "ERROR";
            case LogLevel::CRITICAL:
                return "CRITICAL";
            default:
                return "UNKNOWN";
            }
        }

        static bool writeConsoleUtf8(const std::string &textUtf8, bool useStdErr)
        {
            HANDLE h = GetStdHandle(useStdErr ? STD_ERROR_HANDLE : STD_OUTPUT_HANDLE);
            if (!h || h == INVALID_HANDLE_VALUE)
            {
                return false;
            }

            DWORD mode = 0;
            if (!GetConsoleMode(h, &mode))
            {
                return false;
            }

            const int wideLen = MultiByteToWideChar(CP_UTF8, 0, textUtf8.c_str(), -1, nullptr, 0);
            if (wideLen <= 0)
            {
                return false;
            }

            std::vector<wchar_t> wide(static_cast<std::size_t>(wideLen), L'\0');
            if (MultiByteToWideChar(CP_UTF8, 0, textUtf8.c_str(), -1, wide.data(), wideLen) <= 0)
            {
                return false;
            }
            if (!wide.empty() && wide.back() == L'\0')
            {
                wide.pop_back();
            }

            DWORD written = 0;
            if (!wide.empty())
            {
                if (!WriteConsoleW(h, wide.data(), static_cast<DWORD>(wide.size()), &written, nullptr))
                {
                    return false;
                }
            }
            static const wchar_t kNewLine[] = L"\n";
            return WriteConsoleW(h, kNewLine, 1, &written, nullptr) == TRUE;
        }
    };

} // namespace ProcessGuard

#endif // PG_LOGGER_H
