#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winternl.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

#include "Process_Guard/ModuleManager.h"
#include "Process_Guard/PGUtil.h"
#include "Process_Guard/PGSClient.h"
namespace
{

constexpr DWORD kSocketTimeoutMs = 3000;

struct ParsedSummary
{
    std::unordered_map<std::string, std::string> kv;
};

struct LaunchResult
{
    // bless-start launches suspended first, so we must carry both handles until
    // registration succeeds and the primary thread is resumed.
    DWORD pid = 0;
    std::string pathUtf8;
    std::string startArgsUtf8;
    HANDLE processHandle = nullptr;
    HANDLE threadHandle = nullptr;
};

constexpr ULONG kProcessCommandLineInformationClass = 60;

std::string trim(std::string value)
{
    return ProcessGuard::util::trim(value);
}

std::wstring narrowToWideBestEffort(const std::string &input)
{
    return ProcessGuard::util::narrowToWideBestEffort(input);
}

std::string wideToUtf8(const std::wstring &input)
{
    return ProcessGuard::util::wideToUtf8(input);
}

std::string win32ErrorText(DWORD code)
{
    return ProcessGuard::util::win32ErrorText(code);
}

std::wstring normalizePathForCompare(const std::wstring &pathInput)
{
    if (pathInput.empty())
    {
        return std::wstring();
    }
    std::vector<wchar_t> fullPathBuf(32768, L'\0');
    DWORD fullLen = GetFullPathNameW(pathInput.c_str(), static_cast<DWORD>(fullPathBuf.size()), fullPathBuf.data(), nullptr);
    if (fullLen == 0 || fullLen >= fullPathBuf.size())
    {
        return std::wstring();
    }
    std::wstring path(fullPathBuf.data(), fullLen);
    std::replace(path.begin(), path.end(), L'/', L'\\');
    std::transform(path.begin(), path.end(), path.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(towlower(ch));
    });
    return path;
}

std::string base64Encode(const std::string &input)
{
    return ProcessGuard::util::base64Encode(input);
}

std::string base64Decode(const std::string &input)
{
    return ProcessGuard::util::base64Decode(input);
}

bool parsePid(const std::string &text, DWORD &pid)
{
    const std::string value = trim(text);
    if (value.empty())
    {
        return false;
    }
    for (char c : value)
    {
        if (c < '0' || c > '9')
        {
            return false;
        }
    }
    try
    {
        pid = static_cast<DWORD>(std::stoul(value));
        return pid != 0;
    }
    catch (...)
    {
        return false;
    }
}

bool parseMaxRestarts(const std::string &value, int &outMaxRestarts)
{
    return ProcessGuard::util::parseMaxRestarts(value, outMaxRestarts);
}

std::string maxRestartsLabel(int maxRestarts)
{
    return ProcessGuard::client::maxRestartsLabel(maxRestarts);
}

bool queryProcessPath(DWORD pid, std::string &pathOut)
{
    return ProcessGuard::util::queryProcessPath(pid, pathOut);
}

bool computeFileHash(const std::string &pathUtf8, std::string &outHash)
{
    // File integrity hash is SHA-256 (via CNG), matching the PGS service side.
    return ProcessGuard::util::sha256FileHex(pathUtf8, outHash);
}

std::wstring parentDirectory(const std::wstring &path)
{
    const std::size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos)
    {
        return std::wstring();
    }
    return path.substr(0, pos);
}

std::wstring quoteArgW(const std::wstring &arg)
{
    return ProcessGuard::util::quoteArgW(arg);
}

bool splitLaunchCommand(
    const std::string &commandInput,
    std::wstring &outExeW,
    std::wstring &outArgsW,
    std::string &outError)
{
    const std::wstring commandW = narrowToWideBestEffort(commandInput);
    if (commandW.empty())
    {
        outError = "command is empty";
        return false;
    }

    int argc = 0;
    LPWSTR *argv = CommandLineToArgvW(commandW.c_str(), &argc);
    if (!argv || argc <= 0)
    {
        outError = "CommandLineToArgvW failed";
        if (argv)
        {
            LocalFree(argv);
        }
        return false;
    }

    outExeW = argv[0];
    std::wstring args;
    for (int i = 1; i < argc; ++i)
    {
        if (!args.empty())
        {
            args.push_back(L' ');
        }
        args += quoteArgW(argv[i]);
    }
    outArgsW = args;
    LocalFree(argv);
    return true;
}

bool queryProcessCommandLineArgs(DWORD pid, std::string &outArgsUtf8)
{
    outArgsUtf8.clear();

    // Best effort only:
    // - some system processes will refuse inspection
    // - older Windows versions may not expose this information uniformly
    //
    // When this fails we simply fall back to empty restart args instead of
    // aborting a normal bless operation.
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process)
    {
        return false;
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
    {
        CloseHandle(process);
        return false;
    }

    using NtQueryInformationProcessFn = LONG(WINAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    const FARPROC queryProc = GetProcAddress(ntdll, "NtQueryInformationProcess");
    NtQueryInformationProcessFn ntQueryInformationProcess = nullptr;
    static_assert(sizeof(ntQueryInformationProcess) == sizeof(queryProc));
    std::memcpy(&ntQueryInformationProcess, &queryProc, sizeof(queryProc));
    if (!ntQueryInformationProcess)
    {
        CloseHandle(process);
        return false;
    }

    ULONG needed = 0;
    LONG status = ntQueryInformationProcess(process, kProcessCommandLineInformationClass, nullptr, 0, &needed);
    if (needed == 0 && status >= 0)
    {
        CloseHandle(process);
        return false;
    }

    std::vector<unsigned char> buffer(needed);
    status = ntQueryInformationProcess(process, kProcessCommandLineInformationClass, buffer.data(), needed, &needed);
    CloseHandle(process);
    if (status < 0 || buffer.size() < sizeof(UNICODE_STRING))
    {
        return false;
    }

    const auto *commandLine = reinterpret_cast<const UNICODE_STRING *>(buffer.data());
    if (!commandLine->Buffer || commandLine->Length == 0)
    {
        return true;
    }

    const std::wstring fullCommandLine(commandLine->Buffer, commandLine->Length / sizeof(wchar_t));
    int argc = 0;
    LPWSTR *argv = CommandLineToArgvW(fullCommandLine.c_str(), &argc);
    if (!argv || argc <= 0)
    {
        if (argv)
        {
            LocalFree(argv);
        }
        return false;
    }

    std::wstring argsW;
    for (int i = 1; i < argc; ++i)
    {
        if (!argsW.empty())
        {
            argsW.push_back(L' ');
        }
        argsW += quoteArgW(argv[i]);
    }
    LocalFree(argv);

    outArgsUtf8 = wideToUtf8(argsW);
    return true;
}

void closeLaunchHandles(LaunchResult &launch)
{
    if (launch.threadHandle)
    {
        CloseHandle(launch.threadHandle);
        launch.threadHandle = nullptr;
    }
    if (launch.processHandle)
    {
        CloseHandle(launch.processHandle);
        launch.processHandle = nullptr;
    }
}

void rollbackLaunch(LaunchResult &launch)
{
    // Used by bless-start when "start succeeded but register failed".
    // In that window the child has not become a valid guarded object yet, so
    // the safest behavior is to terminate it immediately and close the handles.
    if (launch.processHandle)
    {
        TerminateProcess(launch.processHandle, 1);
        WaitForSingleObject(launch.processHandle, 3000);
    }
    closeLaunchHandles(launch);
}

bool resumeLaunch(LaunchResult &launch, std::string &outError)
{
    if (!launch.threadHandle)
    {
        return true;
    }

    if (ResumeThread(launch.threadHandle) == static_cast<DWORD>(-1))
    {
        outError = "ResumeThread failed: " + win32ErrorText(GetLastError());
        return false;
    }

    closeLaunchHandles(launch);
    return true;
}

[[maybe_unused]] bool startProcessFromPath(
    const std::string &pathInput,
    const std::string &startArgsInput,
    LaunchResult &outLaunch,
    std::string &outError)
{
    outLaunch = LaunchResult{};

    const std::wstring pathWRaw = narrowToWideBestEffort(pathInput);
    if (pathWRaw.empty())
    {
        outError = "path is empty after conversion";
        return false;
    }

    std::vector<wchar_t> fullPathBuf(32768, L'\0');
    DWORD fullLen = GetFullPathNameW(pathWRaw.c_str(), static_cast<DWORD>(fullPathBuf.size()), fullPathBuf.data(), nullptr);
    if (fullLen == 0 || fullLen >= fullPathBuf.size())
    {
        outError = "GetFullPathNameW failed: " + win32ErrorText(GetLastError());
        return false;
    }
    const std::wstring fullPath(fullPathBuf.data(), fullLen);

    const DWORD attr = GetFileAttributesW(fullPath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES)
    {
        outError = "target file not found: " + wideToUtf8(fullPath) + ", " + win32ErrorText(GetLastError());
        return false;
    }
    if ((attr & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        outError = "target path is a directory: " + wideToUtf8(fullPath);
        return false;
    }

    std::wstring command = L"\"" + fullPath + L"\"";
    const std::wstring argsW = narrowToWideBestEffort(startArgsInput);
    if (!argsW.empty())
    {
        command += L" ";
        command += argsW;
    }
    std::vector<wchar_t> writableCmd(command.begin(), command.end());
    writableCmd.push_back(L'\0');

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    const std::wstring workDir = parentDirectory(fullPath);

    BOOL ok = CreateProcessW(
        nullptr,
        writableCmd.data(),
        nullptr,
        nullptr,
        FALSE,
        // Start suspended so bless-start can become effectively atomic:
        // register first, then resume the primary thread only after PGS has
        // accepted the new guard.
        CREATE_NEW_CONSOLE | CREATE_SUSPENDED,
        nullptr,
        workDir.empty() ? nullptr : workDir.c_str(),
        &si,
        &pi);

    if (!ok)
    {
        outError = "CreateProcessW failed for path=" + wideToUtf8(fullPath) + ", " + win32ErrorText(GetLastError());
        return false;
    }

    outLaunch.pid = pi.dwProcessId;
    outLaunch.pathUtf8 = wideToUtf8(fullPath);
    outLaunch.startArgsUtf8 = wideToUtf8(argsW);
    outLaunch.processHandle = pi.hProcess;
    outLaunch.threadHandle = pi.hThread;
    return true;
}

bool startProcessFromCommand(
    const std::string &commandInput,
    LaunchResult &outLaunch,
    std::string &outError)
{
    outLaunch = LaunchResult{};

    std::wstring exeW;
    std::wstring argsW;
    if (!splitLaunchCommand(commandInput, exeW, argsW, outError))
    {
        return false;
    }

    std::vector<wchar_t> fullPathBuf(32768, L'\0');
    DWORD fullLen = GetFullPathNameW(exeW.c_str(), static_cast<DWORD>(fullPathBuf.size()), fullPathBuf.data(), nullptr);
    if (fullLen == 0 || fullLen >= fullPathBuf.size())
    {
        outError = "GetFullPathNameW failed: " + win32ErrorText(GetLastError());
        return false;
    }
    const std::wstring fullPath(fullPathBuf.data(), fullLen);

    const DWORD attr = GetFileAttributesW(fullPath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES)
    {
        outError = "target file not found: " + wideToUtf8(fullPath) + ", " + win32ErrorText(GetLastError());
        return false;
    }
    if ((attr & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        outError = "target path is a directory: " + wideToUtf8(fullPath);
        return false;
    }

    std::wstring command = quoteArgW(fullPath);
    if (!argsW.empty())
    {
        command.push_back(L' ');
        command += argsW;
    }
    std::vector<wchar_t> writableCmd(command.begin(), command.end());
    writableCmd.push_back(L'\0');

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    const std::wstring workDir = parentDirectory(fullPath);

    BOOL ok = CreateProcessW(
        nullptr,
        writableCmd.data(),
        nullptr,
        nullptr,
        FALSE,
        // Same reasoning as startProcessFromPath(): keep the child suspended
        // until the service has acknowledged the guard registration.
        CREATE_NEW_CONSOLE | CREATE_SUSPENDED,
        nullptr,
        workDir.empty() ? nullptr : workDir.c_str(),
        &si,
        &pi);

    if (!ok)
    {
        outError = "CreateProcessW failed for command=" + commandInput + ", " + win32ErrorText(GetLastError());
        return false;
    }

    outLaunch.pid = pi.dwProcessId;
    outLaunch.pathUtf8 = wideToUtf8(fullPath);
    outLaunch.startArgsUtf8 = wideToUtf8(argsW);
    outLaunch.processHandle = pi.hProcess;
    outLaunch.threadHandle = pi.hThread;
    return true;
}

bool sendToPGS(
    const std::string &host,
    unsigned short port,
    const std::string &commandPayload,
    std::string &responseOut)
{
    // Delegate to the shared PGSClient transport so the CLI, Qt and Web front
    // ends share one implementation of the line-oriented protocol. The caller
    // is responsible for wrapping the command in the auth envelope (withToken).
    ProcessGuard::client::ClientOptions opts;
    opts.host = host;
    opts.port = port;
    const auto resp = ProcessGuard::client::sendCommand(opts, commandPayload, kSocketTimeoutMs);
    responseOut = resp.payload;
    return resp.ok;
}

std::vector<std::string> splitBy(const std::string &value, char delimiter)
{
    return ProcessGuard::util::split(value, delimiter);
}

ParsedSummary parseSummaryLine(const std::string &line)
{
    ParsedSummary result;
    for (const std::string &field : splitBy(line, ';'))
    {
        const std::size_t eq = field.find('=');
        if (eq == std::string::npos)
        {
            continue;
        }
        const std::string key = trim(field.substr(0, eq));
        const std::string value = trim(field.substr(eq + 1));
        result.kv[key] = value;
    }
    return result;
}

std::string jsonEscape(const std::string &value)
{
    return ProcessGuard::client::jsonEscape(value);
}

void printSummaries(const std::vector<std::string> &lines, bool jsonOutput)
{
    std::vector<ParsedSummary> parsed;
    parsed.reserve(lines.size());
    for (const std::string &line : lines)
    {
        parsed.push_back(parseSummaryLine(line));
    }

    if (jsonOutput)
    {
        std::cout << "[";
        for (std::size_t i = 0; i < parsed.size(); ++i)
        {
            if (i != 0)
            {
                std::cout << ",";
            }
            const auto &kv = parsed[i].kv;
            auto get = [&](const std::string &key) -> std::string {
                auto it = kv.find(key);
                return it == kv.end() ? "" : it->second;
            };

            const std::string path = base64Decode(get("PATH_B64"));
            const std::string args = base64Decode(get("RESTART_ARGS_B64"));
            const std::string aumid = base64Decode(get("AUMID_B64"));
            const std::string healthCheck = base64Decode(get("HEALTH_CHECK_B64"));
            const std::string restartHook = base64Decode(get("RESTART_HOOK_B64"));
            std::cout << "{"
                      << "\"pid\":\"" << jsonEscape(get("PID")) << "\","
                      << "\"session\":\"" << jsonEscape(get("SESSION")) << "\","
                      << "\"alive\":\"" << jsonEscape(get("ALIVE")) << "\","
                      << "\"intentional\":\"" << jsonEscape(get("INTENTIONAL")) << "\","
                      << "\"max_restarts\":\"" << jsonEscape(get("MAX_RESTARTS")) << "\","
                      << "\"restart_count\":\"" << jsonEscape(get("RESTART_COUNT")) << "\","
                      << "\"hash_verified\":\"" << jsonEscape(get("HASH_VERIFIED")) << "\","
                      << "\"hash\":\"" << jsonEscape(get("HASH")) << "\","
                      << "\"app_kind\":\"" << jsonEscape(get("APP_KIND")) << "\","
                      << "\"aumid\":\"" << jsonEscape(aumid) << "\","
                      << "\"restart_window\":\"" << jsonEscape(get("RESTART_WINDOW")) << "\","
                      << "\"restart_delay\":\"" << jsonEscape(get("RESTART_DELAY")) << "\","
                      << "\"backoff\":\"" << jsonEscape(get("BACKOFF")) << "\","
                      << "\"hang_timeout\":\"" << jsonEscape(get("HANG_TIMEOUT")) << "\","
                      << "\"kill_on_exit\":\"" << jsonEscape(get("KILL_ON_EXIT")) << "\","
                      << "\"job_attached\":\"" << jsonEscape(get("JOB_ATTACHED")) << "\","
                      << "\"health_check\":\"" << jsonEscape(healthCheck) << "\","
                      << "\"group\":\"" << jsonEscape(get("GROUP")) << "\","
                      << "\"group_paused\":\"" << jsonEscape(get("GROUP_PAUSED")) << "\","
                      << "\"paused\":\"" << jsonEscape(get("PAUSED")) << "\","
                      << "\"guard_paused\":\"" << jsonEscape(get("GUARD_PAUSED")) << "\","
                      << "\"created_at\":\"" << jsonEscape(get("CREATED_AT")) << "\","
                      << "\"last_start\":\"" << jsonEscape(get("LAST_START")) << "\","
                      << "\"last_exit\":\"" << jsonEscape(get("LAST_EXIT")) << "\","
                      << "\"last_exit_code\":\"" << jsonEscape(get("LAST_EXIT_CODE")) << "\","
                      << "\"cumulative_run_ms\":\"" << jsonEscape(get("CUMULATIVE_RUN_MS")) << "\","
                      << "\"avg_restart_interval_ms\":\"" << jsonEscape(get("AVG_RESTART_INTERVAL_MS")) << "\","
                      << "\"crash_loop\":\"" << jsonEscape(get("CRASH_LOOP")) << "\","
                      << "\"restart_hook\":\"" << jsonEscape(restartHook) << "\","
                      << "\"path\":\"" << jsonEscape(path) << "\","
                      << "\"restart_args\":\"" << jsonEscape(args) << "\""
                      << "}";
        }
        std::cout << "]\n";
        return;
    }

    for (const auto &item : parsed)
    {
        auto get = [&](const std::string &key) -> std::string {
            auto it = item.kv.find(key);
            return it == item.kv.end() ? "-" : it->second;
        };
        std::cout
            << "pid=" << get("PID")
            << " session=" << get("SESSION")
            << " alive=" << get("ALIVE")
            << " intentional=" << get("INTENTIONAL")
            << " max=" << get("MAX_RESTARTS")
            << " restarts=" << get("RESTART_COUNT")
            << " app=" << get("APP_KIND")
            << " job=" << get("JOB_ATTACHED")
            << " group=" << get("GROUP")
            << " paused=" << get("PAUSED")
            << " crash_loop=" << get("CRASH_LOOP")
            << " hash_verified=" << get("HASH_VERIFIED")
            << " hash=" << get("HASH")
            << "\n"
            << "  path: " << base64Decode(get("PATH_B64")) << "\n"
            << "  args: " << base64Decode(get("RESTART_ARGS_B64")) << "\n"
            << "  aumid: " << base64Decode(get("AUMID_B64")) << "\n"
            << "  policy: window=" << get("RESTART_WINDOW")
            << " delay=" << get("RESTART_DELAY")
            << " backoff=" << get("BACKOFF")
            << " hang=" << get("HANG_TIMEOUT")
            << " kill_on_exit=" << get("KILL_ON_EXIT") << "\n"
            << "  profile: created=" << get("CREATED_AT")
            << " last_start=" << get("LAST_START")
            << " last_exit=" << get("LAST_EXIT")
            << " exit_code=" << get("LAST_EXIT_CODE")
            << " run_ms=" << get("CUMULATIVE_RUN_MS")
            << " avg_restart_ms=" << get("AVG_RESTART_INTERVAL_MS") << "\n";
        const std::string healthCheck = base64Decode(get("HEALTH_CHECK_B64"));
        const std::string restartHook = base64Decode(get("RESTART_HOOK_B64"));
        if (!healthCheck.empty())
        {
            std::cout << "  health-check: " << healthCheck << "\n";
        }
        if (!restartHook.empty())
        {
            std::cout << "  restart-hook: " << restartHook << " (execution disabled)\n";
        }
    }
}

std::string joinStrings(const std::vector<std::string> &values, const std::string &delimiter)
{
    std::ostringstream oss;
    for (std::size_t i = 0; i < values.size(); ++i)
    {
        if (i != 0)
        {
            oss << delimiter;
        }
        oss << values[i];
    }
    return oss.str();
}

std::string allowlistPathForModulesDir(const std::string &modulesDir)
{
    if (modulesDir.empty())
    {
        return "modules.allow";
    }
    std::filesystem::path p{narrowToWideBestEffort(modulesDir)};
    p /= L"modules.allow";
    return wideToUtf8(p.wstring());
}

bool findAllowlistEntry(
    const std::string &allowlistPath,
    const std::string &moduleKey,
    ProcessGuard::ModuleManager::AllowEntry &outEntry,
    std::string &outLine)
{
    std::ifstream in(allowlistPath, std::ios::in | std::ios::binary);
    if (!in.is_open())
    {
        return false;
    }

    const std::string key = ProcessGuard::util::toLowerAscii(trim(moduleKey));
    std::string line;
    bool found = false;
    while (std::getline(in, line))
    {
        if (!line.empty() && line.back() == '\r')
        {
            line.pop_back();
        }
        ProcessGuard::ModuleManager::AllowEntry entry;
        if (!ProcessGuard::ModuleManager::parseAllowlistLine(line, entry))
        {
            continue;
        }
        if (ProcessGuard::util::toLowerAscii(entry.name) == key)
        {
            outEntry = entry;
            outLine = ProcessGuard::ModuleManager::formatAllowlistLine(entry);
            found = true;
        }
    }
    return found;
}

bool allowEntrySatisfiesInspection(
    const ProcessGuard::ModuleManager::AllowEntry &entry,
    const ProcessGuard::ModuleManager::ModuleInspection &info)
{
    if (ProcessGuard::util::toLowerAscii(entry.name) != ProcessGuard::util::toLowerAscii(info.allowlistKey))
    {
        return false;
    }
    if (!entry.sha256.empty() &&
        ProcessGuard::util::toLowerAscii(entry.sha256) != ProcessGuard::util::toLowerAscii(info.sha256))
    {
        return false;
    }
    if (entry.requireSigned && !info.signatureValid)
    {
        return false;
    }
    return true;
}

bool writeAllowlistEntry(
    const std::string &modulesDir,
    const ProcessGuard::ModuleManager::AllowEntry &entry,
    std::string &outPath,
    std::string &outLine,
    std::string &outError)
{
    outLine = ProcessGuard::ModuleManager::formatAllowlistLine(entry);
    if (outLine.empty())
    {
        outError = "invalid allowlist entry";
        return false;
    }

    std::filesystem::path modulesPath{narrowToWideBestEffort(modulesDir)};
    std::error_code ec;
    std::filesystem::create_directories(modulesPath, ec);
    if (ec)
    {
        outError = "failed to create modules dir: " + modulesDir;
        return false;
    }

    std::filesystem::path allowPath = modulesPath / L"modules.allow";
    outPath = wideToUtf8(allowPath.wstring());

    std::vector<std::string> lines;
    {
        std::ifstream in(outPath, std::ios::in | std::ios::binary);
        std::string line;
        while (std::getline(in, line))
        {
            if (!line.empty() && line.back() == '\r')
            {
                line.pop_back();
            }
            lines.push_back(line);
        }
    }

    int replaceIndex = -1;
    for (std::size_t i = 0; i < lines.size(); ++i)
    {
        ProcessGuard::ModuleManager::AllowEntry parsed;
        if (ProcessGuard::ModuleManager::parseAllowlistLine(lines[i], parsed) &&
            ProcessGuard::util::toLowerAscii(parsed.name) == ProcessGuard::util::toLowerAscii(entry.name))
        {
            replaceIndex = static_cast<int>(i);
        }
    }

    if (lines.empty())
    {
        lines.push_back("# modules.allow - generated by pgs_bless module trust");
        lines.push_back("# format: name[|sha256Hex][|signed]");
    }
    if (replaceIndex >= 0)
    {
        lines[static_cast<std::size_t>(replaceIndex)] = outLine;
    }
    else
    {
        lines.push_back(outLine);
    }

    std::ofstream out(outPath, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!out.is_open())
    {
        outError = "failed to open allowlist for write: " + outPath;
        return false;
    }
    for (const std::string &line : lines)
    {
        out << line << "\n";
    }
    out.flush();
    if (!out.good())
    {
        outError = "failed to write allowlist: " + outPath;
        return false;
    }
    return true;
}

void printModuleInspection(
    const ProcessGuard::ModuleManager::ModuleInspection &info,
    const std::string &modulesDir,
    const std::string &allowlistPath,
    bool allowEntryFound,
    bool allowEntrySatisfied,
    const std::string &allowEntryLine,
    bool jsonOutput)
{
    const bool nameMatchesKey =
        !info.name.empty() &&
        ProcessGuard::util::toLowerAscii(info.name) == ProcessGuard::util::toLowerAscii(info.allowlistKey);
    const std::string caps = joinStrings(info.manifest.capabilities, ",");
    const std::string nameDisplay = info.name.empty() ? std::string("-") : info.name;
    const std::string nameSuffix = (nameMatchesKey || info.name.empty()) ? std::string() : std::string(" (does not match key)");

    if (jsonOutput)
    {
        std::cout << "{"
                  << "\"path\":\"" << jsonEscape(info.path) << "\","
                  << "\"modules_dir\":\"" << jsonEscape(modulesDir) << "\","
                  << "\"allowlist\":\"" << jsonEscape(allowlistPath) << "\","
                  << "\"allowlist_key\":\"" << jsonEscape(info.allowlistKey) << "\","
                  << "\"name\":\"" << jsonEscape(info.name) << "\","
                  << "\"name_matches_key\":" << (nameMatchesKey ? "true" : "false") << ","
                  << "\"has_name_export\":" << (info.hasNameExport ? "true" : "false") << ","
                  << "\"has_invoke_export\":" << (info.hasInvokeExport ? "true" : "false") << ","
                  << "\"has_invoke_json_export\":" << (info.hasInvokeJsonExport ? "true" : "false") << ","
                  << "\"has_manifest_export\":" << (info.hasManifestExport ? "true" : "false") << ","
                  << "\"version\":\"" << jsonEscape(info.version) << "\","
                  << "\"has_abi\":" << (info.hasAbiVersion ? "true" : "false") << ","
                  << "\"abi\":" << info.abiVersion << ","
                  << "\"summary\":\"" << jsonEscape(info.manifest.summary) << "\","
                  << "\"capabilities\":[";
        for (std::size_t i = 0; i < info.manifest.capabilities.size(); ++i)
        {
            if (i != 0)
            {
                std::cout << ",";
            }
            std::cout << "\"" << jsonEscape(info.manifest.capabilities[i]) << "\"";
        }
        std::cout << "],"
                  << "\"sha256\":\"" << jsonEscape(info.sha256) << "\","
                  << "\"signature_valid\":" << (info.signatureValid ? "true" : "false") << ","
                  << "\"allow_entry_found\":" << (allowEntryFound ? "true" : "false") << ","
                  << "\"allow_entry_satisfied\":" << (allowEntrySatisfied ? "true" : "false") << ","
                  << "\"allow_entry\":\"" << jsonEscape(allowEntryLine) << "\""
                  << "}\n";
        return;
    }

    std::cout << "OK module info\n"
              << "  path: " << info.path << "\n"
              << "  modules_dir: " << modulesDir << "\n"
              << "  allowlist: " << allowlistPath << "\n"
              << "  key: " << info.allowlistKey << "\n"
              << "  name: " << nameDisplay << nameSuffix << "\n"
              << "  exports: name=" << (info.hasNameExport ? "yes" : "no")
              << " invoke=" << (info.hasInvokeExport ? "yes" : "no")
              << " invoke_json=" << (info.hasInvokeJsonExport ? "yes" : "no")
              << " manifest=" << (info.hasManifestExport ? "yes" : "no") << "\n"
              << "  version: " << (info.version.empty() ? "-" : info.version) << "\n"
              << "  abi: " << (info.hasAbiVersion ? std::to_string(info.abiVersion) : std::string("-")) << "\n"
              << "  summary: " << (info.manifest.summary.empty() ? "-" : info.manifest.summary) << "\n"
              << "  capabilities: " << (caps.empty() ? "-" : caps) << "\n"
              << "  sha256: " << info.sha256 << "\n"
              << "  signature: " << (info.signatureValid ? "valid" : "not-valid") << "\n"
              << "  allow_entry: " << (allowEntryFound ? allowEntryLine : std::string("-")) << "\n"
              << "  trusted_now: " << (allowEntrySatisfied ? "yes" : "no") << "\n";
}

std::string effectiveModulesDirForModulePath(
    const std::string &path,
    const std::string &modulesDir,
    bool hasModulesDir)
{
    if (hasModulesDir)
    {
        return modulesDir;
    }
    std::string derived = ProcessGuard::ModuleManager::modulesRootForPath(path);
    return derived.empty() ? std::string(".") : derived;
}

int runModuleInfo(
    const std::string &path,
    bool hasPath,
    const std::string &modulesDir,
    bool hasModulesDir,
    bool jsonOutput)
{
    if (!hasPath)
    {
        std::cerr << "module info requires --path\n";
        return 1;
    }

    ProcessGuard::ModuleManager::ModuleInspection info;
    std::string err;
    if (!ProcessGuard::ModuleManager::inspectModulePath(path, info, err))
    {
        std::cerr << "ERR " << err << "\n";
        return 1;
    }

    const std::string effectiveModulesDir = effectiveModulesDirForModulePath(path, modulesDir, hasModulesDir);
    const std::string allowlistPath = allowlistPathForModulesDir(effectiveModulesDir);
    ProcessGuard::ModuleManager::AllowEntry allowEntry;
    std::string allowEntryLine;
    const bool allowFound = findAllowlistEntry(allowlistPath, info.allowlistKey, allowEntry, allowEntryLine);
    const bool allowSatisfied = allowFound && allowEntrySatisfiesInspection(allowEntry, info);
    printModuleInspection(info, effectiveModulesDir, allowlistPath, allowFound, allowSatisfied, allowEntryLine, jsonOutput);
    return 0;
}

int runModuleTrust(
    const std::string &path,
    bool hasPath,
    const std::string &modulesDir,
    bool hasModulesDir,
    const std::string &nameOverride,
    bool hasName,
    const std::string &hashOpt,
    bool requireSigned)
{
    if (!hasPath)
    {
        std::cerr << "module trust requires --path\n";
        return 1;
    }

    ProcessGuard::ModuleManager::ModuleInspection info;
    std::string err;
    if (!ProcessGuard::ModuleManager::inspectModulePath(path, info, err))
    {
        std::cerr << "ERR " << err << "\n";
        return 1;
    }

    const std::string key = ProcessGuard::util::toLowerAscii(info.allowlistKey);
    if (!info.name.empty() && ProcessGuard::util::toLowerAscii(info.name) != key)
    {
        std::cerr << "ERR module manifest name '" << info.name
                  << "' does not match path-derived allowlist key '" << info.allowlistKey << "'\n";
        return 1;
    }
    if (hasName && ProcessGuard::util::toLowerAscii(nameOverride) != key)
    {
        std::cerr << "ERR --name must match path-derived allowlist key '" << info.allowlistKey << "'\n";
        return 1;
    }
    if (requireSigned && !info.signatureValid)
    {
        std::cerr << "ERR --require-signed requested but Authenticode verification failed\n";
        return 1;
    }

    std::string pinHash;
    const std::string normalizedHashOpt = ProcessGuard::util::toLowerAscii(trim(hashOpt));
    if (normalizedHashOpt == "auto")
    {
        pinHash = info.sha256;
    }
    else if (normalizedHashOpt == "none")
    {
        pinHash.clear();
    }
    else
    {
        pinHash = normalizedHashOpt;
    }

    ProcessGuard::ModuleManager::AllowEntry entry;
    entry.name = info.allowlistKey;
    entry.sha256 = pinHash;
    entry.requireSigned = requireSigned;
    const std::string effectiveModulesDir = effectiveModulesDirForModulePath(path, modulesDir, hasModulesDir);

    std::string allowlistPath;
    std::string allowlistLine;
    if (!writeAllowlistEntry(effectiveModulesDir, entry, allowlistPath, allowlistLine, err))
    {
        std::cerr << "ERR " << err << "\n";
        return 1;
    }

    std::cout << "OK trusted\n"
              << "  allowlist: " << allowlistPath << "\n"
              << "  entry: " << allowlistLine << "\n";
    return 0;
}

struct DoctorCheck
{
    std::string id;
    std::string status;
    std::string message;
};

bool isProcessElevated()
{
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminGroup = nullptr;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup))
    {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin == TRUE;
}

std::filesystem::path executableDir()
{
    wchar_t buffer[MAX_PATH] = {0};
    DWORD len = GetModuleFileNameW(nullptr, buffer, MAX_PATH);
    if (len == 0 || len >= MAX_PATH)
    {
        return std::filesystem::current_path();
    }
    return std::filesystem::path(std::wstring(buffer, len)).parent_path();
}

std::string serviceStateText()
{
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm)
    {
        return "unknown: OpenSCManager failed " + std::to_string(GetLastError());
    }
    SC_HANDLE service = OpenServiceA(scm, "PGS", SERVICE_QUERY_STATUS);
    if (!service)
    {
        const DWORD err = GetLastError();
        CloseServiceHandle(scm);
        return err == ERROR_SERVICE_DOES_NOT_EXIST ? "not-installed" : ("unknown: OpenService failed " + std::to_string(err));
    }
    SERVICE_STATUS status{};
    const BOOL ok = QueryServiceStatus(service, &status);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    if (!ok)
    {
        return "unknown: QueryServiceStatus failed " + std::to_string(GetLastError());
    }
    switch (status.dwCurrentState)
    {
    case SERVICE_RUNNING: return "running";
    case SERVICE_STOPPED: return "stopped";
    case SERVICE_START_PENDING: return "starting";
    case SERVICE_STOP_PENDING: return "stopping";
    default: return "state=" + std::to_string(status.dwCurrentState);
    }
}

bool canWriteProbe(const std::filesystem::path &dir)
{
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec)
    {
        return false;
    }
    const std::filesystem::path probe = dir / L".pgs_doctor_probe";
    HANDLE h = CreateFileW(probe.wstring().c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    CloseHandle(h);
    DeleteFileW(probe.wstring().c_str());
    return true;
}

int runDoctor(const std::string &host, unsigned short port, const std::string &token, bool jsonOutput)
{
    std::vector<DoctorCheck> checks;
    auto add = [&](std::string id, std::string status, std::string message) {
        checks.push_back({std::move(id), std::move(status), std::move(message)});
    };

    std::string response;
    const std::string pingCommand = ProcessGuard::client::withAuthToken(token, "ping");
    if (sendToPGS(host, port, pingCommand, response) && response.rfind("OK", 0) == 0)
    {
        add("pgs_connect", "ok", response);
        add("token", "ok", "management token accepted");
    }
    else
    {
        add("pgs_connect", "fail", response.empty() ? "could not connect to PGS" : response);
        add("token", token.empty() ? "warn" : "fail", token.empty() ? "no token supplied" : "token rejected or service unavailable");
    }

    add("service", "info", serviceStateText());
    const bool elevated = isProcessElevated();
    add("administrator", elevated ? "ok" : "warn", elevated ? "running elevated" : "not running as administrator");

    const std::filesystem::path exeDir = executableDir();
    const std::filesystem::path modules = exeDir / L"modules";
    const wchar_t *programDataEnv = _wgetenv(L"ProgramData");
    const std::filesystem::path programDataRoot = (programDataEnv && programDataEnv[0]) ? std::filesystem::path(programDataEnv) : std::filesystem::path(L"C:\\ProgramData");
    const std::filesystem::path programData = programDataRoot / L"ProcessGuard";
    const std::filesystem::path stateDir = programData / L"state";
    add("programdata_acl", canWriteProbe(programData) ? "ok" : "warn", wideToUtf8(programData.wstring()));
    add("state_acl", canWriteProbe(stateDir) ? "ok" : "warn", wideToUtf8(stateDir.wstring()));
    add("modules_acl", canWriteProbe(modules) ? "ok" : "warn", wideToUtf8(modules.wstring()));
    add("modules_staging", canWriteProbe(exeDir / L"modules_staging") ? "ok" : "warn", wideToUtf8((exeDir / L"modules_staging").wstring()));
    add("modules_allow", std::filesystem::exists(modules / L"modules.allow") ? "ok" : "warn", wideToUtf8((modules / L"modules.allow").wstring()));
    add("modules_lock", std::filesystem::exists(modules / L"modules.lock") ? "ok" : "warn", wideToUtf8((modules / L"modules.lock").wstring()));
    add("ppl_driver", std::filesystem::exists(modules / L"ppl" / L"Sirius.sys") ? "info" : "warn", wideToUtf8((modules / L"ppl" / L"Sirius.sys").wstring()));
    add("qt_runtime", std::filesystem::exists(exeDir / L"Qt6Core.dll") || std::filesystem::exists(exeDir / L"Qt5Core.dll") ? "ok" : "info", "Qt runtime DLL check beside tool directory");
    add("openssl_runtime", std::filesystem::exists(exeDir / L"libssl-3-x64.dll") || std::filesystem::exists(exeDir / L"libssl-3.dll") ? "ok" : "info", "OpenSSL runtime DLL check beside tool directory");

    response.clear();
    if (sendToPGS(host, port, ProcessGuard::client::withAuthToken(token, "module verify"), response) && response.rfind("OK", 0) == 0)
    {
        add("module_loader", "ok", response);
    }
    else
    {
        add("module_loader", "warn", response.empty() ? "module verify unavailable" : response);
    }

    if (jsonOutput)
    {
        std::cout << "{\"checks\":[";
        for (std::size_t i = 0; i < checks.size(); ++i)
        {
            if (i != 0) std::cout << ",";
            std::cout << "{\"id\":\"" << jsonEscape(checks[i].id) << "\",\"status\":\""
                      << jsonEscape(checks[i].status) << "\",\"message\":\""
                      << jsonEscape(checks[i].message) << "\"}";
        }
        std::cout << "]}\n";
        return 0;
    }

    std::cout << "PGS doctor\n";
    for (const DoctorCheck &check : checks)
    {
        std::cout << "  [" << check.status << "] " << check.id << ": " << check.message << "\n";
    }
    return 0;
}

void showUsage(const char *exe)
{
    std::cout
        << "Usage:\n"
        << "  " << exe << " bless --pid <pid> [--max-restarts N|no] [--restart-args \"...\"] [--hash auto|none|HEX] [advanced-policy]\n"
        << "  " << exe << " bless-start --path <exe> [--start-args \"...\"] [--max-restarts N|no] [--restart-args \"...\"] [--hash auto|none|HEX] [advanced-policy]\n"
        << "  " << exe << " bless-start --command \"<exe and args>\" [--max-restarts N|no] [--restart-args \"...\"] [--hash auto|none|HEX] [advanced-policy]\n"
        << "  " << exe << " unbless --pid <pid>\n"
        << "  " << exe << " unbless-path --path <exe>\n"
        << "  " << exe << " policy --pid <pid> --max-restarts N|no [--restart-args \"...\"] [advanced-policy]\n"
        << "  " << exe << " intentional --pid <pid>\n"
        << "  " << exe << " list [--json]\n"
        << "  " << exe << " get --pid <pid> [--json]\n"
        << "  " << exe << " token-set --new-token <token> [--old-token <token>]\n"
        << "  " << exe << " ping\n"
        << "  " << exe << " version\n"
        << "  " << exe << " stats\n"
        << "  " << exe << " doctor [--json]\n"
        << "  " << exe << " module list\n"
        << "  " << exe << " module info --path <dll> [--modules-dir <dir>] [--json]\n"
        << "  " << exe << " module trust --path <dll> [--modules-dir <dir>] [--hash auto|none|HEX] [--require-signed]\n"
        << "  " << exe << " module load --path <dll>\n"
        << "  " << exe << " module unload --name <name>\n"
        << "  " << exe << " module call --name <name> --request \"op=set;pid=N;signer=X\"\n"
        << "  " << exe << " module invoke --name <name> --method <namespace.method> --params-json <json>\n"
        << "  " << exe << " module verify|reload|disable|rollback\n"
        << "  " << exe << " module op-status <operation-id>\n"
        << "  " << exe << " module artifact get <id>\n"
        << "  " << exe << " health-check set|get|clear --pid <pid> [--config-json <json>]\n"
        << "  " << exe << " restart-hook set|get|clear --pid <pid> [--config-json <json>]\n"
        << "  " << exe << " group create|add|remove|restart|pause|resume|list --name <name> [--pid <pid>] [--order N] [--deps a,b]\n"
        << "  " << exe << " ppl set --pid <pid> --signer <None|Authenticode|CodeGen|Antimalware|Lsa|Windows|WinTcb|WinSystem>\n"
        << "  " << exe << " ppl get --pid <pid>\n"
        << "  " << exe << " ppl clear --pid <pid>\n"
        << "  " << exe << " schedule|sched add --cron <m h dom mon dow> --action <wire-command>\n"
        << "  " << exe << " schedule|sched add --once <YYYY-MM-DDTHH:MM:SS> --action <wire-command>\n"
        << "  " << exe << " schedule|sched add --interval <seconds> [--count N] --action <wire-command>\n"
        << "  " << exe << " schedule|sched list\n"
        << "  " << exe << " schedule|sched remove --id <id>\n"
        << "  " << exe << " schedule|sched enable --id <id>\n"
        << "  " << exe << " schedule|sched disable --id <id>\n"
        << "  " << exe << " health summary|stats|list|events [--limit N]\n"
        << "  " << exe << " profile set --name <profile> --max-restarts N|no [--restart-args \"...\"]\n"
        << "  " << exe << " profile list|get|remove|apply --name <profile> [--pid <pid>]\n"
        << "  " << exe << " report snapshot|backup [--limit N]\n"
        << "  " << exe << " events list [--limit N]\n"
        << "\nCommon options:\n"
        << "  --host <ip>          default 127.0.0.1\n"
        << "  --port <port>        default 12345\n"
        << "  --token <value>      prepend auth envelope: token <value> <command>\n"
        << "                      --host/--port/--token may appear before or after the command\n"
        << "  --old-token <value>  old token for token-set (defaults to --token)\n"
        << "  --new-token <value>  new token for token-set\n"
        << "  --path <exe>         for bless-start, or override path in bless mode\n"
        << "  --start-args \"...\"   process launch arguments for bless-start\n"
        << "  --command \"...\"      custom full launch command for bless-start\n"
        << "  --json               print list/get output as JSON\n"
        << "  --name <value>       module name (module unload/call, ppl module)\n"
        << "  --request \"kv\"      module call request, e.g. op=set;pid=N;signer=X\n"
        << "  --method <value>    module invoke JSON-RPC method, e.g. profile.apply\n"
        << "  --params-json <json> module invoke JSON params object\n"
        << "  --config-json <json> health-check/restart-hook JSON config\n"
        << "  --order <N>          guard group startup order metadata\n"
        << "  --deps <a,b>         guard group dependency names\n"
        << "  --signer <value>     PPL signer for ppl set\n"
        << "  --modules-dir <dir>  modules root for module info/trust (default: derived from --path)\n"
        << "  --require-signed     module trust writes a signed requirement and verifies it now\n"
        << "\nAdvanced guard-policy options (bless / bless-start / policy):\n"
        << "  --restart-window <s> sliding restart-count window, 0 keeps lifetime count\n"
        << "  --restart-delay <ms> delay before relaunch\n"
        << "  --restart-backoff    exponential backoff from --restart-delay\n"
        << "  --no-restart-backoff clear backoff when used with policy\n"
        << "  --hang-timeout <ms>  GUI hang probe timeout, max 60000\n"
        << "  --kill-on-exit       close the whole process family when PGS exits\n"
        << "  --no-kill-on-exit    clear kill-on-exit when used with policy\n"
        << "  --winapp --aumid <id> mark guard as WindowsApps; AUMID is required\n"
        << "  --win32              switch an existing policy back to Win32\n"
        << "\nCompatibility:\n"
        << "  " << exe << " <pid>          equivalent to: " << exe << " bless --pid <pid>\n";
}

bool parseUnsignedShort(const std::string &text, unsigned short &outValue)
{
    if (text.empty())
    {
        return false;
    }
    for (char c : text)
    {
        if (c < '0' || c > '9')
        {
            return false;
        }
    }
    try
    {
        const unsigned long value = std::stoul(text);
        if (value > 65535ul)
        {
            return false;
        }
        outValue = static_cast<unsigned short>(value);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
} // namespace

int main()
{
    int argcW = 0;
    LPWSTR *argvW = CommandLineToArgvW(GetCommandLineW(), &argcW);
    if (!argvW || argcW <= 0)
    {
        std::cerr << "Failed to parse command line (wide args unavailable)\n";
        if (argvW)
        {
            LocalFree(argvW);
        }
        return 1;
    }

    std::vector<std::string> argsUtf8;
    argsUtf8.reserve(static_cast<std::size_t>(argcW));
    for (int i = 0; i < argcW; ++i)
    {
        argsUtf8.push_back(wideToUtf8(argvW[i]));
    }
    LocalFree(argvW);

    if (argsUtf8.size() < 2)
    {
        showUsage(argsUtf8.empty() ? "pgs_bless.exe" : argsUtf8[0].c_str());
        return 1;
    }

    std::string command;
    // For "module"/"ppl" commands the first positional token after the command
    // word is the subcommand (e.g. "module list", "ppl set"). It is consumed
    // here so the --flag parsing loop below does not reject it as unknown.
    std::string subCommand;
    int argIndex = 1;

    DWORD pid = 0;
    bool hasPid = false;
    int maxRestarts = 3;
    bool hasMaxRestarts = false;
    std::string restartArgs;
    bool hasRestartArgs = false;
    std::string pathOverride;
    bool hasPath = false;
    std::string startArgs;
    std::string startCommand;
    bool hasStartCommand = false;
    std::string hashOpt = "auto";
    bool jsonOutput = false;
    std::string host = "127.0.0.1";
    unsigned short port = 12345;
    std::string token;
    std::string oldToken;
    bool hasOldToken = false;
    std::string newToken;
    bool hasNewToken = false;
    LaunchResult launchedProcess;
    bool hasLaunchedProcess = false;
    std::string moduleName;
    bool hasName = false;
    std::string moduleRequest;
    bool hasRequest = false;
    std::string moduleMethod;
    bool hasMethod = false;
    std::string moduleParamsJson = "{}";
    bool hasParamsJson = false;
    std::vector<std::string> moduleExtraArgs;
    std::string modulesDir;
    bool hasModulesDir = false;
    bool requireSigned = false;
    std::string signerText;
    bool hasSigner = false;
    // schedule subcommand
    std::string schedCron;
    bool hasSchedCron = false;
    std::string schedOnce;
    bool hasSchedOnce = false;
    std::string schedInterval;
    bool hasSchedInterval = false;
    std::string schedAction;
    bool hasSchedAction = false;
    std::string schedCount;
    bool hasSchedCount = false;
    std::string schedId;
    bool hasSchedId = false;
    std::string eventLimit;
    bool hasEventLimit = false;
    std::string configJson;
    bool hasConfigJson = false;
    std::string groupOrder;
    bool hasGroupOrder = false;
    std::string groupDeps;
    bool hasGroupDeps = false;
    // v3 advanced guard policy (all default to legacy behaviour).
    int restartWindowSec = 0;
    bool hasRestartWindowSec = false;
    int restartDelayMs = 0;
    bool hasRestartDelayMs = false;
    bool restartBackoff = false;
    bool hasRestartBackoff = false;
    int hangTimeoutMs = 0;
    bool hasHangTimeoutMs = false;
    bool killOnExit = false;
    bool hasKillOnExit = false;
    std::string aumid;
    bool hasAumid = false;
    bool winapp = false;
    bool hasAppKind = false;

    auto consumeValue = [&](int &index, const char *name) -> std::string {
        if (index + 1 >= static_cast<int>(argsUtf8.size()))
        {
            std::cerr << "Missing value for " << name << "\n";
            return std::string();
        }
        return argsUtf8[++index];
    };

    // Common transport/auth options are accepted before the command as well as
    // after it. This keeps `pgs_bless --port 12443 ping` intuitive while
    // preserving the existing `pgs_bless ping --port 12443` form.
    while (argIndex < static_cast<int>(argsUtf8.size()))
    {
        const std::string arg = argsUtf8[argIndex];
        if (arg == "--host")
        {
            host = consumeValue(argIndex, "--host");
            if (host.empty())
                return 1;
            ++argIndex;
            continue;
        }
        if (arg == "--port")
        {
            const std::string value = consumeValue(argIndex, "--port");
            if (!parseUnsignedShort(value, port))
            {
                std::cerr << "Invalid --port value\n";
                return 1;
            }
            ++argIndex;
            continue;
        }
        if (arg == "--token")
        {
            token = consumeValue(argIndex, "--token");
            if (token.empty())
                return 1;
            ++argIndex;
            continue;
        }
        if (arg == "--modules-dir")
        {
            modulesDir = consumeValue(argIndex, "--modules-dir");
            if (modulesDir.empty())
                return 1;
            hasModulesDir = true;
            ++argIndex;
            continue;
        }
        if (arg == "--require-signed" || arg == "--signed")
        {
            requireSigned = true;
            ++argIndex;
            continue;
        }
        break;
    }

    if (argIndex >= static_cast<int>(argsUtf8.size()))
    {
        showUsage(argsUtf8[0].c_str());
        return 1;
    }

    if (parsePid(argsUtf8[argIndex], pid))
    {
        command = "bless";
        hasPid = true;
        ++argIndex;
    }
    else
    {
        command = argsUtf8[argIndex++];
        // Peel off the subcommand token for module/ppl so argIndex skips it.
        if (command == "module" || command == "ppl" || command == "schedule" ||
            command == "sched" ||
            command == "events" || command == "health" || command == "profile" ||
            command == "report" || command == "health-check" || command == "restart-hook" ||
            command == "group")
        {
            subCommand = (argIndex < static_cast<int>(argsUtf8.size())) ? argsUtf8[argIndex] : std::string();
            ++argIndex;
        }
    }

    for (int i = argIndex; i < static_cast<int>(argsUtf8.size()); ++i)
    {
        const std::string arg = argsUtf8[i];
        auto needValue = [&](const char *name) -> std::string {
            return consumeValue(i, name);
        };

        if (arg == "--pid")
        {
            const std::string value = needValue("--pid");
            if (value.empty() || !parsePid(value, pid))
            {
                std::cerr << "Invalid --pid value\n";
                return 1;
            }
            hasPid = true;
            continue;
        }
        if (arg == "--max-restarts")
        {
            const std::string value = needValue("--max-restarts");
            if (value.empty() || !parseMaxRestarts(value, maxRestarts))
            {
                std::cerr << "Invalid --max-restarts value\n";
                return 1;
            }
            hasMaxRestarts = true;
            continue;
        }
        if (arg == "--restart-args")
        {
            restartArgs = needValue("--restart-args");
            hasRestartArgs = true;
            continue;
        }
        if (arg == "--start-args")
        {
            startArgs = needValue("--start-args");
            continue;
        }
        if (arg == "--command")
        {
            startCommand = needValue("--command");
            hasStartCommand = true;
            continue;
        }
        if (arg == "--path")
        {
            pathOverride = needValue("--path");
            hasPath = true;
            continue;
        }
        if (arg == "--hash")
        {
            hashOpt = needValue("--hash");
            if (hashOpt.empty())
            {
                return 1;
            }
            continue;
        }
        if (arg == "--host")
        {
            host = needValue("--host");
            if (host.empty())
            {
                return 1;
            }
            continue;
        }
        if (arg == "--port")
        {
            const std::string value = needValue("--port");
            if (!parseUnsignedShort(value, port))
            {
                std::cerr << "Invalid --port value\n";
                return 1;
            }
            continue;
        }
        if (arg == "--token")
        {
            token = needValue("--token");
            if (token.empty())
            {
                return 1;
            }
            continue;
        }
        if (arg == "--modules-dir")
        {
            modulesDir = needValue("--modules-dir");
            if (modulesDir.empty())
            {
                return 1;
            }
            hasModulesDir = true;
            continue;
        }
        if (arg == "--require-signed" || arg == "--signed")
        {
            requireSigned = true;
            continue;
        }
        if (arg == "--json")
        {
            jsonOutput = true;
            continue;
        }
        if (arg == "--old-token")
        {
            oldToken = needValue("--old-token");
            hasOldToken = true;
            continue;
        }
        if (arg == "--new-token")
        {
            newToken = needValue("--new-token");
            hasNewToken = true;
            continue;
        }

        if (arg == "--name")
        {
            moduleName = needValue("--name");
            hasName = true;
            continue;
        }
        if (arg == "--request")
        {
            moduleRequest = needValue("--request");
            hasRequest = true;
            continue;
        }
        if (arg == "--method")
        {
            moduleMethod = needValue("--method");
            hasMethod = true;
            continue;
        }
        if (arg == "--params-json")
        {
            moduleParamsJson = needValue("--params-json");
            hasParamsJson = true;
            continue;
        }
        if (arg == "--config-json")
        {
            configJson = needValue("--config-json");
            hasConfigJson = true;
            continue;
        }
        if (arg == "--order")
        {
            groupOrder = needValue("--order");
            hasGroupOrder = true;
            continue;
        }
        if (arg == "--deps")
        {
            groupDeps = needValue("--deps");
            hasGroupDeps = true;
            continue;
        }
        if (arg == "--signer")
        {
            signerText = needValue("--signer");
            hasSigner = true;
            continue;
        }
        // schedule flags
        if (arg == "--cron")
        {
            schedCron = needValue("--cron");
            hasSchedCron = true;
            continue;
        }
        if (arg == "--once")
        {
            schedOnce = needValue("--once");
            hasSchedOnce = true;
            continue;
        }
        if (arg == "--interval")
        {
            schedInterval = needValue("--interval");
            hasSchedInterval = true;
            continue;
        }
        if (arg == "--action")
        {
            schedAction = needValue("--action");
            hasSchedAction = true;
            continue;
        }
        if (arg == "--count")
        {
            schedCount = needValue("--count");
            hasSchedCount = true;
            continue;
        }
        if (arg == "--id")
        {
            schedId = needValue("--id");
            hasSchedId = true;
            continue;
        }
        if (arg == "--limit")
        {
            eventLimit = needValue("--limit");
            hasEventLimit = true;
            continue;
        }

        // v3 advanced guard-policy flags (optional, apply to bless / bless-start).
        if (arg == "--restart-window")
        {
            const std::string v = needValue("--restart-window");
            DWORD parsed = 0;
            if (!ProcessGuard::util::parseDwordValue(v, parsed) || parsed > 2147483647ul)
            {
                std::cerr << "Invalid --restart-window\n";
                return 1;
            }
            restartWindowSec = static_cast<int>(parsed);
            hasRestartWindowSec = true;
            continue;
        }
        if (arg == "--restart-delay")
        {
            const std::string v = needValue("--restart-delay");
            DWORD parsed = 0;
            if (!ProcessGuard::util::parseDwordValue(v, parsed) || parsed > 2147483647ul)
            {
                std::cerr << "Invalid --restart-delay\n";
                return 1;
            }
            restartDelayMs = static_cast<int>(parsed);
            hasRestartDelayMs = true;
            continue;
        }
        if (arg == "--restart-backoff")
        {
            restartBackoff = true;
            hasRestartBackoff = true;
            continue;
        }
        if (arg == "--no-restart-backoff")
        {
            restartBackoff = false;
            hasRestartBackoff = true;
            continue;
        }
        if (arg == "--hang-timeout")
        {
            const std::string v = needValue("--hang-timeout");
            DWORD parsed = 0;
            if (!ProcessGuard::util::parseDwordValue(v, parsed) || parsed > 60000ul)
            {
                std::cerr << "Invalid --hang-timeout\n";
                return 1;
            }
            hangTimeoutMs = static_cast<int>(parsed);
            hasHangTimeoutMs = true;
            continue;
        }
        if (arg == "--kill-on-exit")
        {
            killOnExit = true;
            hasKillOnExit = true;
            continue;
        }
        if (arg == "--no-kill-on-exit")
        {
            killOnExit = false;
            hasKillOnExit = true;
            continue;
        }
        if (arg == "--aumid")
        {
            aumid = needValue("--aumid");
            if (aumid.empty()) { return 1; }
            hasAumid = true;
            continue;
        }
        if (arg == "--winapp")
        {
            winapp = true;
            hasAppKind = true;
            continue;
        }
        if (arg == "--win32")
        {
            winapp = false;
            hasAppKind = true;
            continue;
        }

        if (command == "module" && !arg.empty() && arg[0] != '-')
        {
            moduleExtraArgs.push_back(arg);
            continue;
        }

        std::cerr << "Unknown argument: " << arg << "\n";
        return 1;
    }

    if ((command == "bless" || command == "register" ||
         command == "bless-start" || command == "start-bless" ||
         command == "policy") &&
        hasAppKind && winapp && !hasAumid)
    {
        std::cerr << "--winapp requires --aumid <ApplicationUserModelId>\n";
        return 1;
    }
    if ((command == "bless-start" || command == "start-bless") && hasAppKind && winapp)
    {
        std::cerr << "bless-start --winapp is not implemented; start the app first, then use bless --pid --winapp --aumid <id>\n";
        return 1;
    }

    // Token resolution priority: explicit --token flag, then the PGS_AUTH_TOKEN
    // environment variable (used by the Qt/Web backends so the secret never
    // appears on the process command line), then empty (auth will fail).
    if (token.empty())
    {
        if (const char *envToken = std::getenv("PGS_AUTH_TOKEN"))
        {
            token = envToken;
        }
    }

    WSADATA wsaData{};
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }

    auto withToken = [&](const std::string &cmd) -> std::string {
        // Envelope: "token <base64(token)> <command>". Base64 lets the token
        // contain spaces/special bytes; the service decodes + SHA-256-compares.
        return ProcessGuard::client::withAuthToken(token, cmd);
    };

    if (command == "doctor")
    {
        const int rc = runDoctor(host, port, token, jsonOutput);
        WSACleanup();
        return rc;
    }

    std::string wireCommand;
    if (command == "bless" || command == "register" || command == "bless-start" || command == "start-bless")
    {
        // Two registration modes share one wire command:
        // - bless: attach to an already-running pid
        // - bless-start: create the process suspended, then register it
        //
        // Both eventually send "register", but bless-start additionally owns
        // launch rollback/resume so the user does not end up with an unguarded
        // child process running after a failed registration.
        std::string path;
        std::string derivedRestartArgs;
        bool useServerStartRegister = false;
        if (command == "bless-start" || command == "start-bless")
        {
            if (hasPath && hasStartCommand)
            {
                std::cerr << "bless-start cannot use --path and --command together\n";
                WSACleanup();
                return 1;
            }
            if (!hasPath && !hasStartCommand)
            {
                std::cerr << "bless-start requires --path or --command\n";
                WSACleanup();
                return 1;
            }

            std::string startError;
            if (hasStartCommand)
            {
                if (!startProcessFromCommand(startCommand, launchedProcess, startError))
                {
                    std::cerr << "Failed to start process from command: " << startCommand;
                    if (!startError.empty())
                    {
                        std::cerr << " | " << startError;
                    }
                    std::cerr << "\n";
                    WSACleanup();
                    return 1;
                }
            }
            else
            {
                path = pathOverride;
                derivedRestartArgs = startArgs;
                useServerStartRegister = true;
            }

            if (hasStartCommand)
            {
                hasLaunchedProcess = true;
                pid = launchedProcess.pid;
                path = launchedProcess.pathUtf8;
                derivedRestartArgs = launchedProcess.startArgsUtf8;
                hasPid = true;
                if (derivedRestartArgs.empty())
                {
                    derivedRestartArgs = startArgs;
                }
            }
        }

        if (!hasPid && !useServerStartRegister)
        {
            std::cerr << "bless requires --pid, or use bless-start --path\n";
            WSACleanup();
            return 1;
        }

        if (path.empty())
        {
            path = pathOverride;
        }
        if (path.empty() && !queryProcessPath(pid, path))
        {
            std::cerr << "Failed to query process path for pid=" << pid << "\n";
            WSACleanup();
            return 1;
        }

        std::string hashValue;
        const std::string normalizedHashOpt = trim(hashOpt);
        if (normalizedHashOpt == "auto")
        {
            if (!computeFileHash(path, hashValue))
            {
                std::cerr << "Failed to compute file hash for path: " << path
                          << ", " << win32ErrorText(GetLastError()) << "\n";
                WSACleanup();
                return 1;
            }
        }
        else if (normalizedHashOpt == "none")
        {
            hashValue.clear();
        }
        else
        {
            hashValue = normalizedHashOpt;
        }

        const int effectiveMax = hasMaxRestarts ? maxRestarts : 3;
        std::string effectiveArgs;
        if (hasRestartArgs)
        {
            effectiveArgs = restartArgs;
        }
        else if (command == "bless-start" || command == "start-bless")
        {
            effectiveArgs = derivedRestartArgs;
        }
        else
        {
            // For a plain bless of an already-running process, capture the
            // existing command line when possible. This is not a perfect clone
            // of the original runtime environment, but it is much closer than
            // restarting the executable with no arguments at all.
            queryProcessCommandLineArgs(pid, effectiveArgs);
        }

        std::ostringstream oss;
        if (useServerStartRegister)
        {
            oss << "start-register " << base64Encode(path) << "|" << base64Encode(startArgs) << "|"
                << maxRestartsLabel(effectiveMax) << "|" << base64Encode(effectiveArgs);
        }
        else
        {
            oss << "register " << pid << "|" << base64Encode(path) << "|" << maxRestartsLabel(effectiveMax) << "|" << base64Encode(effectiveArgs);
        }
        // v3 guard-policy fields (positions 5..11 after pid|path|max|args|hash).
        // The hash slot is always emitted (empty => compatible/no-hash mode) so
        // the trailing fields stay aligned with the protocol parser.
        oss << "|" << hashValue
            << "|" << restartWindowSec
            << "|" << restartDelayMs
            << "|" << (restartBackoff ? "1" : "0")
            << "|" << hangTimeoutMs
            << "|" << (killOnExit ? "1" : "0")
            << "|" << (winapp ? "winapp" : "win32")
            << "|" << base64Encode(aumid);
        wireCommand = oss.str();
    }
    else if (command == "unbless" || command == "unregister")
    {
        if (!hasPid)
        {
            std::cerr << "unbless requires --pid\n";
            WSACleanup();
            return 1;
        }
        wireCommand = "unregister " + std::to_string(pid);
    }
    else if (command == "unbless-path")
    {
        if (!hasPath)
        {
            std::cerr << "unbless-path requires --path\n";
            WSACleanup();
            return 1;
        }

        const std::wstring targetNorm = normalizePathForCompare(narrowToWideBestEffort(pathOverride));
        if (targetNorm.empty())
        {
            std::cerr << "failed to normalize target path: " << pathOverride << "\n";
            WSACleanup();
            return 1;
        }

        std::string listResponse;
        if (!sendToPGS(host, port, withToken("list"), listResponse))
        {
            std::cerr << "Failed to connect to PGS at " << host << ":" << port << "\n";
            WSACleanup();
            return 1;
        }
        if (listResponse.rfind("ERR", 0) == 0)
        {
            std::cerr << listResponse << "\n";
            WSACleanup();
            return 1;
        }

        std::vector<DWORD> matchedPids;
        for (const std::string &line : splitBy(listResponse, '\n'))
        {
            const std::string value = trim(line);
            if (value.empty() || value.rfind("OK", 0) == 0)
            {
                continue;
            }
            ParsedSummary s = parseSummaryLine(value);
            const auto itPid = s.kv.find("PID");
            const auto itPath = s.kv.find("PATH_B64");
            if (itPid == s.kv.end() || itPath == s.kv.end())
            {
                continue;
            }

            DWORD foundPid = 0;
            if (!parsePid(itPid->second, foundPid))
            {
                continue;
            }

            const std::wstring pathNorm = normalizePathForCompare(narrowToWideBestEffort(base64Decode(itPath->second)));
            if (!pathNorm.empty() && pathNorm == targetNorm)
            {
                matchedPids.push_back(foundPid);
            }
        }

        if (matchedPids.empty())
        {
            std::cerr << "ERR no guard matched path: " << pathOverride << "\n";
            WSACleanup();
            return 1;
        }

        int removed = 0;
        for (DWORD matchedPid : matchedPids)
        {
            std::string resp;
            if (sendToPGS(host, port, withToken("unregister " + std::to_string(matchedPid)), resp) && resp.rfind("OK", 0) == 0)
            {
                ++removed;
            }
        }
        std::cout << "OK unbless-path matched=" << matchedPids.size() << ", removed=" << removed << "\n";
        WSACleanup();
        return (removed == 0) ? 1 : 0;
    }
    else if (command == "policy")
    {
        if (!hasPid || !hasMaxRestarts)
        {
            std::cerr << "policy requires --pid and --max-restarts\n";
            WSACleanup();
            return 1;
        }
        std::ostringstream oss;
        oss << "set-policy " << pid << "|" << maxRestartsLabel(maxRestarts);
        const bool hasPolicyAdvanced =
            hasRestartWindowSec || hasRestartDelayMs || hasRestartBackoff ||
            hasHangTimeoutMs || hasKillOnExit || hasAppKind || hasAumid;
        if (hasRestartArgs || hasPolicyAdvanced)
        {
            oss << "|" << (hasRestartArgs ? base64Encode(restartArgs) : std::string());
        }
        if (hasPolicyAdvanced)
        {
            oss << "|"
                << (hasRestartWindowSec ? std::to_string(restartWindowSec) : std::string())
                << "|"
                << (hasRestartDelayMs ? std::to_string(restartDelayMs) : std::string())
                << "|"
                << (hasRestartBackoff ? (restartBackoff ? "1" : "0") : "")
                << "|"
                << (hasHangTimeoutMs ? std::to_string(hangTimeoutMs) : std::string())
                << "|"
                << (hasKillOnExit ? (killOnExit ? "1" : "0") : "")
                << "|"
                << (hasAppKind ? (winapp ? "winapp" : "win32") : "")
                << "|"
                << (hasAumid ? base64Encode(aumid) : std::string());
        }
        wireCommand = oss.str();
    }
    else if (command == "intentional")
    {
        if (!hasPid)
        {
            std::cerr << "intentional requires --pid\n";
            WSACleanup();
            return 1;
        }
        wireCommand = "intentional " + std::to_string(pid);
    }
    else if (command == "list")
    {
        wireCommand = "list";
    }
    else if (command == "get")
    {
        if (!hasPid)
        {
            std::cerr << "get requires --pid\n";
            WSACleanup();
            return 1;
        }
        wireCommand = "get " + std::to_string(pid);
    }
    else if (command == "ping")
    {
        wireCommand = "ping";
    }
    else if (command == "version")
    {
        wireCommand = "version";
    }
    else if (command == "stats")
    {
        wireCommand = "stats";
    }
    else if (command == "token-set" || command == "set-token")
    {
        if (!hasNewToken)
        {
            std::cerr << "token-set requires --new-token\n";
            WSACleanup();
            return 1;
        }
        if (!hasOldToken)
        {
            oldToken = token;
        }
        token = oldToken;
        wireCommand = "set-token " + base64Encode(oldToken) + "|" + base64Encode(newToken);
    }
    // module <list|load|unload|call>. Builds the wire command; the common
    // send-to-PGS block at the end transmits it. load takes a base64 path so
    // spaces in the DLL path survive the line protocol.
    else if (command == "module")
    {
        const std::string sub = subCommand;
        if (sub == "list")
        {
            wireCommand = "module list";
        }
        else if (sub == "info")
        {
            const int rc = runModuleInfo(pathOverride, hasPath, modulesDir, hasModulesDir, jsonOutput);
            WSACleanup();
            return rc;
        }
        else if (sub == "trust")
        {
            const int rc = runModuleTrust(pathOverride, hasPath, modulesDir, hasModulesDir,
                                          moduleName, hasName, hashOpt, requireSigned);
            WSACleanup();
            return rc;
        }
        else if (sub == "load")
        {
            if (!hasPath)
            {
                std::cerr << "module load requires --path\n";
                WSACleanup();
                return 1;
            }
            wireCommand = "module load " + base64Encode(pathOverride);
        }
        else if (sub == "unload")
        {
            if (!hasName)
            {
                std::cerr << "module unload requires --name\n";
                WSACleanup();
                return 1;
            }
            wireCommand = "module unload " + moduleName;
        }
        else if (sub == "call")
        {
            if (!hasName || !hasRequest)
            {
                std::cerr << "module call requires --name and --request\n";
                WSACleanup();
                return 1;
            }
            wireCommand = "module call " + moduleName + " " + moduleRequest;
        }
        else if (sub == "invoke")
        {
            if (!hasName || !hasMethod)
            {
                std::cerr << "module invoke requires --name and --method\n";
                WSACleanup();
                return 1;
            }
            const std::string params = hasParamsJson ? moduleParamsJson : std::string("{}");
            wireCommand = "module invoke " + moduleName + " " + moduleMethod + " " + base64Encode(params);
        }
        else if (sub == "verify")
        {
            wireCommand = "module verify";
        }
        else if (sub == "reload" || sub == "disable" || sub == "rollback")
        {
            if (!hasName)
            {
                std::cerr << "module " << sub << " requires --name\n";
                WSACleanup();
                return 1;
            }
            wireCommand = "module " + sub + " " + moduleName;
        }
        else if (sub == "install")
        {
            if (!hasPath)
            {
                std::cerr << "module install requires --path\n";
                WSACleanup();
                return 1;
            }
            wireCommand = "module install " + base64Encode(pathOverride);
        }
        else if (sub == "artifact")
        {
            std::string artifactId;
            if (moduleExtraArgs.size() >= 2 && moduleExtraArgs[0] == "get")
            {
                artifactId = moduleExtraArgs[1];
            }
            else if (hasName)
            {
                artifactId = moduleName;
            }
            if (artifactId.empty())
            {
                std::cerr << "module artifact get requires an id\n";
                WSACleanup();
                return 1;
            }
            wireCommand = "module artifact get " + artifactId;
        }
        else if (sub == "op-status")
        {
            std::string operationId;
            if (!moduleExtraArgs.empty())
            {
                operationId = moduleExtraArgs[0];
            }
            else if (hasName)
            {
                operationId = moduleName;
            }
            if (operationId.empty())
            {
                std::cerr << "module op-status requires an operation id\n";
                WSACleanup();
                return 1;
            }
            wireCommand = "module op-status " + operationId;
        }
        else
        {
            std::cerr << "Unknown module subcommand: " << sub << "\n";
            WSACleanup();
            return 1;
        }
        // module subcommands are dispatched above; skip the common send below
        // by falling through with wireCommand set.
    }
    // schedule <add|list|remove|enable|disable>. Routes to the "sched" module
    // via "module call sched op=...". The schedule action is a PGS wire
    // command restricted to guard-management verbs by the module allowlist.
    else if (command == "schedule" || command == "sched")
    {
        const std::string sub = subCommand;
        std::string req;
        if (sub == "add")
        {
            if (!hasSchedAction)
            {
                std::cerr << "schedule add requires --action\n";
                WSACleanup();
                return 1;
            }
            std::string type;
            std::string expr;
            if (hasSchedCron) { type = "cron"; expr = schedCron; }
            else if (hasSchedOnce) { type = "once"; expr = schedOnce; }
            else if (hasSchedInterval) { type = "interval"; expr = schedInterval; }
            else
            {
                std::cerr << "schedule add requires one of --cron/--once/--interval\n";
                WSACleanup();
                return 1;
            }
            // Build the module-call request KV. The action is a free-form
            // wire command; the module rejects any verb outside its
            // allowlist, so passing it as a single KV value is safe.
            req = "op=add;type=" + type + ";expr=" + expr + ";action=" + schedAction;
            if (hasSchedCount) req += ";count=" + schedCount;
            wireCommand = "module call sched " + req;
        }
        else if (sub == "list")
        {
            wireCommand = "module call sched op=list";
        }
        else if (sub == "remove")
        {
            if (!hasSchedId) { std::cerr << "schedule remove requires --id\n"; WSACleanup(); return 1; }
            wireCommand = "module call sched op=remove;id=" + schedId;
        }
        else if (sub == "enable" || sub == "disable")
        {
            if (!hasSchedId) { std::cerr << "schedule " << sub << " requires --id\n"; WSACleanup(); return 1; }
            wireCommand = "module call sched op=" + sub + ";id=" + schedId;
        }
        else
        {
            std::cerr << "Unknown schedule subcommand: " << sub << "\n";
            WSACleanup();
            return 1;
        }
        // schedule subcommands are dispatched above; fall through with wireCommand set.
    }
    else if (command == "health")
    {
        const std::string sub = subCommand.empty() ? "summary" : subCommand;
        if (sub == "summary" || sub == "stats" || sub == "list")
        {
            wireCommand = "module call health op=" + sub;
        }
        else if (sub == "events")
        {
            wireCommand = "module call health op=events";
            if (hasEventLimit)
            {
                DWORD parsed = 0;
                if (!ProcessGuard::util::parseDwordValue(eventLimit, parsed) || parsed == 0)
                {
                    std::cerr << "Invalid --limit value\n";
                    WSACleanup();
                    return 1;
                }
                wireCommand += ";limit=" + eventLimit;
            }
        }
        else
        {
            std::cerr << "Unknown health subcommand: " << sub << "\n";
            WSACleanup();
            return 1;
        }
    }
    else if (command == "profile")
    {
        const std::string sub = subCommand.empty() ? "list" : subCommand;
        if (sub == "list")
        {
            wireCommand = "module call profile op=list";
        }
        else if (sub == "set")
        {
            if (!hasName || !hasMaxRestarts)
            {
                std::cerr << "profile set requires --name and --max-restarts\n";
                WSACleanup();
                return 1;
            }
            wireCommand = "module call profile op=set;name=" + moduleName +
                          ";max=" + maxRestartsLabel(maxRestarts);
            if (hasRestartArgs)
            {
                wireCommand += ";restart_args_b64=" + base64Encode(restartArgs);
            }
        }
        else if (sub == "get" || sub == "remove")
        {
            if (!hasName)
            {
                std::cerr << "profile " << sub << " requires --name\n";
                WSACleanup();
                return 1;
            }
            wireCommand = "module call profile op=" + sub + ";name=" + moduleName;
        }
        else if (sub == "apply")
        {
            if (!hasName || !hasPid)
            {
                std::cerr << "profile apply requires --name and --pid\n";
                WSACleanup();
                return 1;
            }
            wireCommand = "module call profile op=apply;name=" + moduleName +
                          ";pid=" + std::to_string(pid);
        }
        else
        {
            std::cerr << "Unknown profile subcommand: " << sub << "\n";
            WSACleanup();
            return 1;
        }
    }
    else if (command == "report")
    {
        const std::string sub = subCommand.empty() ? "snapshot" : subCommand;
        if (sub != "snapshot" && sub != "backup")
        {
            std::cerr << "Unknown report subcommand: " << sub << "\n";
            WSACleanup();
            return 1;
        }
        wireCommand = "module call report op=" + sub;
        if (hasEventLimit)
        {
            DWORD parsed = 0;
            if (!ProcessGuard::util::parseDwordValue(eventLimit, parsed) || parsed == 0)
            {
                std::cerr << "Invalid --limit value\n";
                WSACleanup();
                return 1;
            }
            wireCommand += ";limit=" + eventLimit;
        }
    }
    // ppl <set|get|clear>. Convenience wrapper around the ppl module; PGS turns
    // these into "op=..." module calls internally.
    else if (command == "ppl")
    {
        const std::string sub = subCommand;
        if (sub == "set")
        {
            if (!hasPid || !hasSigner)
            {
                std::cerr << "ppl set requires --pid and --signer\n";
                WSACleanup();
                return 1;
            }
            wireCommand = "module invoke ppl ppl.set " + base64Encode("{\"pid\":" + std::to_string(pid) + ",\"signer\":\"" + jsonEscape(signerText) + "\"}");
        }
        else if (sub == "get" || sub == "clear")
        {
            if (!hasPid)
            {
                std::cerr << "ppl " << sub << " requires --pid\n";
                WSACleanup();
                return 1;
            }
            wireCommand = "module invoke ppl ppl." + sub + " " + base64Encode("{\"pid\":" + std::to_string(pid) + "}");
        }
        else
        {
            std::cerr << "Unknown ppl subcommand: " << sub << "\n";
            WSACleanup();
            return 1;
        }
    }
    else if (command == "health-check" || command == "restart-hook")
    {
        const std::string sub = subCommand;
        if (sub != "set" && sub != "get" && sub != "clear")
        {
            std::cerr << "Unknown " << command << " subcommand: " << sub << "\n";
            WSACleanup();
            return 1;
        }
        if (!hasPid)
        {
            std::cerr << command << " " << sub << " requires --pid\n";
            WSACleanup();
            return 1;
        }
        wireCommand = command + " " + sub + " " + std::to_string(pid);
        if (sub == "set")
        {
            if (!hasConfigJson)
            {
                std::cerr << command << " set requires --config-json\n";
                WSACleanup();
                return 1;
            }
            wireCommand += " " + base64Encode(configJson);
        }
    }
    else if (command == "group")
    {
        const std::string sub = subCommand.empty() ? "list" : subCommand;
        if (sub == "list")
        {
            wireCommand = "group list";
        }
        else if (sub == "create")
        {
            if (!hasName)
            {
                std::cerr << "group create requires --name\n";
                WSACleanup();
                return 1;
            }
            DWORD orderValue = 0;
            if (hasGroupOrder && !ProcessGuard::util::parseDwordValue(groupOrder, orderValue))
            {
                std::cerr << "Invalid --order value\n";
                WSACleanup();
                return 1;
            }
            wireCommand = "group create " + moduleName + " " +
                          std::to_string(hasGroupOrder ? orderValue : 0) + " " +
                          (hasGroupDeps ? base64Encode(groupDeps) : std::string("-"));
        }
        else if (sub == "add" || sub == "remove")
        {
            if (!hasName || !hasPid)
            {
                std::cerr << "group " << sub << " requires --name and --pid\n";
                WSACleanup();
                return 1;
            }
            wireCommand = "group " + sub + " " + moduleName + " " + std::to_string(pid);
        }
        else if (sub == "restart" || sub == "pause" || sub == "resume")
        {
            if (!hasName)
            {
                std::cerr << "group " << sub << " requires --name\n";
                WSACleanup();
                return 1;
            }
            wireCommand = "group " + sub + " " + moduleName;
        }
        else
        {
            std::cerr << "Unknown group subcommand: " << sub << "\n";
            WSACleanup();
            return 1;
        }
    }
    else if (command == "events")
    {
        const std::string sub = subCommand.empty() ? "list" : subCommand;
        if (sub != "list")
        {
            std::cerr << "Unknown events subcommand: " << sub << "\n";
            WSACleanup();
            return 1;
        }
        wireCommand = "events list";
        if (hasEventLimit)
        {
            DWORD parsed = 0;
            if (!ProcessGuard::util::parseDwordValue(eventLimit, parsed) || parsed == 0)
            {
                std::cerr << "Invalid --limit value\n";
                WSACleanup();
                return 1;
            }
            wireCommand += " " + eventLimit;
        }
    }
    else
    {
        showUsage(argsUtf8[0].c_str());
        WSACleanup();
        return 1;
    }

    wireCommand = withToken(wireCommand);

    std::string response;
    const bool sent = sendToPGS(host, port, wireCommand, response);
    if (!sent)
    {
        if (hasLaunchedProcess)
        {
            rollbackLaunch(launchedProcess);
        }
        WSACleanup();
        std::cerr << "Failed to connect to PGS at " << host << ":" << port << "\n";
        return 1;
    }

    if (response.rfind("ERR", 0) == 0)
    {
        if (hasLaunchedProcess)
        {
            rollbackLaunch(launchedProcess);
        }
        WSACleanup();
        std::cerr << response << "\n";
        return 1;
    }

    if (hasLaunchedProcess)
    {
        std::string resumeError;
        if (!resumeLaunch(launchedProcess, resumeError))
        {
            // Registration already succeeded at this point, so roll back the
            // guard entry before killing the still-suspended child process.
            std::string cleanupResponse;
            sendToPGS(host, port, withToken("unregister " + std::to_string(pid)), cleanupResponse);
            rollbackLaunch(launchedProcess);
            WSACleanup();
            std::cerr << resumeError << "\n";
            return 1;
        }
    }

    if (command == "list" || command == "get")
    {
        std::vector<std::string> lines = splitBy(response, '\n');
        std::vector<std::string> summaries;
        for (const std::string &line : lines)
        {
            const std::string value = trim(line);
            if (value.empty() || value.rfind("OK", 0) == 0)
            {
                continue;
            }
            summaries.push_back(value);
        }

        if (!jsonOutput && !lines.empty())
        {
            std::cout << trim(lines.front()) << "\n";
        }
        printSummaries(summaries, jsonOutput);
    }
    else
    {
        std::cout << response << "\n";
    }

    WSACleanup();
    return 0;
}
