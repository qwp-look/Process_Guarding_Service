#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winternl.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
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

bool startProcessFromPath(
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
            std::cout << "{"
                      << "\"pid\":\"" << jsonEscape(get("PID")) << "\","
                      << "\"session\":\"" << jsonEscape(get("SESSION")) << "\","
                      << "\"alive\":\"" << jsonEscape(get("ALIVE")) << "\","
                      << "\"intentional\":\"" << jsonEscape(get("INTENTIONAL")) << "\","
                      << "\"max_restarts\":\"" << jsonEscape(get("MAX_RESTARTS")) << "\","
                      << "\"restart_count\":\"" << jsonEscape(get("RESTART_COUNT")) << "\","
                      << "\"hash_verified\":\"" << jsonEscape(get("HASH_VERIFIED")) << "\","
                      << "\"hash\":\"" << jsonEscape(get("HASH")) << "\","
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
            << " hash_verified=" << get("HASH_VERIFIED")
            << " hash=" << get("HASH")
            << "\n"
            << "  path: " << base64Decode(get("PATH_B64")) << "\n"
            << "  args: " << base64Decode(get("RESTART_ARGS_B64")) << "\n";
    }
}

void showUsage(const char *exe)
{
    std::cout
        << "Usage:\n"
        << "  " << exe << " bless --pid <pid> [--max-restarts N|no] [--restart-args \"...\"] [--hash auto|none|HEX]\n"
        << "  " << exe << " bless-start --path <exe> [--start-args \"...\"] [--max-restarts N|no] [--restart-args \"...\"] [--hash auto|none|HEX]\n"
        << "  " << exe << " bless-start --command \"<exe and args>\" [--max-restarts N|no] [--restart-args \"...\"] [--hash auto|none|HEX]\n"
        << "  " << exe << " unbless --pid <pid>\n"
        << "  " << exe << " unbless-path --path <exe>\n"
        << "  " << exe << " policy --pid <pid> --max-restarts N|no [--restart-args \"...\"]\n"
        << "  " << exe << " intentional --pid <pid>\n"
        << "  " << exe << " list [--json]\n"
        << "  " << exe << " get --pid <pid> [--json]\n"
        << "  " << exe << " token-set --new-token <token> [--old-token <token>]\n"
        << "  " << exe << " ping\n"
        << "  " << exe << " module list\n"
        << "  " << exe << " module load --path <dll>\n"
        << "  " << exe << " module unload --name <name>\n"
        << "  " << exe << " module call --name <name> --request \"op=set;pid=N;signer=X\"\n"
        << "  " << exe << " ppl set --pid <pid> --signer <None|Authenticode|CodeGen|Antimalware|Lsa|Windows|WinTcb|WinSystem>\n"
        << "  " << exe << " ppl get --pid <pid>\n"
        << "  " << exe << " ppl clear --pid <pid>\n"
        << "  " << exe << " schedule add --cron <m h dom mon dow> --action <wire-command>\n"
        << "  " << exe << " schedule add --once <YYYY-MM-DDTHH:MM:SS> --action <wire-command>\n"
        << "  " << exe << " schedule add --interval <seconds> [--count N] --action <wire-command>\n"
        << "  " << exe << " schedule list\n"
        << "  " << exe << " schedule remove --id <id>\n"
        << "  " << exe << " schedule enable --id <id>\n"
        << "  " << exe << " schedule disable --id <id>\n"
        << "\nCommon options:\n"
        << "  --host <ip>          default 127.0.0.1\n"
        << "  --port <port>        default 12345\n"
        << "  --token <value>      prepend auth envelope: token <value> <command>\n"
        << "  --old-token <value>  old token for token-set (defaults to --token)\n"
        << "  --new-token <value>  new token for token-set\n"
        << "  --path <exe>         for bless-start, or override path in bless mode\n"
        << "  --start-args \"...\"   process launch arguments for bless-start\n"
        << "  --command \"...\"      custom full launch command for bless-start\n"
        << "  --json               print list/get output as JSON\n"        << "  --name <value>       module name (module unload/call, ppl module)\n"
        << "  --request \"kv\"      module call request, e.g. op=set;pid=N;signer=X\n"
        << "  --signer <value>     PPL signer for ppl set\n"
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
    // v3 advanced guard policy (all default to legacy behaviour).
    int restartWindowSec = 0;
    int restartDelayMs = 0;
    bool restartBackoff = false;
    int hangTimeoutMs = 0;
    bool killOnExit = false;
    std::string aumid;
    bool winapp = false;

    if (parsePid(argsUtf8[1], pid))
    {
        command = "bless";
        hasPid = true;
        argIndex = 2;
    }
    else
    {
        command = argsUtf8[1];
        argIndex = 2;
        // Peel off the subcommand token for module/ppl so argIndex skips it.
        if (command == "module" || command == "ppl" || command == "schedule")
        {
            subCommand = (argsUtf8.size() > 2) ? argsUtf8[2] : std::string();
            argIndex = 3;
        }
    }

    for (int i = argIndex; i < static_cast<int>(argsUtf8.size()); ++i)
    {
        const std::string arg = argsUtf8[i];
        auto needValue = [&](const char *name) -> std::string {
            if (i + 1 >= static_cast<int>(argsUtf8.size()))
            {
                std::cerr << "Missing value for " << name << "\n";
                return std::string();
            }
            return argsUtf8[++i];
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

        // v3 advanced guard-policy flags (optional, apply to bless / bless-start).
        if (arg == "--restart-window")
        {
            const std::string v = needValue("--restart-window");
            try { restartWindowSec = std::stoi(v); } catch (...) { std::cerr << "Invalid --restart-window\n"; return 1; }
            continue;
        }
        if (arg == "--restart-delay")
        {
            const std::string v = needValue("--restart-delay");
            try { restartDelayMs = std::stoi(v); } catch (...) { std::cerr << "Invalid --restart-delay\n"; return 1; }
            continue;
        }
        if (arg == "--restart-backoff")
        {
            restartBackoff = true;
            continue;
        }
        if (arg == "--hang-timeout")
        {
            const std::string v = needValue("--hang-timeout");
            try { hangTimeoutMs = std::stoi(v); } catch (...) { std::cerr << "Invalid --hang-timeout\n"; return 1; }
            continue;
        }
        if (arg == "--kill-on-exit")
        {
            killOnExit = true;
            continue;
        }
        if (arg == "--aumid")
        {
            aumid = needValue("--aumid");
            if (aumid.empty()) { return 1; }
            continue;
        }
        if (arg == "--winapp")
        {
            winapp = true;
            continue;
        }

        std::cerr << "Unknown argument: " << arg << "\n";
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
            else if (!startProcessFromPath(pathOverride, startArgs, launchedProcess, startError))
            {
                std::cerr << "Failed to start process from path: " << pathOverride;
                if (!startError.empty())
                {
                    std::cerr << " | " << startError;
                }
                std::cerr << "\n";
                WSACleanup();
                return 1;
            }

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

        if (!hasPid)
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
        oss << "register " << pid << "|" << base64Encode(path) << "|" << maxRestartsLabel(effectiveMax) << "|" << base64Encode(effectiveArgs);
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
        if (hasRestartArgs)
        {
            oss << "|" << base64Encode(restartArgs);
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
    else if (command == "schedule")
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
            wireCommand = "ppl set " + std::to_string(pid) + " " + signerText;
        }
        else if (sub == "get" || sub == "clear")
        {
            if (!hasPid)
            {
                std::cerr << "ppl " << sub << " requires --pid\n";
                WSACleanup();
                return 1;
            }
            wireCommand = "ppl " + sub + " " + std::to_string(pid);
        }
        else
        {
            std::cerr << "Unknown ppl subcommand: " << sub << "\n";
            WSACleanup();
            return 1;
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
