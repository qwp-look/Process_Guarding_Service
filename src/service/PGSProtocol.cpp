/**
 * @file PGSProtocol.cpp
 * @brief PGS management-protocol dispatch and command handlers.
 *
 * Split out of PGS.cpp so the core (PGS.cpp) keeps only lifecycle, monitor,
 * persistence and socket transport. This file owns the line-oriented command
 * dispatcher (processMessage), the per-command handlers (register / list /
 * get / policy / token / module / ppl), the auth envelope and the guard
 * summary formatter. All functions are PGS members; definitions may live in
 * any TU that includes PGS.h.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "Process_Guard/PGS.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <vector>
#include <fstream>

namespace ProcessGuard
{

using namespace util; // pull in base64/utf8/hash/path helpers from PGUtil.h

    // Alias the utf8 path-normalizer to the historical call-site name (matches
    // the alias kept in PGS.cpp so handlers can call normalizePathForCompare()).
    inline std::string normalizePathForCompare(const std::string &p) { return util::normalizePathForCompareUtf8(p); }

namespace
{
std::string jsonEscapeLocal(const std::string &value)
{
    std::ostringstream out;
    for (unsigned char ch : value)
    {
        switch (ch)
        {
        case '\\': out << "\\\\"; break;
        case '"': out << "\\\""; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (ch < 0x20)
            {
                out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(ch)
                    << std::dec << std::setfill(' ');
            }
            else
            {
                out << static_cast<char>(ch);
            }
            break;
        }
    }
    return out.str();
}

std::string jsonStringValueLocal(const std::string &text, const std::string &key)
{
    const std::string needle = "\"" + key + "\"";
    std::size_t pos = text.find(needle);
    if (pos == std::string::npos)
    {
        return std::string();
    }
    pos = text.find(':', pos + needle.size());
    if (pos == std::string::npos)
    {
        return std::string();
    }
    ++pos;
    while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos])))
    {
        ++pos;
    }
    if (pos >= text.size() || text[pos] != '"')
    {
        return std::string();
    }
    ++pos;
    std::string out;
    bool escaped = false;
    for (; pos < text.size(); ++pos)
    {
        const char ch = text[pos];
        if (escaped)
        {
            switch (ch)
            {
            case '"': out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            default: out.push_back(ch); break;
            }
            escaped = false;
            continue;
        }
        if (ch == '\\')
        {
            escaped = true;
            continue;
        }
        if (ch == '"')
        {
            break;
        }
        out.push_back(ch);
    }
    return out;
}

std::string jsonRpcError(const std::string &id, const std::string &code, const std::string &message)
{
    const std::string idJson = id.empty() ? std::string("null") : ("\"" + jsonEscapeLocal(id) + "\"");
    return "{\"jsonrpc\":\"2.0\",\"id\":" + idJson +
           ",\"error\":{\"code\":\"" + jsonEscapeLocal(code) +
           "\",\"message\":\"" + jsonEscapeLocal(message) + "\"}}";
}

std::string jsonRpcRequest(const std::string &module, const std::string &method, const std::string &paramsJsonB64)
{
    const std::string paramsJson = base64Decode(paramsJsonB64);
    const std::string trimmedParams = trim(paramsJson);
    const bool paramsLooksJson = !trimmedParams.empty() &&
        (trimmedParams[0] == '{' || trimmedParams[0] == '[');
    const std::string safeParams = paramsLooksJson ? paramsJson : std::string("{}");
    const std::int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    const std::string id = std::to_string(nowMs);
    return "{\"jsonrpc\":\"2.0\",\"id\":\"" + id +
           "\",\"module\":\"" + jsonEscapeLocal(module) +
           "\",\"method\":\"" + jsonEscapeLocal(method) +
           "\",\"params\":" + safeParams +
           ",\"context\":{\"caller\":\"tcp\",\"deadline_ms\":5000}}";
}

std::int64_t epochMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::filesystem::path stagingRootForModulesDir(const std::string &modulesDir)
{
    std::filesystem::path root = std::filesystem::path(utf8ToWide(modulesDir)).parent_path();
    if (root.empty())
    {
        root = L".";
    }
    return root / L"modules_staging";
}

std::string safeModuleName(const ProcessGuard::ModuleManager::ModuleInspection &info)
{
    std::string key = info.name.empty() ? info.allowlistKey : info.name;
    key = toLowerAscii(trim(key));
    for (char ch : key)
    {
        const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.';
        if (!ok)
        {
            return std::string();
        }
    }
    return key;
}

std::string moduleLockObject(const ProcessGuard::ModuleManager::ModuleInspection &info, const std::string &name)
{
    std::string risk = jsonStringValueLocal(info.manifest.raw, "risk");
    if (risk.empty())
    {
        risk = (name == "ppl") ? "critical" : "medium";
    }
    std::ostringstream caps;
    caps << '[';
    for (std::size_t i = 0; i < info.manifest.capabilities.size(); ++i)
    {
        if (i != 0) caps << ',';
        caps << '"' << jsonEscapeLocal(info.manifest.capabilities[i]) << '"';
    }
    caps << ']';
    return "{\"name\":\"" + jsonEscapeLocal(name) +
           "\",\"version\":\"" + jsonEscapeLocal(info.version.empty() ? "1.0.0" : info.version) +
           "\",\"sha256\":\"" + jsonEscapeLocal(toLowerAscii(info.sha256)) +
           "\",\"publisher\":\"" + jsonEscapeLocal(jsonStringValueLocal(info.manifest.raw, "publisher").empty() ? "local" : jsonStringValueLocal(info.manifest.raw, "publisher")) +
           "\",\"source\":\"local-install\",\"capabilities\":" + caps.str() +
           ",\"risk\":\"" + jsonEscapeLocal(risk) +
           "\",\"trustedAt\":\"" + std::to_string(epochMs()) +
           "\",\"signature_policy\":\"hash\",\"require_signed\":false}";
}

bool writeOrUpdateModulesLock(const std::filesystem::path &lockPath,
                              const ProcessGuard::ModuleManager::ModuleInspection &info,
                              const std::string &name, std::string &err)
{
    std::string body;
    {
        std::ifstream in(lockPath, std::ios::in | std::ios::binary);
        if (in.is_open())
        {
            std::ostringstream oss;
            oss << in.rdbuf();
            body = oss.str();
        }
    }

    std::vector<std::string> objects;
    std::size_t pos = 0;
    while (!body.empty())
    {
        const std::size_t namePos = body.find("\"name\"", pos);
        if (namePos == std::string::npos) break;
        const std::size_t objStart = body.rfind('{', namePos);
        const std::size_t objEnd = body.find('}', namePos);
        if (objStart == std::string::npos || objEnd == std::string::npos) break;
        const std::string obj = body.substr(objStart, objEnd - objStart + 1);
        const std::string existingName = toLowerAscii(trim(jsonStringValueLocal(obj, "name")));
        if (!existingName.empty() && existingName != name)
        {
            objects.push_back(obj);
        }
        pos = objEnd + 1;
    }
    objects.push_back(moduleLockObject(info, name));

    std::error_code ec;
    std::filesystem::create_directories(lockPath.parent_path(), ec);
    if (ec)
    {
        err = "failed to create modules dir for modules.lock";
        return false;
    }
    std::ofstream out(lockPath, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!out.is_open())
    {
        err = "failed to open modules.lock for write";
        return false;
    }
    out << "{\"version\":1,\"generated_at\":\"service\",\"modules\":[";
    for (std::size_t i = 0; i < objects.size(); ++i)
    {
        if (i != 0) out << ',';
        out << objects[i];
    }
    out << "]}\n";
    out.flush();
    if (!out.good())
    {
        err = "failed to write modules.lock";
        return false;
    }
    return true;
}

bool copyModulePayloadToStage(const std::filesystem::path &sourceDll, const std::filesystem::path &stageDir, std::string &err)
{
    std::error_code ec;
    std::filesystem::create_directories(stageDir, ec);
    if (ec)
    {
        err = "failed to create staging directory";
        return false;
    }
    const std::filesystem::path sourceDir = sourceDll.parent_path();
    for (const auto &entry : std::filesystem::directory_iterator(sourceDir, ec))
    {
        if (ec) break;
        if (!entry.is_regular_file())
        {
            continue;
        }
        const std::filesystem::path ext = entry.path().extension();
        if (ext != L".dll" && ext != L".json" && ext != L".manifest" && ext != L".html" && ext != L".sys" && ext != L".txt")
        {
            continue;
        }
        std::filesystem::copy_file(entry.path(), stageDir / entry.path().filename(), std::filesystem::copy_options::overwrite_existing, ec);
        if (ec)
        {
            err = "failed to copy module payload file";
            return false;
        }
    }
    return true;
}

std::filesystem::path firstDllInDir(const std::filesystem::path &dir)
{
    std::error_code ec;
    for (const auto &entry : std::filesystem::directory_iterator(dir, ec))
    {
        if (entry.is_regular_file() && entry.path().extension() == L".dll")
        {
            return entry.path();
        }
    }
    return std::filesystem::path();
}

std::filesystem::path newestRollbackDir(const std::filesystem::path &rollbackRoot, const std::string &name)
{
    std::filesystem::path newest;
    std::error_code ec;
    const std::wstring prefix = utf8ToWide(name + "-");
    for (const auto &entry : std::filesystem::directory_iterator(rollbackRoot, ec))
    {
        if (!entry.is_directory()) continue;
        const std::wstring leaf = entry.path().filename().wstring();
        if (leaf.rfind(prefix, 0) != 0) continue;
        if (newest.empty() || leaf > newest.filename().wstring())
        {
            newest = entry.path();
        }
    }
    return newest;
}

std::string sanitizeGroupNameLocal(std::string name)
{
    name = toLowerAscii(trim(name));
    if (name.empty() || name.size() > 64)
    {
        return std::string();
    }
    for (char ch : name)
    {
        const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
                        ch == '_' || ch == '-' || ch == '.';
        if (!ok)
        {
            return std::string();
        }
    }
    return name;
}

std::vector<std::string> splitCsvTrimmedLocal(const std::string &value)
{
    std::vector<std::string> out;
    std::string current;
    for (char ch : value)
    {
        if (ch == ',')
        {
            const std::string item = sanitizeGroupNameLocal(current);
            if (!item.empty())
            {
                out.push_back(item);
            }
            current.clear();
        }
        else
        {
            current.push_back(ch);
        }
    }
    const std::string item = sanitizeGroupNameLocal(current);
    if (!item.empty())
    {
        out.push_back(item);
    }
    return out;
}

std::string joinCsvLocal(const std::vector<std::string> &values)
{
    std::ostringstream oss;
    for (std::size_t i = 0; i < values.size(); ++i)
    {
        if (i != 0)
        {
            oss << ',';
        }
        oss << values[i];
    }
    return oss.str();
}

bool looksLikeJsonObjectOrArrayLocal(const std::string &text)
{
    const std::string t = trim(text);
    return !t.empty() && ((t.front() == '{' && t.back() == '}') || (t.front() == '[' && t.back() == ']'));
}

bool parseIntLocal(const std::string &text, int &out)
{
    try
    {
        const std::string t = trim(text);
        if (t.empty())
        {
            return false;
        }
        std::size_t used = 0;
        const long value = std::stol(t, &used, 10);
        if (used != t.size() || value < std::numeric_limits<int>::min() ||
            value > std::numeric_limits<int>::max())
        {
            return false;
        }
        out = static_cast<int>(value);
        return true;
    }
    catch (const std::exception &)
    {
        return false;
    }
}

constexpr std::size_t kMaxGuardConfigJsonSize = 8 * 1024;


struct SuspendedLaunch
{
    DWORD pid = 0;
    std::string pathUtf8;
    HANDLE process = nullptr;
    HANDLE thread = nullptr;
};

void closeLaunch(SuspendedLaunch &launch)
{
    if (launch.thread)
    {
        CloseHandle(launch.thread);
        launch.thread = nullptr;
    }
    if (launch.process)
    {
        CloseHandle(launch.process);
        launch.process = nullptr;
    }
}

bool startSuspendedFromPath(const std::string &pathUtf8, const std::string &argsUtf8,
                            SuspendedLaunch &out, std::string &err)
{
    out = SuspendedLaunch{};
    const std::wstring rawPath = utf8ToWide(pathUtf8);
    if (rawPath.empty())
    {
        err = "path is empty";
        return false;
    }
    std::vector<wchar_t> fullPathBuf(32768, L'\0');
    const DWORD fullLen = GetFullPathNameW(rawPath.c_str(), static_cast<DWORD>(fullPathBuf.size()), fullPathBuf.data(), nullptr);
    if (fullLen == 0 || fullLen >= fullPathBuf.size())
    {
        err = "GetFullPathNameW failed: " + win32ErrorText(GetLastError());
        return false;
    }
    const std::wstring fullPath(fullPathBuf.data(), fullLen);
    const DWORD attr = GetFileAttributesW(fullPath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        err = "target executable is not a file: " + wideToUtf8(fullPath);
        return false;
    }
    std::wstring command = quoteArgW(fullPath);
    const std::wstring argsW = utf8ToWide(argsUtf8);
    if (!argsW.empty())
    {
        command.push_back(L' ');
        command += argsW;
    }
    std::vector<wchar_t> writable(command.begin(), command.end());
    writable.push_back(L'\0');
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    const std::wstring workDir = std::filesystem::path(fullPath).parent_path().wstring();
    if (!CreateProcessW(nullptr, writable.data(), nullptr, nullptr, FALSE,
                        CREATE_NEW_CONSOLE | CREATE_SUSPENDED, nullptr,
                        workDir.empty() ? nullptr : workDir.c_str(), &si, &pi))
    {
        err = "CreateProcessW failed: " + win32ErrorText(GetLastError());
        return false;
    }
    out.pid = pi.dwProcessId;
    out.pathUtf8 = wideToUtf8(fullPath);
    out.process = pi.hProcess;
    out.thread = pi.hThread;
    return true;
}
} // namespace

std::string PGS::processMessage(const std::string &message)
{
    // Protocol framing is line-oriented text:
    // - optional auth envelope: "token <token> <command>"
    // - command body:          "<verb> <args>"
    //
    // The dispatcher is intentionally explicit instead of clever so each
    // management command has a narrow validation path and returns predictable
    // error messages for CLI / GUI callers.
    std::string normalized;
    if (!stripAuthEnvelope(message, normalized))
    {
        return m_requireAuth ? "ERR auth failed or token missing" : "ERR empty command";
    }

    return dispatchCommandLine(normalized);
}

std::string PGS::dispatchCommandLine(const std::string &commandLine)
{
    const std::string normalized = trim(commandLine);
    if (normalized.empty())
    {
        return "ERR empty command";
    }

    const auto spacePos = normalized.find(' ');
    std::string command = (spacePos == std::string::npos) ? normalized : normalized.substr(0, spacePos);
    const std::string args = (spacePos == std::string::npos) ? std::string() : trim(normalized.substr(spacePos + 1));

    // v3 user-facing verb aliases map to the canonical wire verbs so the CLI
    // ("bless"/"unbless") and the on-wire protocol stop diverging.
    if (command == "bless")
    {
        command = "register";
    }
    else if (command == "unbless")
    {
        command = "unregister";
    }
    else if (command == "policy")
    {
        command = "set-policy";
    }

    if (command == "start-register")
    {
        const std::vector<std::string> fields = splitByChar(args, '|');
        if (fields.size() < 3)
        {
            return "ERR invalid start-register payload";
        }
        const std::string path = base64Decode(fields[0]);
        const std::string startArgs = base64Decode(fields[1]);
        int maxRestarts = kDefaultMaxRestarts;
        if (!parseMaxRestarts(trim(fields[2]), maxRestarts))
        {
            return "ERR invalid max-restarts";
        }
        const std::string restartArgs = (fields.size() >= 4) ? base64Decode(fields[3]) : startArgs;
        const std::string declaredHash = (fields.size() >= 5) ? trim(fields[4]) : std::string();
        int restartWindowSec = 0;
        if (fields.size() >= 6)
        {
            DWORD v = 0;
            if (!util::parseDwordValue(trim(fields[5]), v) || v > static_cast<DWORD>(std::numeric_limits<int>::max()))
                return "ERR invalid restart-window";
            restartWindowSec = static_cast<int>(v);
        }
        int restartDelayMs = 0;
        if (fields.size() >= 7)
        {
            DWORD v = 0;
            if (!util::parseDwordValue(trim(fields[6]), v) || v > static_cast<DWORD>(std::numeric_limits<int>::max()))
                return "ERR invalid restart-delay";
            restartDelayMs = static_cast<int>(v);
        }
        bool backoff = false;
        if (fields.size() >= 8 && !util::parseBoolFlag(fields[7], backoff))
            return "ERR invalid restart-backoff";
        int hangTimeoutMs = 0;
        if (fields.size() >= 9)
        {
            DWORD v = 0;
            if (!util::parseDwordValue(trim(fields[8]), v) || v > static_cast<DWORD>(kMaxHangTimeoutMs))
                return "ERR invalid hang-timeout";
            hangTimeoutMs = static_cast<int>(v);
        }
        bool killOnExit = false;
        if (fields.size() >= 10 && !util::parseBoolFlag(fields[9], killOnExit))
            return "ERR invalid kill-on-exit";
        SuspendedLaunch launch;
        std::string startError;
        if (!startSuspendedFromPath(path, startArgs, launch, startError))
        {
            return "ERR " + startError;
        }
        const std::string registerResponse = handleRegister(launch.pid, base64Encode(launch.pathUtf8), maxRestarts,
                                                          restartArgs, declaredHash, AppKind::Win32, std::string(),
                                                          restartWindowSec, restartDelayMs, backoff, hangTimeoutMs,
                                                          killOnExit);
        if (registerResponse.rfind("OK", 0) != 0)
        {
            TerminateProcess(launch.process, 1);
            WaitForSingleObject(launch.process, 3000);
            closeLaunch(launch);
            return registerResponse;
        }
        if (ResumeThread(launch.thread) == static_cast<DWORD>(-1))
        {
            const DWORD err = GetLastError();
            handleUnregister(launch.pid);
            TerminateProcess(launch.process, 1);
            closeLaunch(launch);
            return "ERR ResumeThread failed: " + win32ErrorText(err);
        }
        const DWORD pid = launch.pid;
        closeLaunch(launch);
        return "OK started-registered pid=" + std::to_string(pid);
    }

    if (command == "register")
    {
        const std::vector<std::string> fields = splitByChar(args, '|');
        if (fields.size() < 2)
        {
            return "ERR invalid register payload";
        }

        DWORD pid = 0;
        if (!parsePid(trim(fields[0]), pid))
        {
            return "ERR invalid pid in register";
        }

        int maxRestarts = kDefaultMaxRestarts;
        if (fields.size() >= 3 && !parseMaxRestarts(trim(fields[2]), maxRestarts))
        {
            return "ERR invalid max-restarts";
        }

        // restartArgs is base64-encoded on the wire so '|', newlines and
        // leading/trailing spaces survive intact (path is also base64). The
        // declared hash is a hex string with no '|'.
        const std::string restartArgs = (fields.size() >= 4) ? base64Decode(fields[3]) : std::string();
        const std::string declaredHash = (fields.size() >= 5) ? trim(fields[4]) : std::string();

        // v3 optional advanced guard policy. Field positions 5..10:
        //   restart-window|restart-delay|backoff|hang-timeout|kill-on-exit|appKind
        // Field 11 is a base64 AUMID (only meaningful when appKind=winapp).
        // All default to legacy behaviour (Win32, lifetime restart count).
        int restartWindowSec = 0;
        {
            if (fields.size() >= 6)
            {
                DWORD v = 0;
                const std::string text = trim(fields[5]);
                if (text.empty() || !util::parseDwordValue(text, v) ||
                    v > static_cast<DWORD>(std::numeric_limits<int>::max()))
                {
                    return "ERR invalid restart-window";
                }
                restartWindowSec = static_cast<int>(v);
            }
        }
        int restartDelayMs = 0;
        {
            if (fields.size() >= 7)
            {
                DWORD v = 0;
                const std::string text = trim(fields[6]);
                if (text.empty() || !util::parseDwordValue(text, v) ||
                    v > static_cast<DWORD>(std::numeric_limits<int>::max()))
                {
                    return "ERR invalid restart-delay";
                }
                restartDelayMs = static_cast<int>(v);
            }
        }
        bool backoff = false;
        if (fields.size() >= 8)
        {
            if (!util::parseBoolFlag(fields[7], backoff))
            {
                return "ERR invalid restart-backoff";
            }
        }
        int hangTimeoutMs = 0;
        {
            if (fields.size() >= 9)
            {
                DWORD v = 0;
                const std::string hv = trim(fields[8]);
                if (hv.empty() || !util::parseDwordValue(hv, v) || v > static_cast<DWORD>(kMaxHangTimeoutMs))
                {
                    return "ERR invalid hang-timeout";
                }
                hangTimeoutMs = static_cast<int>(v);
            }
        }
        bool killOnExit = false;
        if (fields.size() >= 10)
        {
            if (!util::parseBoolFlag(fields[9], killOnExit))
            {
                return "ERR invalid kill-on-exit";
            }
        }
        AppKind appKind = AppKind::Win32;
        if (fields.size() >= 11)
        {
            const std::string low = toLowerAscii(trim(fields[10]));
            if (low == "1" || low == "winapp" || low == "uwp" || low == "store")
            {
                appKind = AppKind::WinApp;
            }
            else if (low == "0" || low == "win32" || low.empty())
            {
                appKind = AppKind::Win32;
            }
            else
            {
                return "ERR invalid app-kind";
            }
        }
        std::string aumid;
        if (fields.size() >= 12)
        {
            aumid = base64Decode(fields[11]);
        }
        if (appKind == AppKind::WinApp && aumid.empty())
        {
            return "ERR missing AUMID for winapp";
        }

        return handleRegister(pid, trim(fields[1]), maxRestarts, restartArgs, declaredHash,
                              appKind, aumid, restartWindowSec, restartDelayMs, backoff,
                              hangTimeoutMs, killOnExit);
    }

    if (command == "intentional")
    {
        DWORD pid = 0;
        if (!parsePid(args, pid))
        {
            return "ERR invalid pid for intentional";
        }
        return handleIntentionalExit(pid);
    }

    if (command == "unregister")
    {
        DWORD pid = 0;
        if (!parsePid(args, pid))
        {
            return "ERR invalid pid for unregister";
        }
        return handleUnregister(pid);
    }

    if (command == "set-policy")
    {
        const std::vector<std::string> fields = splitByChar(args, '|');
        if (fields.size() < 2)
        {
            return "ERR invalid set-policy payload";
        }
        DWORD pid = 0;
        if (!parsePid(trim(fields[0]), pid))
        {
            return "ERR invalid pid in set-policy";
        }
        int maxRestarts = -1;
        if (!parseMaxRestarts(trim(fields[1]), maxRestarts))
        {
            return "ERR invalid max-restarts in set-policy";
        }
        const std::string restartArgs = (fields.size() >= 3) ? base64Decode(fields[2]) : std::string();

        GuardPolicyPatch patch;
        if (fields.size() >= 4)
        {
            const std::string text = trim(fields[3]);
            if (!text.empty())
            {
                DWORD v = 0;
                if (!util::parseDwordValue(text, v) ||
                    v > static_cast<DWORD>(std::numeric_limits<int>::max()))
                {
                    return "ERR invalid restart-window in set-policy";
                }
                patch.hasRestartWindowSec = true;
                patch.restartWindowSec = static_cast<int>(v);
            }
        }
        if (fields.size() >= 5)
        {
            const std::string text = trim(fields[4]);
            if (!text.empty())
            {
                DWORD v = 0;
                if (!util::parseDwordValue(text, v) ||
                    v > static_cast<DWORD>(std::numeric_limits<int>::max()))
                {
                    return "ERR invalid restart-delay in set-policy";
                }
                patch.hasRestartDelayMs = true;
                patch.restartDelayMs = static_cast<int>(v);
            }
        }
        if (fields.size() >= 6)
        {
            const std::string text = trim(fields[5]);
            if (!text.empty())
            {
                bool v = false;
                if (!util::parseBoolFlag(text, v))
                {
                    return "ERR invalid restart-backoff in set-policy";
                }
                patch.hasBackoff = true;
                patch.backoff = v;
            }
        }
        if (fields.size() >= 7)
        {
            const std::string text = trim(fields[6]);
            if (!text.empty())
            {
                DWORD v = 0;
                if (!util::parseDwordValue(text, v) || v > static_cast<DWORD>(kMaxHangTimeoutMs))
                {
                    return "ERR invalid hang-timeout in set-policy";
                }
                patch.hasHangTimeoutMs = true;
                patch.hangTimeoutMs = static_cast<int>(v);
            }
        }
        if (fields.size() >= 8)
        {
            const std::string text = trim(fields[7]);
            if (!text.empty())
            {
                bool v = false;
                if (!util::parseBoolFlag(text, v))
                {
                    return "ERR invalid kill-on-exit in set-policy";
                }
                patch.hasKillOnExit = true;
                patch.killOnExit = v;
            }
        }
        if (fields.size() >= 9)
        {
            const std::string low = toLowerAscii(trim(fields[8]));
            if (!low.empty())
            {
                if (low == "1" || low == "winapp" || low == "uwp" || low == "store")
                {
                    patch.hasAppKind = true;
                    patch.appKind = AppKind::WinApp;
                }
                else if (low == "0" || low == "win32")
                {
                    patch.hasAppKind = true;
                    patch.appKind = AppKind::Win32;
                }
                else
                {
                    return "ERR invalid app-kind in set-policy";
                }
            }
        }
        if (fields.size() >= 10)
        {
            patch.hasAumid = true;
            patch.aumid = base64Decode(fields[9]);
        }
        return handleSetPolicy(pid, maxRestarts, restartArgs, patch);
    }

    if (command == "set-token")
    {
        const std::vector<std::string> fields = splitByChar(args, '|');
        if (fields.size() < 2)
        {
            return "ERR invalid set-token payload";
        }
        return handleSetToken(trim(fields[0]), trim(fields[1]));
    }

    if (command == "list")
    {
        return handleList();
    }

    if (command == "get")
    {
        DWORD pid = 0;
        if (!parsePid(args, pid))
        {
            return "ERR invalid pid for get";
        }
        return handleGet(pid);
    }

    if (command == "module")
    {
        return handleModuleCommand(args);
    }

    if (command == "ppl")
    {
        return handlePplCommand(args);
    }

    if (command == "health-check")
    {
        return handleHealthCheckCommand(args);
    }

    if (command == "group")
    {
        return handleGroupCommand(args);
    }

    if (command == "restart-hook")
    {
        return handleRestartHookCommand(args);
    }

    if (command == "events")
    {
        return handleEventsCommand(args);
    }

    if (command == "ping")
    {
        return "OK pong protocol=3";
    }

    if (command == "version")
    {
        // Protocol version. v3 adds advanced policy fields and WindowsApps;
        // min=2 means v2 clients (no advanced fields) still register fine.
        return "OK protocol=3 min=2";
    }

    if (command == "stats")
    {
        std::lock_guard<std::mutex> lock(m_guardsMutex);
        std::size_t totalRestarts = 0;
        std::size_t windowedRestarts = 0;
        const std::int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        for (const auto &entry : m_guards)
        {
            const auto pit = m_policyByGuardId.find(entry.second.guardId);
            if (pit == m_policyByGuardId.end())
            {
                continue;
            }
            totalRestarts += static_cast<std::size_t>(pit->second.restartCount);
            const int win = entry.second.restartWindowSec;
            if (win > 0 && !pit->second.recentRestartMs.empty())
            {
                windowedRestarts += static_cast<std::size_t>(
                    util::pruneRestartWindow(pit->second.recentRestartMs, nowMs, win).size());
            }
        }
        std::size_t active = 0;
        std::size_t paused = 0;
        std::size_t crashLoops = 0;
        for (const auto &entry : m_guards)
        {
            if (entry.second.handle && WaitForSingleObject(entry.second.handle, 0) == WAIT_TIMEOUT)
            {
                ++active;
            }
            const auto git = entry.second.groupName.empty() ? m_guardGroups.end() : m_guardGroups.find(entry.second.groupName);
            if (entry.second.paused || (git != m_guardGroups.end() && git->second.paused))
            {
                ++paused;
            }
            if (entry.second.crashLoop)
            {
                ++crashLoops;
            }
        }
        const auto uptimeSec = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - m_startTime).count();
        return "OK guards=" + std::to_string(m_guards.size()) +
               " active=" + std::to_string(active) +
               " paused=" + std::to_string(paused) +
               " crashLoops=" + std::to_string(crashLoops) +
               " totalRestarts=" + std::to_string(totalRestarts) +
               " restartsInWindow=" + std::to_string(windowedRestarts) +
               " uptime=" + std::to_string(uptimeSec) +
               " protocol=3";
    }

    return "ERR unknown command";
}

std::string PGS::handleRegister(
    DWORD pid,
    const std::string &encodedPath,
    int maxRestarts,
    const std::string &restartArgs,
    const std::string &declaredHash,
    AppKind appKind,
    const std::string &aumid,
    int restartWindowSec,
    int restartDelayMs,
    bool backoff,
    int hangTimeoutMs,
    bool killOnExit)
{
    // Registration is the trust boundary between clients and the service. The
    // service re-derives everything important that it can:
    // - decode the requested path
    // - query the real image path from pid
    // - verify the two paths match
    // - optionally compute and validate the file hash
    // - open its own synchronization handle
    //
    // That way the guard record stored in memory reflects the actual process
    // being watched, not merely what the client claimed.
    const std::string requestedPath = base64Decode(encodedPath);
    if (requestedPath.empty())
    {
        Logger::warning("PGS: empty decoded path for pid=" + std::to_string(pid));
        return "ERR empty decoded path";
    }

    // Never trust the client supplied path as the source of truth.
    //
    // The CLI may provide a path for convenience, but the service must verify
    // that the pid actually points at the same image. Otherwise a caller could
    // ask PGS to monitor pid=A while later restarting executable=B.
    std::string actualPath;
    if (!queryProcessPath(pid, actualPath))
    {
        Logger::warning("PGS: failed to query image path for pid=" + std::to_string(pid));
        return "ERR failed to query process image path";
    }

    const std::string requestedNormalized = normalizePathForCompare(requestedPath);
    const std::string actualNormalized = normalizePathForCompare(actualPath);
    if (requestedNormalized.empty() || actualNormalized.empty() || requestedNormalized != actualNormalized)
    {
        Logger::warning("PGS: register rejected, path mismatch for pid=" + std::to_string(pid) +
                        ", requested=" + requestedPath + ", actual=" + actualPath);
        return "ERR pid/path mismatch";
    }

    std::string actualHash;
    const bool hasActualHash = computeFileHash(actualPath, actualHash);
    bool hashVerified = false;
    if (!declaredHash.empty())
    {
        if (!hasActualHash)
        {
            return "ERR failed to compute file hash";
        }
        hashVerified = (toLowerAscii(actualHash) == toLowerAscii(declaredHash));
        if (!hashVerified)
        {
            Logger::warning("PGS: register rejected, hash mismatch for path=" + actualPath);
            return "ERR hash mismatch";
        }
    }

    constexpr DWORD kGuardProcessAccess =
        SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_QUOTA | PROCESS_TERMINATE;
    HANDLE processHandle = OpenProcess(kGuardProcessAccess, FALSE, pid);
    if (!processHandle)
    {
        processHandle = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    }
    if (!processHandle)
    {
        Logger::warning("PGS: OpenProcess failed for pid=" + std::to_string(pid) + ", error=" + std::to_string(GetLastError()));
        return "ERR OpenProcess failed";
    }

    DWORD sessionId = 0xFFFFFFFF;
    ProcessIdToSessionId(pid, &sessionId);

    const std::string storedHash = declaredHash;
    {
        std::lock_guard<std::mutex> lock(m_guardsMutex);
        auto existing = m_guards.find(pid);

        // Preserve guard identity across re-registers of the same live pid.
        // This matters when policy is updated or when a client re-submits the
        // same guard with refreshed metadata.
        const std::uint64_t guardId = (existing != m_guards.end()) ? existing->second.guardId : m_nextGuardId++;
        const std::int64_t nowMs = currentEpochMs();
        GuardInfo updated{};
        updated.pid = pid;
        updated.sessionId = sessionId;
        updated.path = actualPath;
        updated.maxRestarts = maxRestarts;
        updated.restartArgs = restartArgs;
        updated.fileHash = storedHash;
        updated.handle = processHandle;
        updated.intentional = false;
        updated.hashVerified = hashVerified;
        updated.guardId = guardId;
        updated.appKind = appKind;
        updated.aumid = aumid;
        updated.restartWindowSec = restartWindowSec;
        updated.restartDelayMs = restartDelayMs;
        updated.backoff = backoff;
        updated.hangTimeoutMs = hangTimeoutMs;
        updated.killOnExit = killOnExit;
        updated.jobHandle = nullptr;
        if (existing != m_guards.end())
        {
            updated.healthCheckJson = existing->second.healthCheckJson;
            updated.groupName = existing->second.groupName;
            updated.paused = existing->second.paused;
            updated.createdAtMs = existing->second.createdAtMs > 0 ? existing->second.createdAtMs : nowMs;
            updated.lastStartMs = existing->second.lastStartMs > 0 ? existing->second.lastStartMs : nowMs;
            updated.lastExitMs = existing->second.lastExitMs;
            updated.lastExitCode = existing->second.lastExitCode;
            updated.cumulativeRunMs = existing->second.cumulativeRunMs;
            updated.restartIntervalSumMs = existing->second.restartIntervalSumMs;
            updated.restartIntervalCount = existing->second.restartIntervalCount;
            updated.crashLoop = existing->second.crashLoop;
            updated.restartHookJson = existing->second.restartHookJson;
        }
        else
        {
            updated.createdAtMs = nowMs;
            updated.lastStartMs = nowMs;
        }

        if (existing != m_guards.end())
        {
            if (existing->second.handle)
            {
                CloseHandle(existing->second.handle);
            }
            existing->second = updated;
        }
        else
        {
            m_guards.emplace(pid, std::move(updated));
        }

        // v3: assign the live process to a per-guard Job Object so the monitor
        // can observe the whole process family and TerminateJobObject the
        // family on restart. Harmless if it fails (poll-based exit detection
        // still works); assignGuardToJob logs the reason.
        assignGuardToJob(m_guards[pid]);

        auto policyIt = m_policyByGuardId.find(guardId);
        if (policyIt == m_policyByGuardId.end())
        {
            m_policyByGuardId.emplace(guardId, RestartPolicyState{maxRestarts, 0, {}});
        }
        else
        {
            policyIt->second.maxRestarts = maxRestarts;
        }

        auto &persisted = m_persistedGuards[guardId];
        copyGuardToPersisted(m_guards[pid], persisted);
    }

    persistState();

    Logger::warning("PGS: registered guard pid=" + std::to_string(pid) +
                    ", path=" + actualPath +
                    ", max-restarts=" + maxRestartsLabel(maxRestarts) +
                    ", hash=" + (storedHash.empty() ? std::string("<none>") : storedHash));
    recordEvent("guard.register",
                "pid=" + std::to_string(pid) +
                ";path=" + actualPath +
                ";max=" + maxRestartsLabel(maxRestarts) +
                ";app=" + (appKind == AppKind::WinApp ? std::string("winapp") : std::string("win32")));

    return "OK registered pid=" + std::to_string(pid);
}

std::string PGS::handleIntentionalExit(DWORD pid)
{
    {
        std::lock_guard<std::mutex> lock(m_guardsMutex);
        const auto it = m_guards.find(pid);
        if (it == m_guards.end())
        {
            Logger::warning("PGS: intentional exit for unknown pid=" + std::to_string(pid));
            return "ERR pid not found";
        }

        it->second.intentional = true;
        auto persisted = m_persistedGuards.find(it->second.guardId);
        if (persisted != m_persistedGuards.end())
        {
            persisted->second.intentional = true;
        }
    }

    persistState();
    Logger::warning("PGS: marked intentional exit for pid=" + std::to_string(pid));
    recordEvent("guard.intentional", "pid=" + std::to_string(pid));
    return "OK intentional marked pid=" + std::to_string(pid);
}

std::string PGS::handleUnregister(DWORD pid)
{
    {
        std::lock_guard<std::mutex> lock(m_guardsMutex);
        auto it = m_guards.find(pid);
        if (it == m_guards.end())
        {
            return "ERR pid not found";
        }

        const std::uint64_t guardId = it->second.guardId;
        if (it->second.handle)
        {
            CloseHandle(it->second.handle);
        }
        m_guards.erase(it);
        m_policyByGuardId.erase(guardId);
        m_persistedGuards.erase(guardId);
        // v3: stop observing this guard's Job Object. The guarded process is
        // left running - "unregister" means stop protecting, not kill. If this
        // guard was registered with killOnExit, clear KILL_ON_JOB_CLOSE before
        // closing PGS's job handle so unregister does not terminate the job.
        closeGuardJob(guardId, true);
    }

    persistState();
    Logger::warning("PGS: unregistered pid=" + std::to_string(pid));
    recordEvent("guard.unregister", "pid=" + std::to_string(pid));
    return "OK unregistered pid=" + std::to_string(pid);
}

std::string PGS::handleSetPolicy(DWORD pid, int maxRestarts, const std::string &restartArgs,
                                 const GuardPolicyPatch &patch)
{
    std::uint64_t jobIdForKillOnExitUpdate = 0;
    bool updateKillOnExitJob = false;
    bool killOnExitValue = false;
    {
        std::lock_guard<std::mutex> lock(m_guardsMutex);
        auto it = m_guards.find(pid);
        if (it == m_guards.end())
        {
            return "ERR pid not found";
        }

        const AppKind finalAppKind = patch.hasAppKind ? patch.appKind : it->second.appKind;
        std::string finalAumid = patch.hasAumid ? patch.aumid : it->second.aumid;
        if (patch.hasAppKind && finalAppKind == AppKind::Win32 && !patch.hasAumid)
        {
            finalAumid.clear();
        }
        if (finalAppKind == AppKind::WinApp && finalAumid.empty())
        {
            return "ERR missing AUMID for winapp";
        }

        it->second.maxRestarts = maxRestarts;
        it->second.restartArgs = restartArgs;
        if (patch.hasRestartWindowSec)
            it->second.restartWindowSec = patch.restartWindowSec;
        if (patch.hasRestartDelayMs)
            it->second.restartDelayMs = patch.restartDelayMs;
        if (patch.hasBackoff)
            it->second.backoff = patch.backoff;
        if (patch.hasHangTimeoutMs)
            it->second.hangTimeoutMs = patch.hangTimeoutMs;
        if (patch.hasKillOnExit)
        {
            it->second.killOnExit = patch.killOnExit;
            jobIdForKillOnExitUpdate = it->second.guardId;
            killOnExitValue = patch.killOnExit;
            updateKillOnExitJob = true;
        }
        if (patch.hasAppKind)
            it->second.appKind = patch.appKind;
        if (patch.hasAumid || (patch.hasAppKind && patch.appKind == AppKind::Win32))
            it->second.aumid = finalAumid;

        auto &policy = m_policyByGuardId[it->second.guardId];
        policy.maxRestarts = maxRestarts;
        auto persisted = m_persistedGuards.find(it->second.guardId);
        if (persisted != m_persistedGuards.end())
        {
            persisted->second.maxRestarts = maxRestarts;
            persisted->second.restartArgs = restartArgs;
            if (patch.hasRestartWindowSec)
                persisted->second.restartWindowSec = patch.restartWindowSec;
            if (patch.hasRestartDelayMs)
                persisted->second.restartDelayMs = patch.restartDelayMs;
            if (patch.hasBackoff)
                persisted->second.backoff = patch.backoff;
            if (patch.hasHangTimeoutMs)
                persisted->second.hangTimeoutMs = patch.hangTimeoutMs;
            if (patch.hasKillOnExit)
                persisted->second.killOnExit = patch.killOnExit;
            if (patch.hasAppKind)
                persisted->second.appKind = patch.appKind;
            if (patch.hasAumid || (patch.hasAppKind && patch.appKind == AppKind::Win32))
                persisted->second.aumid = finalAumid;
        }
    }

    if (updateKillOnExitJob)
    {
        setGuardJobKillOnExit(jobIdForKillOnExitUpdate, killOnExitValue);
    }
    persistState();
    Logger::warning("PGS: updated policy pid=" + std::to_string(pid) +
                    ", max=" + maxRestartsLabel(maxRestarts));
    recordEvent("guard.policy",
                "pid=" + std::to_string(pid) +
                ";max=" + maxRestartsLabel(maxRestarts) +
                ";restart_args_b64=" + base64Encode(restartArgs));
    return "OK policy updated pid=" + std::to_string(pid);
}

std::string PGS::handleSetToken(const std::string &encodedOldToken, const std::string &encodedNewToken)
{
    const std::string oldToken = base64Decode(encodedOldToken);
    const std::string newToken = base64Decode(encodedNewToken);
    if (oldToken.empty() || newToken.empty())
    {
        return "ERR token must not be empty";
    }
    const std::string oldHash = sha256Hex(oldToken);
    const std::string newHash = sha256Hex(newToken);

    {
        std::lock_guard<std::mutex> lock(m_authMutex);
        if (!constantTimeEquals(oldHash, m_authTokenHash))
        {
            return "ERR old token mismatch";
        }

        m_authTokenHash = toLowerAscii(newHash);
    }

    persistState();
    Logger::warning("PGS: auth token updated in-memory and persisted");
    recordEvent("auth.token-set", "result=updated");
    return "OK token updated";
}

std::string PGS::handleList()
{
    std::lock_guard<std::mutex> lock(m_guardsMutex);
    std::ostringstream oss;
    oss << "OK count=" << m_guards.size();
    for (const auto &entry : m_guards)
    {
        const auto policyIt = m_policyByGuardId.find(entry.second.guardId);
        const int restartCount = (policyIt == m_policyByGuardId.end()) ? 0 : policyIt->second.restartCount;
        const auto groupIt = entry.second.groupName.empty() ? m_guardGroups.end() : m_guardGroups.find(entry.second.groupName);
        const bool groupPaused = (groupIt != m_guardGroups.end() && groupIt->second.paused);
        oss << "\n" << makeGuardSummaryLine(entry.second, restartCount, groupPaused);
    }
    return oss.str();
}

std::string PGS::handleGet(DWORD pid)
{
    std::lock_guard<std::mutex> lock(m_guardsMutex);
    const auto it = m_guards.find(pid);
    if (it == m_guards.end())
    {
        return "ERR pid not found";
    }
    const auto policyIt = m_policyByGuardId.find(it->second.guardId);
    const int restartCount = (policyIt == m_policyByGuardId.end()) ? 0 : policyIt->second.restartCount;
    const auto groupIt = it->second.groupName.empty() ? m_guardGroups.end() : m_guardGroups.find(it->second.groupName);
    const bool groupPaused = (groupIt != m_guardGroups.end() && groupIt->second.paused);
    return "OK\n" + makeGuardSummaryLine(it->second, restartCount, groupPaused);
}

std::string PGS::makeGuardSummaryLine(const GuardInfo &guard, int restartCount, bool groupPaused)
{
    const bool alive = (guard.handle && WaitForSingleObject(guard.handle, 0) == WAIT_TIMEOUT);
    const std::int64_t nowMs = currentEpochMs();
    const std::int64_t cumulativeMs = effectiveCumulativeRunMs(guard, nowMs);
    const std::int64_t avgRestartIntervalMs = guard.restartIntervalCount > 0
        ? guard.restartIntervalSumMs / guard.restartIntervalCount
        : 0;
    std::ostringstream oss;
    oss << "PID=" << guard.pid
        << ";SESSION=" << guard.sessionId
        << ";ALIVE=" << (alive ? "1" : "0")
        << ";INTENTIONAL=" << (guard.intentional ? "1" : "0")
        << ";MAX_RESTARTS=" << maxRestartsLabel(guard.maxRestarts)
        << ";RESTART_COUNT=" << restartCount
        << ";HASH_VERIFIED=" << (guard.hashVerified ? "1" : "0")
        << ";HASH=" << (guard.fileHash.empty() ? "-" : guard.fileHash)
        << ";PATH_B64=" << base64Encode(guard.path)
        << ";RESTART_ARGS_B64=" << base64Encode(guard.restartArgs)
        << ";APP_KIND=" << (guard.appKind == AppKind::WinApp ? "winapp" : "win32")
        << ";AUMID_B64=" << base64Encode(guard.aumid)
        << ";RESTART_WINDOW=" << guard.restartWindowSec
        << ";RESTART_DELAY=" << guard.restartDelayMs
        << ";BACKOFF=" << (guard.backoff ? "1" : "0")
        << ";HANG_TIMEOUT=" << guard.hangTimeoutMs
        << ";KILL_ON_EXIT=" << (guard.killOnExit ? "1" : "0")
        << ";JOB_ATTACHED=" << (guard.jobHandle ? "1" : "0")
        << ";HEALTH_CHECK_B64=" << base64Encode(guard.healthCheckJson)
        << ";GROUP=" << (guard.groupName.empty() ? "-" : guard.groupName)
        << ";GROUP_PAUSED=" << (groupPaused ? "1" : "0")
        << ";PAUSED=" << ((guard.paused || groupPaused) ? "1" : "0")
        << ";GUARD_PAUSED=" << (guard.paused ? "1" : "0")
        << ";CREATED_AT=" << guard.createdAtMs
        << ";LAST_START=" << guard.lastStartMs
        << ";LAST_EXIT=" << guard.lastExitMs
        << ";LAST_EXIT_CODE=" << guard.lastExitCode
        << ";CUMULATIVE_RUN_MS=" << cumulativeMs
        << ";AVG_RESTART_INTERVAL_MS=" << avgRestartIntervalMs
        << ";CRASH_LOOP=" << (guard.crashLoop ? "1" : "0")
        << ";RESTART_HOOK_B64=" << base64Encode(guard.restartHookJson);
    return oss.str();
}

bool PGS::stripAuthEnvelope(const std::string &message, std::string &commandLine) const
{
    // Authentication envelope: "token <base64(token)> <commandLine>". The token
    // is base64-encoded so it may contain arbitrary bytes/spaces; the service
    // only stores and compares a SHA-256 hash in memory. An empty token is never
    // accepted (initialize() always establishes a non-empty token).
    commandLine = trim(message);
    if (commandLine.empty())
    {
        return false;
    }
    if (!m_requireAuth)
    {
        return true;
    }

    if (commandLine.rfind("token ", 0) != 0)
    {
        return false;
    }

    const std::size_t tokenStart = 6;
    const std::size_t tokenEnd = commandLine.find(' ', tokenStart);
    if (tokenEnd == std::string::npos)
    {
        return false;
    }

    const std::string encodedToken = commandLine.substr(tokenStart, tokenEnd - tokenStart);
    const std::string token = base64Decode(encodedToken);
    if (token.empty())
    {
        return false;
    }
    const std::string inputHash = sha256Hex(token);
    std::lock_guard<std::mutex> lock(m_authMutex);
    if (!constantTimeEquals(inputHash, m_authTokenHash))
    {
        return false;
    }

    commandLine = trim(commandLine.substr(tokenEnd + 1));
    return !commandLine.empty();
}

std::string PGS::handleModuleCommand(const std::string &args)
{
    // Sub-protocol: "module <sub> <rest>"
    //   list
    //   load <base64-path>
    //   unload <name>
    //   call <name> <kv-request>
    //   invoke <name> <method> <params-json-b64>
    //   invoke-json <json-request>
    const auto spacePos = args.find(' ');
    const std::string sub = (spacePos == std::string::npos) ? args : args.substr(0, spacePos);
    const std::string rest = (spacePos == std::string::npos) ? std::string() : trim(args.substr(spacePos + 1));

    if (sub == "list")
    {
        const auto mods = m_modules.list();
        std::string out = "OK count=" + std::to_string(mods.size());
        for (const auto &m : mods)
        {
            out += "\n" + m.name + "\t" + m.version + "\tabi=" +
                   (m.hasAbiVersion ? std::to_string(m.abiVersion) : std::string("?")) +
                   "\tjson=" + (m.hasInvokeJson ? "1" : "0");
        }
        return out;
    }

    if (sub == "load")
    {
        if (rest.empty())
        {
            return "ERR module load requires a base64 path";
        }
        const std::string path = base64Decode(rest);
        if (path.empty())
        {
            return "ERR invalid base64 path";
        }
        // Security: only allow loading DLLs that live inside the service's
        // modules directory. Without this, any authenticated client could
        // LoadLibrary an arbitrary DLL into the (LocalSystem) service process
        // and run code as SYSTEM.
        if (!isPathInsideModulesDir(path))
        {
            Logger::warning("PGS: rejected module load outside modules dir, path=" + path);
            return "ERR module load restricted to modules directory";
        }
        const std::string allowKey = ModuleManager::allowlistKeyForPath(path);
        if (!(m_kernelModulesEnabled || m_pplEnabled) && allowKey == "ppl")
        {
            return "ERR ppl module loading requires --enable-kernel-modules, --enable-risk critical, PGS_ENABLE_KERNEL_MODULES=1, or legacy --enable-ppl";
        }
        // Startup may skip directory scanning unless PPL/module loading is
        // explicitly enabled, but a direct module load must still honor the
        // same fail-closed allowlist gate.
        m_modules.ensureAllowlistLoaded(m_modulesDir);
        std::string err;
        if (m_modules.load(path, err))
        {
            recordEvent("module.load", "path=" + path + ";name=" + allowKey);
            return "OK loaded";
        }
        recordEvent("module.load-failed", "path=" + path + ";name=" + allowKey + ";error=" + err);
        return "ERR " + err;
    }

    if (sub == "unload")
    {
        if (rest.empty())
        {
            return "ERR module unload requires a name";
        }
        std::string err;
        if (m_modules.unload(rest, err))
        {
            recordEvent("module.unload", "name=" + rest);
            return "OK unloaded " + rest;
        }
        recordEvent("module.unload-failed", "name=" + rest + ";error=" + err);
        return "ERR " + err;
    }

    if (sub == "call")
    {
        // "call <name> <kv>"
        const auto sp = rest.find(' ');
        if (sp == std::string::npos)
        {
            return "ERR module call requires <name> <request>";
        }
        const std::string name = rest.substr(0, sp);
        const std::string request = trim(rest.substr(sp + 1));
        std::string response;
        std::string err;
        if (m_modules.invoke(name, request, response, err))
        {
            recordEvent("module.call", "name=" + name + ";request_b64=" + base64Encode(request) +
                                       ";response_b64=" + base64Encode(response));
            return response;
        }
        recordEvent("module.call-failed", "name=" + name + ";error=" + err);
        return "ERR " + err;
    }

    if (sub == "invoke")
    {
        const auto sp1 = rest.find(' ');
        if (sp1 == std::string::npos)
        {
            return "ERR module invoke requires <name> <method> <params-json-b64>";
        }
        const std::string name = trim(rest.substr(0, sp1));
        const std::string tail = trim(rest.substr(sp1 + 1));
        const auto sp2 = tail.find(' ');
        if (sp2 == std::string::npos)
        {
            return "ERR module invoke requires <name> <method> <params-json-b64>";
        }
        const std::string method = trim(tail.substr(0, sp2));
        const std::string paramsB64 = trim(tail.substr(sp2 + 1));
        if (name.empty() || method.empty())
        {
            return "ERR invalid module invoke target";
        }
        if (method.find('.') == std::string::npos)
        {
            return "ERR module method must be namespaced, e.g. profile.apply";
        }
        const std::string requestJson = jsonRpcRequest(name, method, paramsB64);
        std::string response;
        std::string err;
        if (m_modules.invokeJson(name, requestJson, response, err))
        {
            recordEvent("module.invoke", "name=" + name + ";method=" + method +
                                         ";response_b64=" + base64Encode(response));
            return response;
        }
        recordEvent("module.invoke-failed", "name=" + name + ";method=" + method + ";error=" + err);
        return "ERR " + err;
    }

    if (sub == "invoke-json")
    {
        const std::string requestJson = rest;
        if (requestJson.empty())
        {
            return jsonRpcError("", "INVALID_REQUEST", "module invoke-json requires a request envelope");
        }
        const std::string name = jsonStringValueLocal(requestJson, "module");
        const std::string method = jsonStringValueLocal(requestJson, "method");
        const std::string id = jsonStringValueLocal(requestJson, "id");
        if (name.empty() || method.empty())
        {
            return jsonRpcError(id, "INVALID_REQUEST", "module and method are required");
        }
        if (method.find('.') == std::string::npos)
        {
            return jsonRpcError(id, "INVALID_METHOD", "module method must be namespaced");
        }
        std::string response;
        std::string err;
        if (m_modules.invokeJson(name, requestJson, response, err))
        {
            recordEvent("module.invoke-json", "name=" + name + ";method=" + method +
                                              ";response_b64=" + base64Encode(response));
            return response;
        }
        recordEvent("module.invoke-json-failed", "name=" + name + ";method=" + method + ";error=" + err);
        return jsonRpcError(id, "MODULE_NOT_AVAILABLE", err);
    }

    if (sub == "verify")
    {
        const std::filesystem::path root = std::filesystem::path(utf8ToWide(m_modulesDir));
        const bool allowExists = std::filesystem::exists(root / L"modules.allow");
        const bool lockExists = std::filesystem::exists(root / L"modules.lock");
        const std::filesystem::path stagingRoot = stagingRootForModulesDir(m_modulesDir);
        const bool stagingExists = std::filesystem::exists(stagingRoot);
        const bool managerExists = std::filesystem::exists(root.parent_path() / L"module_managers");
        return std::string("OK modules_dir_b64=") + base64Encode(m_modulesDir) +
               ";modules_allow=" + (allowExists ? "1" : "0") +
               ";modules_lock=" + (lockExists ? "1" : "0") +
               ";modules_staging=" + (stagingExists ? "1" : "0") +
               ";module_managers=" + (managerExists ? "1" : "0") +
               ";permissive=" + (m_modulesPermissive ? "1" : "0") +
               ";kernel_enabled=" + ((m_kernelModulesEnabled || m_pplEnabled) ? "1" : "0");
    }

    if (sub == "reload")
    {
        if (rest.empty())
        {
            return "ERR module reload requires a name";
        }
        std::string err;
        m_modules.unload(rest, err);
        m_modules.ensureAllowlistLoaded(m_modulesDir);
        std::filesystem::path path = std::filesystem::path(utf8ToWide(m_modulesDir)) / utf8ToWide(rest);
        std::error_code ec;
        for (const auto &entry : std::filesystem::directory_iterator(path, ec))
        {
            if (!entry.is_regular_file() || entry.path().extension() != L".dll")
            {
                continue;
            }
            std::string loadErr;
            if (m_modules.load(wideToUtf8(entry.path().wstring()), loadErr))
            {
                return "OK reloaded " + rest;
            }
            return "ERR " + loadErr;
        }
        return "ERR module dll not found: " + rest;
    }

    if (sub == "disable")
    {
        if (rest.empty())
        {
            return "ERR module disable requires a name";
        }
        std::string err;
        if (m_modules.unload(rest, err))
        {
            recordEvent("module.disable", "name=" + rest);
            return "OK disabled " + rest;
        }
        return "ERR " + err;
    }

    if (sub == "install")
    {
        if (rest.empty())
        {
            return "ERR module install requires a base64 path to a module DLL";
        }
        const std::string sourcePathUtf8 = base64Decode(rest);
        std::filesystem::path sourceDll = std::filesystem::path(utf8ToWide(sourcePathUtf8));
        std::error_code ec;
        if (!std::filesystem::is_regular_file(sourceDll, ec) || sourceDll.extension() != L".dll")
        {
            return "ERR module install source must be a DLL file";
        }
        ModuleManager::ModuleInspection info;
        std::string err;
        if (!ModuleManager::inspectModulePath(sourcePathUtf8, info, err))
        {
            return "ERR " + err;
        }
        const std::string name = safeModuleName(info);
        if (name.empty())
        {
            return "ERR invalid module name in manifest/path";
        }
        if (!info.name.empty() && toLowerAscii(info.name) != name)
        {
            return "ERR module manifest name does not match install key";
        }
        if (name == "ppl" && !(m_kernelModulesEnabled || m_pplEnabled))
        {
            return "ERR ppl install requires --enable-kernel-modules, --enable-risk critical, or legacy --enable-ppl";
        }

        const std::filesystem::path modulesRoot = std::filesystem::path(utf8ToWide(m_modulesDir));
        const std::filesystem::path stagingRoot = stagingRootForModulesDir(m_modulesDir);
        const std::string stamp = std::to_string(epochMs());
        const std::filesystem::path stageDir = stagingRoot / utf8ToWide(name + "-stage-" + stamp);
        const std::filesystem::path finalDir = modulesRoot / utf8ToWide(name);
        const std::filesystem::path rollbackRoot = stagingRoot / L"rollback";
        const std::filesystem::path backupDir = rollbackRoot / utf8ToWide(name + "-" + stamp);
        std::filesystem::create_directories(stagingRoot, ec);
        std::filesystem::create_directories(rollbackRoot, ec);
        if (!copyModulePayloadToStage(sourceDll, stageDir, err))
        {
            std::filesystem::remove_all(stageDir, ec);
            return "ERR " + err;
        }
        const std::filesystem::path stagedDll = stageDir / sourceDll.filename();
        ModuleManager::ModuleInspection stagedInfo;
        if (!ModuleManager::inspectModulePath(wideToUtf8(stagedDll.wstring()), stagedInfo, err))
        {
            std::filesystem::remove_all(stageDir, ec);
            return "ERR staged module verification failed: " + err;
        }
        if (safeModuleName(stagedInfo) != name || stagedInfo.sha256 != info.sha256)
        {
            std::filesystem::remove_all(stageDir, ec);
            return "ERR staged module changed during install";
        }

        m_modules.unload(name, err);
        if (std::filesystem::exists(finalDir, ec))
        {
            std::filesystem::rename(finalDir, backupDir, ec);
            if (ec)
            {
                std::filesystem::remove_all(stageDir, ec);
                return "ERR failed to backup existing module for rollback";
            }
        }
        std::filesystem::rename(stageDir, finalDir, ec);
        if (ec)
        {
            if (std::filesystem::exists(backupDir))
            {
                std::filesystem::rename(backupDir, finalDir, ec);
            }
            return "ERR failed to promote staged module";
        }
        const std::filesystem::path finalDll = finalDir / sourceDll.filename();
        ModuleManager::ModuleInspection finalInfo;
        if (!ModuleManager::inspectModulePath(wideToUtf8(finalDll.wstring()), finalInfo, err))
        {
            return "ERR installed module verification failed: " + err;
        }
        if (!writeOrUpdateModulesLock(modulesRoot / L"modules.lock", finalInfo, name, err))
        {
            return "ERR " + err;
        }
        m_modules.setModulesRoot(std::string());
        m_modules.ensureAllowlistLoaded(m_modulesDir);
        recordEvent("module.install", "name=" + name + ";path=" + wideToUtf8(finalDll.wstring()));
        return "OK installed " + name + ";staged=1;trusted=1";
    }

    if (sub == "rollback")
    {
        if (rest.empty())
        {
            return "ERR module rollback requires a name";
        }
        const std::string name = toLowerAscii(trim(rest));
        const std::filesystem::path modulesRoot = std::filesystem::path(utf8ToWide(m_modulesDir));
        const std::filesystem::path stagingRoot = stagingRootForModulesDir(m_modulesDir);
        const std::filesystem::path rollbackRoot = stagingRoot / L"rollback";
        const std::filesystem::path rollbackDir = newestRollbackDir(rollbackRoot, name);
        if (rollbackDir.empty())
        {
            return "ERR no rollback found for module " + name;
        }
        std::filesystem::path rollbackDll = firstDllInDir(rollbackDir);
        if (rollbackDll.empty())
        {
            return "ERR rollback payload has no DLL";
        }
        ModuleManager::ModuleInspection info;
        std::string err;
        if (!ModuleManager::inspectModulePath(wideToUtf8(rollbackDll.wstring()), info, err))
        {
            return "ERR rollback verification failed: " + err;
        }
        if (safeModuleName(info) != name)
        {
            return "ERR rollback module name mismatch";
        }
        std::error_code ec;
        const std::filesystem::path finalDir = modulesRoot / utf8ToWide(name);
        const std::filesystem::path currentBackupRoot = stagingRoot / L"current";
        std::filesystem::create_directories(currentBackupRoot, ec);
        const std::filesystem::path currentBackup = currentBackupRoot / utf8ToWide(name + "-" + std::to_string(epochMs()));
        m_modules.unload(name, err);
        if (std::filesystem::exists(finalDir, ec))
        {
            std::filesystem::rename(finalDir, currentBackup, ec);
            if (ec)
            {
                return "ERR failed to backup current module before rollback";
            }
        }
        std::filesystem::rename(rollbackDir, finalDir, ec);
        if (ec)
        {
            if (std::filesystem::exists(currentBackup))
            {
                std::filesystem::rename(currentBackup, finalDir, ec);
            }
            return "ERR failed to restore rollback payload";
        }
        rollbackDll = firstDllInDir(finalDir);
        if (!rollbackDll.empty() && ModuleManager::inspectModulePath(wideToUtf8(rollbackDll.wstring()), info, err))
        {
            writeOrUpdateModulesLock(modulesRoot / L"modules.lock", info, name, err);
        }
        m_modules.setModulesRoot(std::string());
        m_modules.ensureAllowlistLoaded(m_modulesDir);
        recordEvent("module.rollback", "name=" + name);
        return "OK rolled back " + name;
    }

    if (sub == "artifact")
    {
        return "ERR module artifact store is not enabled; modules should return small JSON results or external artifact IDs";
    }

    if (sub == "op-status")
    {
        if (trim(rest).empty())
        {
            return "ERR module op-status requires an operation id";
        }
        return "ERR module operation status store is not enabled; long-running modules should return durable operation IDs handled by their module or a future host";
    }

    return "ERR unknown module subcommand";
}

// "ppl" convenience dispatcher. Routes to the ppl module so callers do not
// need the module-call syntax. If the ppl module is not loaded, returns
// "ERR ppl module not loaded" instead of a transport error.
std::string PGS::handlePplCommand(const std::string &args)
{
    // Convenience wrapper that routes to the "ppl" module so callers do not
    // need to remember the module-call syntax:
    //   ppl set <pid> <signer>
    //   ppl get <pid>
    //   ppl clear <pid>
    const auto spacePos = args.find(' ');
    const std::string sub = (spacePos == std::string::npos) ? args : args.substr(0, spacePos);
    const std::string rest = (spacePos == std::string::npos) ? std::string() : trim(args.substr(spacePos + 1));

    if (sub == "set")
    {
        // "set <pid> <signer>"
        const auto sp = rest.find(' ');
        if (sp == std::string::npos)
        {
            return "ERR ppl set requires <pid> <signer>";
        }
        DWORD pid = 0;
        if (!parsePid(trim(rest.substr(0, sp)), pid))
        {
            return "ERR invalid pid for ppl set";
        }
        const std::string signer = trim(rest.substr(sp + 1));
        if (signer.empty())
        {
            return "ERR ppl set requires a signer";
        }
        const std::string params = "{\"pid\":" + std::to_string(pid) + ",\"signer\":\"" + jsonEscapeLocal(signer) + "\"}";
        const std::string response = handleModuleCommand("invoke ppl ppl.set " + base64Encode(params));
        recordEvent(response.rfind("ERR", 0) == 0 ? "ppl.set-failed" : "ppl.set",
                    "pid=" + std::to_string(pid) + ";signer=" + signer +
                    ";response_b64=" + base64Encode(response));
        return response;
    }

    if (sub == "get" || sub == "clear")
    {
        DWORD pid = 0;
        if (!parsePid(rest, pid))
        {
            return "ERR invalid pid for ppl " + sub;
        }
        const std::string params = "{\"pid\":" + std::to_string(pid) + "}";
        const std::string response = handleModuleCommand("invoke ppl ppl." + sub + " " + base64Encode(params));
        recordEvent(response.rfind("ERR", 0) == 0 ? ("ppl." + sub + "-failed") : ("ppl." + sub),
                    "pid=" + std::to_string(pid) + ";response_b64=" + base64Encode(response));
        return response;
    }

    return "ERR unknown ppl subcommand";
}

std::string PGS::handleHealthCheckCommand(const std::string &args)
{
    const auto spacePos = args.find(' ');
    const std::string sub = (spacePos == std::string::npos) ? trim(args) : trim(args.substr(0, spacePos));
    const std::string rest = (spacePos == std::string::npos) ? std::string() : trim(args.substr(spacePos + 1));
    if (sub != "set" && sub != "get" && sub != "clear")
    {
        return "ERR unknown health-check subcommand";
    }

    const auto sp = rest.find(' ');
    const std::string pidText = (sp == std::string::npos) ? rest : trim(rest.substr(0, sp));
    const std::string payload = (sp == std::string::npos) ? std::string() : trim(rest.substr(sp + 1));
    DWORD pid = 0;
    if (!parsePid(pidText, pid))
    {
        return "ERR invalid pid for health-check";
    }

    if (sub == "get")
    {
        std::lock_guard<std::mutex> lock(m_guardsMutex);
        const auto it = m_guards.find(pid);
        if (it == m_guards.end())
        {
            return "ERR pid not found";
        }
        return "OK health_check_b64=" + base64Encode(it->second.healthCheckJson);
    }

    bool changed = false;
    std::string configJson;
    if (sub == "set")
    {
        if (payload.empty())
        {
            return "ERR health-check set requires config-json-b64";
        }
        configJson = base64Decode(payload);
        if (configJson.empty() || configJson.size() > kMaxGuardConfigJsonSize || !looksLikeJsonObjectOrArrayLocal(configJson))
        {
            return "ERR invalid health-check JSON";
        }
    }
    {
        std::lock_guard<std::mutex> lock(m_guardsMutex);
        auto it = m_guards.find(pid);
        if (it == m_guards.end())
        {
            return "ERR pid not found";
        }
        it->second.healthCheckJson = (sub == "set") ? configJson : std::string();
        auto persisted = m_persistedGuards.find(it->second.guardId);
        if (persisted != m_persistedGuards.end())
        {
            copyGuardToPersisted(it->second, persisted->second);
        }
        changed = true;
    }
    if (changed)
    {
        persistState();
        recordEvent(sub == "set" ? "guard.health-check-set" : "guard.health-check-clear",
                    "pid=" + std::to_string(pid));
    }
    return sub == "set" ? "OK health-check stored" : "OK health-check cleared";
}

std::string PGS::handleRestartHookCommand(const std::string &args)
{
    const auto spacePos = args.find(' ');
    const std::string sub = (spacePos == std::string::npos) ? trim(args) : trim(args.substr(0, spacePos));
    const std::string rest = (spacePos == std::string::npos) ? std::string() : trim(args.substr(spacePos + 1));
    if (sub != "set" && sub != "get" && sub != "clear")
    {
        return "ERR unknown restart-hook subcommand";
    }

    const auto sp = rest.find(' ');
    const std::string pidText = (sp == std::string::npos) ? rest : trim(rest.substr(0, sp));
    const std::string payload = (sp == std::string::npos) ? std::string() : trim(rest.substr(sp + 1));
    DWORD pid = 0;
    if (!parsePid(pidText, pid))
    {
        return "ERR invalid pid for restart-hook";
    }

    if (sub == "get")
    {
        std::lock_guard<std::mutex> lock(m_guardsMutex);
        const auto it = m_guards.find(pid);
        if (it == m_guards.end())
        {
            return "ERR pid not found";
        }
        return "OK restart_hook_b64=" + base64Encode(it->second.restartHookJson) + ";execution=disabled";
    }

    std::string hookJson;
    if (sub == "set")
    {
        if (payload.empty())
        {
            return "ERR restart-hook set requires config-json-b64";
        }
        hookJson = base64Decode(payload);
        if (hookJson.empty() || hookJson.size() > kMaxGuardConfigJsonSize || !looksLikeJsonObjectOrArrayLocal(hookJson))
        {
            return "ERR invalid restart-hook JSON";
        }
    }
    {
        std::lock_guard<std::mutex> lock(m_guardsMutex);
        auto it = m_guards.find(pid);
        if (it == m_guards.end())
        {
            return "ERR pid not found";
        }
        it->second.restartHookJson = (sub == "set") ? hookJson : std::string();
        auto persisted = m_persistedGuards.find(it->second.guardId);
        if (persisted != m_persistedGuards.end())
        {
            copyGuardToPersisted(it->second, persisted->second);
        }
    }
    persistState();
    recordEvent(sub == "set" ? "guard.restart-hook-set" : "guard.restart-hook-clear",
                "pid=" + std::to_string(pid) + ";execution=disabled");
    return sub == "set" ? "OK restart-hook stored execution=disabled" : "OK restart-hook cleared";
}

std::string PGS::handleGroupCommand(const std::string &args)
{
    const auto spacePos = args.find(' ');
    const std::string sub = (spacePos == std::string::npos) ? trim(args) : trim(args.substr(0, spacePos));
    const std::string rest = (spacePos == std::string::npos) ? std::string() : trim(args.substr(spacePos + 1));
    if (sub.empty())
    {
        return "ERR group subcommand required";
    }

    if (sub == "list")
    {
        std::vector<GuardGroupState> groups;
        std::unordered_map<std::string, std::size_t> counts;
        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            groups.reserve(m_guardGroups.size());
            for (const auto &entry : m_guardGroups)
            {
                groups.push_back(entry.second);
            }
            for (const auto &entry : m_guards)
            {
                if (!entry.second.groupName.empty())
                {
                    ++counts[entry.second.groupName];
                }
            }
        }
        std::sort(groups.begin(), groups.end(), [](const GuardGroupState &a, const GuardGroupState &b) {
            if (a.startupOrder != b.startupOrder) return a.startupOrder < b.startupOrder;
            return a.name < b.name;
        });
        std::ostringstream oss;
        oss << "OK count=" << groups.size();
        for (const auto &group : groups)
        {
            oss << "\nNAME=" << group.name
                << ";PAUSED=" << (group.paused ? "1" : "0")
                << ";STARTUP_ORDER=" << group.startupOrder
                << ";DEPENDENCIES=" << (group.dependencies.empty() ? "-" : joinCsvLocal(group.dependencies))
                << ";MEMBERS=" << counts[group.name];
        }
        return oss.str();
    }

    const auto sp = rest.find(' ');
    const std::string rawName = (sp == std::string::npos) ? rest : trim(rest.substr(0, sp));
    const std::string tail = (sp == std::string::npos) ? std::string() : trim(rest.substr(sp + 1));
    const std::string name = sanitizeGroupNameLocal(rawName);
    if (name.empty())
    {
        return "ERR invalid group name";
    }

    if (sub == "create")
    {
        int startupOrder = 0;
        std::string depsB64;
        if (!tail.empty())
        {
            const auto sp2 = tail.find(' ');
            const std::string orderText = (sp2 == std::string::npos) ? tail : trim(tail.substr(0, sp2));
            depsB64 = (sp2 == std::string::npos) ? std::string() : trim(tail.substr(sp2 + 1));
            if (!parseIntLocal(orderText, startupOrder))
            {
                return "ERR invalid group startup order";
            }
        }
        GuardGroupState group;
        group.name = name;
        group.startupOrder = startupOrder;
        if (!depsB64.empty() && depsB64 != "-")
        {
            group.dependencies = splitCsvTrimmedLocal(base64Decode(depsB64));
        }
        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            auto existing = m_guardGroups.find(name);
            if (existing != m_guardGroups.end())
            {
                group.paused = existing->second.paused;
            }
            m_guardGroups[name] = group;
        }
        persistState();
        recordEvent("guard.group-create", "name=" + name);
        return "OK group created name=" + name;
    }

    if (sub == "add" || sub == "remove")
    {
        DWORD pid = 0;
        if (!parsePid(tail, pid))
        {
            return "ERR group " + sub + " requires <name> <pid>";
        }
        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            auto groupIt = m_guardGroups.find(name);
            if (groupIt == m_guardGroups.end())
            {
                if (sub == "remove")
                {
                    return "ERR group not found";
                }
                m_guardGroups[name] = GuardGroupState{name, false, 0, {}};
            }
            auto it = m_guards.find(pid);
            if (it == m_guards.end())
            {
                return "ERR pid not found";
            }
            if (sub == "add")
            {
                it->second.groupName = name;
            }
            else if (it->second.groupName == name)
            {
                it->second.groupName.clear();
            }
            auto persisted = m_persistedGuards.find(it->second.guardId);
            if (persisted != m_persistedGuards.end())
            {
                copyGuardToPersisted(it->second, persisted->second);
            }
        }
        persistState();
        recordEvent(sub == "add" ? "guard.group-add" : "guard.group-remove",
                    "name=" + name + ";pid=" + std::to_string(pid));
        return sub == "add" ? "OK group member added" : "OK group member removed";
    }

    if (sub == "pause" || sub == "resume")
    {
        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            auto it = m_guardGroups.find(name);
            if (it == m_guardGroups.end())
            {
                return "ERR group not found";
            }
            it->second.paused = (sub == "pause");
        }
        persistState();
        recordEvent(sub == "pause" ? "guard.group-pause" : "guard.group-resume", "name=" + name);
        return sub == "pause" ? "OK group paused" : "OK group resumed";
    }

    if (sub == "restart")
    {
        std::vector<GuardInfo> targets;
        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            auto groupIt = m_guardGroups.find(name);
            if (groupIt == m_guardGroups.end())
            {
                return "ERR group not found";
            }
            if (groupIt->second.paused)
            {
                return "ERR group is paused; resume before restart";
            }
            for (const auto &entry : m_guards)
            {
                if (entry.second.groupName == name)
                {
                    targets.push_back(entry.second);
                }
            }
        }
        for (const GuardInfo &guard : targets)
        {
            terminateGuardFamily(guard.guardId);
            if (guard.handle)
            {
                TerminateProcess(guard.handle, 1);
            }
        }
        recordEvent("guard.group-restart", "name=" + name + ";members=" + std::to_string(targets.size()));
        return "OK group restart requested members=" + std::to_string(targets.size());
    }

    return "ERR unknown group subcommand";
}

void PGS::recordEvent(const std::string &type, const std::string &detail)
{
    const std::uint64_t id = m_nextEventId.fetch_add(1);
    const std::int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::string line = "ID=" + std::to_string(id) +
                       ";TS=" + std::to_string(nowMs) +
                       ";TYPE=" + type +
                       ";DETAIL_B64=" + base64Encode(detail);
    std::lock_guard<std::mutex> lock(m_eventsMutex);
    m_events.push_back(std::move(line));
    while (m_events.size() > kMaxEventHistory)
    {
        m_events.pop_front();
    }
}

std::string PGS::handleEventsCommand(const std::string &args)
{
    const std::vector<std::string> parts = splitByChar(trim(args), ' ');
    const std::string sub = parts.empty() ? std::string() : trim(parts[0]);
    if (!sub.empty() && sub != "list")
    {
        return "ERR unknown events subcommand";
    }

    std::size_t limit = kMaxEventHistory;
    if (parts.size() >= 2)
    {
        std::uint64_t parsed = 0;
        if (!parseUnsignedLongLong(parts[1], parsed) || parsed == 0)
        {
            return "ERR invalid events limit";
        }
        limit = static_cast<std::size_t>(std::min<std::uint64_t>(
            parsed, static_cast<std::uint64_t>(kMaxEventHistory)));
    }

    std::vector<std::string> snapshot;
    {
        std::lock_guard<std::mutex> lock(m_eventsMutex);
        const std::size_t count = std::min(limit, m_events.size());
        snapshot.reserve(count);
        const auto start = m_events.end() - static_cast<std::ptrdiff_t>(count);
        for (auto it = start; it != m_events.end(); ++it)
        {
            snapshot.push_back(*it);
        }
    }

    std::string out = "OK count=" + std::to_string(snapshot.size());
    for (const std::string &line : snapshot)
    {
        out += "\n" + line;
    }
    return out;
}

} // namespace ProcessGuard
