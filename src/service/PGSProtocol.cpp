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
#include "PGSServiceHelpers.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

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
    return service_util::jsonEscape(value);
}

std::string jsonStringValueLocal(const std::string &text, const std::string &key)
{
    return service_util::jsonStringValue(text, key);
}

std::string jsonRpcError(const std::string &id, const std::string &code, const std::string &message)
{
    return service_util::jsonRpcError(id, code, message);
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

constexpr std::int64_t kDefaultOperationTtlMs = 24LL * 60LL * 60LL * 1000LL;
constexpr std::int64_t kMinArtifactRetentionTtlMs = 60LL * 1000LL;
constexpr std::int64_t kMaxArtifactRetentionTtlMs = 7LL * 24LL * 60LL * 60LL * 1000LL;
constexpr std::size_t kMaxOperations = 1024;
constexpr std::uint64_t kMaxArtifactBytes = 16ull * 1024ull * 1024ull;
constexpr std::uint64_t kMaxArtifactTotalBytes = 256ull * 1024ull * 1024ull;
constexpr std::uint64_t kMaxArtifactChunkBytes = 32768ull;

bool isOpaqueId(const std::string &id, const std::string &prefix)
{
    return service_util::isOpaqueId(id, prefix);
}

std::string jsonRawValueLocal(const std::string &text, const std::string &key)
{
    return service_util::jsonRawValue(text, key);
}

std::vector<std::string> jsonStringArrayLocal(const std::string &text, const std::string &key)
{
    return service_util::jsonStringArray(text, key);
}

std::int64_t jsonInt64Local(const std::string &text, const std::string &key, std::int64_t fallback)
{
    return service_util::jsonInt64(text, key, fallback);
}

std::string safeDisplayFilename(std::string value)
{
    value = trim(value);
    if (value.empty()) return "artifact.bin";
    std::string out;
    for (char ch : value)
    {
        const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                        (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-';
        out.push_back(ok ? ch : '_');
    }
    if (out == "." || out == "..") return "artifact.bin";
    if (out.size() > 96) out.resize(96);
    return out.empty() ? std::string("artifact.bin") : out;
}

std::string defaultArtifactSensitivity(const PGS::ArtifactRecord &rec)
{
    const std::string method = toLowerAscii(rec.method);
    const std::string type = toLowerAscii(rec.contentType);
    const std::string name = toLowerAscii(rec.filename);
    if (method.find("dump") != std::string::npos || (name.size() >= 4 && name.rfind(".dmp") == name.size() - 4) ||
        type.find("minidump") != std::string::npos || type.find("portable-executable") != std::string::npos)
    {
        return "high";
    }
    if (method.find("backup") != std::string::npos)
    {
        return "medium";
    }
    return std::string();
}

bool parseJsonBoolLocal(const std::string &text, const std::string &key, bool fallback = false)
{
    const std::string value = toLowerAscii(trim(jsonRawValueLocal(text, key)));
    if (value == "true" || value == "1") return true;
    if (value == "false" || value == "0") return false;
    return fallback;
}

std::filesystem::path artifactRootForStateFile(const std::string &stateFilePath)
{
    std::filesystem::path root = std::filesystem::path(stateFilePath).parent_path();
    if (root.empty()) root = L".";
    return root / L"artifacts";
}

std::filesystem::path artifactPolicyPathForStateFile(const std::string &stateFilePath)
{
    std::filesystem::path root = std::filesystem::path(stateFilePath).parent_path();
    if (root.empty()) root = L".";
    return root / L"artifact_policy.cfg";
}

std::filesystem::path artifactContentPath(const std::filesystem::path &root, const std::string &id)
{
    return root / utf8ToWide(id + ".bin");
}

std::filesystem::path artifactMetaPath(const std::filesystem::path &root, const std::string &id)
{
    return root / utf8ToWide(id + ".json");
}

std::string artifactRecordJson(const PGS::ArtifactRecord &rec)
{
    return "{\"id\":\"" + jsonEscapeLocal(rec.id) +
           "\",\"module\":\"" + jsonEscapeLocal(rec.module) +
           "\",\"method\":\"" + jsonEscapeLocal(rec.method) +
           "\",\"content_type\":\"" + jsonEscapeLocal(rec.contentType) +
           "\",\"filename\":\"" + jsonEscapeLocal(rec.filename) +
           "\",\"size\":" + std::to_string(rec.size) +
           ",\"sha256\":\"" + jsonEscapeLocal(rec.sha256) +
           "\",\"created_ms\":" + std::to_string(rec.createdMs) +
           ",\"expires_ms\":" + std::to_string(rec.expiresMs) +
           ",\"trace_id\":\"" + jsonEscapeLocal(rec.traceId) +
           "\",\"operation_id\":\"" + jsonEscapeLocal(rec.operationId) +
           "\",\"sensitive\":" + std::string(rec.sensitive ? "true" : "false") +
           ",\"sensitivity\":\"" + jsonEscapeLocal(rec.sensitivity) +
           "\",\"storage_hash\":\"" + jsonEscapeLocal(rec.storageHash) +
           "\",\"storage_hash_verified\":" + (rec.storageHashVerified ? "true" : "false") + "}";
}

std::string operationRecordJson(const PGS::OperationRecord &rec)
{
    std::ostringstream artifacts;
    artifacts << '[';
    for (std::size_t i = 0; i < rec.artifactIds.size(); ++i)
    {
        if (i != 0) artifacts << ',';
        artifacts << '"' << jsonEscapeLocal(rec.artifactIds[i]) << '"';
    }
    artifacts << ']';
    std::string json = "{\"id\":\"" + jsonEscapeLocal(rec.id) +
        "\",\"module\":\"" + jsonEscapeLocal(rec.module) +
        "\",\"method\":\"" + jsonEscapeLocal(rec.method) +
        "\",\"status\":\"" + jsonEscapeLocal(rec.status) + "\"";
    if (rec.progress >= 0) json += ",\"progress\":" + std::to_string(rec.progress);
    json += ",\"message\":\"" + jsonEscapeLocal(rec.message) +
            "\",\"artifact_ids\":" + artifacts.str() +
            ",\"created_ms\":" + std::to_string(rec.createdMs) +
            ",\"updated_ms\":" + std::to_string(rec.updatedMs) +
            ",\"expires_ms\":" + std::to_string(rec.expiresMs) +
            ",\"trace_id\":\"" + jsonEscapeLocal(rec.traceId) +
            "\",\"caller\":\"" + jsonEscapeLocal(rec.caller) + "\"";
    if (!rec.resultJson.empty()) json += ",\"result\":" + rec.resultJson;
    if (!rec.errorCode.empty() || !rec.errorMessage.empty())
    {
        json += ",\"error\":{\"code\":\"" + jsonEscapeLocal(rec.errorCode) +
                "\",\"message\":\"" + jsonEscapeLocal(rec.errorMessage) + "\"}";
    }
    json += '}';
    return json;
}

std::string jsonRpcResultLocal(const std::string &id, const std::string &resultJson)
{
    return service_util::jsonRpcResult(id, resultJson);
}

bool artifactRecordFromJson(const std::string &json, PGS::ArtifactRecord &rec)
{
    rec = PGS::ArtifactRecord{};
    rec.id = jsonStringValueLocal(json, "id");
    if (!isOpaqueId(rec.id, "art_"))
    {
        return false;
    }
    rec.module = jsonStringValueLocal(json, "module");
    rec.method = jsonStringValueLocal(json, "method");
    rec.contentType = jsonStringValueLocal(json, "content_type");
    rec.filename = jsonStringValueLocal(json, "filename");
    rec.sha256 = jsonStringValueLocal(json, "sha256");
    rec.traceId = jsonStringValueLocal(json, "trace_id");
    rec.operationId = jsonStringValueLocal(json, "operation_id");
    rec.storageHash = jsonStringValueLocal(json, "storage_hash");
    rec.sensitive = trim(jsonRawValueLocal(json, "sensitive")) == "true";
    rec.sensitivity = jsonStringValueLocal(json, "sensitivity");
    rec.storageHashVerified = trim(jsonRawValueLocal(json, "storage_hash_verified")) == "true";
    rec.size = static_cast<std::uint64_t>(std::max<std::int64_t>(0, jsonInt64Local(json, "size", 0)));
    rec.createdMs = jsonInt64Local(json, "created_ms", 0);
    rec.expiresMs = jsonInt64Local(json, "expires_ms", 0);
    return true;
}

bool readWholeFile(const std::filesystem::path &path, std::string &out)
{
    return service_util::readWholeFile(path, out);
}

bool writeWholeFile(const std::filesystem::path &path, const std::string &data)
{
    return service_util::writeWholeFile(path, data);
}

std::string makeOpaqueId(const std::string &prefix)
{
    std::string hex = randomBytesHex(16);
    if (hex.empty())
    {
        hex = sha256Hex(prefix + std::to_string(epochMs())).substr(0, 32);
    }
    return prefix + hex;
}

std::uint64_t regularFileSize(const std::filesystem::path &path)
{
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec))
    {
        return 0;
    }
    return static_cast<std::uint64_t>(std::filesystem::file_size(path, ec));
}

void removeArtifactFiles(const std::filesystem::path &root, const std::string &artifactId, PGS::ArtifactCleanupResult &result)
{
    std::error_code ec;
    std::string metaText;
    PGS::ArtifactRecord rec;
    if (readWholeFile(artifactMetaPath(root, artifactId), metaText) && artifactRecordFromJson(metaText, rec) && rec.sensitive)
    {
        ++result.sensitiveRemoved;
    }
    const std::filesystem::path content = artifactContentPath(root, artifactId);
    const std::filesystem::path meta = artifactMetaPath(root, artifactId);
    result.reclaimedBytes += regularFileSize(content);
    std::filesystem::remove(content, ec);
    std::filesystem::remove(meta, ec);
    ++result.removed;
}

void appendCleanupDetail(std::string &detail, const std::string &item)
{
    if (item.empty())
    {
        return;
    }
    if (!detail.empty())
    {
        detail += ',';
    }
    detail += item;
}

std::string artifactPolicySummaryValues(std::int64_t ttlMs, bool autoCleanup, bool verifyOnStatus)
{
    return "ttl_ms=" + std::to_string(ttlMs) +
           ";auto_cleanup=" + (autoCleanup ? std::string("1") : std::string("0")) +
           ";verify_on_status=" + (verifyOnStatus ? std::string("1") : std::string("0")) +
           ";max_artifact_bytes=" + std::to_string(kMaxArtifactBytes) +
           ";max_total_bytes=" + std::to_string(kMaxArtifactTotalBytes);
}

std::string artifactPolicyJson(std::int64_t ttlMs, bool autoCleanup, bool verifyOnStatus)
{
    return "{\"ttl_ms\":" + std::to_string(ttlMs) +
           ",\"auto_cleanup\":" + std::string(autoCleanup ? "true" : "false") +
           ",\"verify_on_status\":" + std::string(verifyOnStatus ? "true" : "false") +
           ",\"max_artifact_bytes\":" + std::to_string(kMaxArtifactBytes) +
           ",\"max_total_bytes\":" + std::to_string(kMaxArtifactTotalBytes) + "}";
}

std::string artifactStatusJson(const PGS::ArtifactStoreStatus &status,
                               std::int64_t ttlMs,
                               bool autoCleanup,
                               bool verifyOnStatus)
{
    return "{\"store_exists\":" + std::string(status.storeExists ? "true" : "false") +
           ",\"root_secured\":" + std::string(status.rootSecured ? "true" : "false") +
           ",\"count\":" + std::to_string(status.count) +
           ",\"total_bytes\":" + std::to_string(status.totalBytes) +
           ",\"expired\":" + std::to_string(status.expired) +
           ",\"corrupt\":" + std::to_string(status.corrupt) +
           ",\"orphaned\":" + std::to_string(status.orphaned) +
           ",\"verified\":" + std::to_string(status.verified) +
           ",\"sensitive\":" + std::to_string(status.sensitive) +
           ",\"ttl_ms\":" + std::to_string(ttlMs) +
           ",\"auto_cleanup\":" + std::string(autoCleanup ? "true" : "false") +
           ",\"verify_on_status\":" + std::string(verifyOnStatus ? "true" : "false") +
           ",\"max_artifact_bytes\":" + std::to_string(kMaxArtifactBytes) +
           ",\"max_total_bytes\":" + std::to_string(kMaxArtifactTotalBytes) + "}";
}

bool isTerminalOperationStatus(const std::string &status)
{
    return status == "succeeded" || status == "failed" || status == "cancelled" || status == "expired";
}

bool parseTtlMsText(const std::string &text, std::int64_t &out)
{
    const std::string value = trim(text);
    if (value.empty())
    {
        return false;
    }
    try
    {
        std::size_t used = 0;
        const long long parsed = std::stoll(value, &used, 10);
        if (used != value.size() || parsed < kMinArtifactRetentionTtlMs || parsed > kMaxArtifactRetentionTtlMs)
        {
            return false;
        }
        out = static_cast<std::int64_t>(parsed);
        return true;
    }
    catch (const std::exception &)
    {
        return false;
    }
}

bool parseArtifactBoolText(const std::string &text, bool &out)
{
    const std::string value = toLowerAscii(trim(text));
    if (value == "1" || value == "true" || value == "yes" || value == "on")
    {
        out = true;
        return true;
    }
    if (value == "0" || value == "false" || value == "no" || value == "off")
    {
        out = false;
        return true;
    }
    return false;
}

std::string clampMessage(std::string text)
{
    if (text.size() > 512)
    {
        text.resize(512);
    }
    return text;
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
    return service_util::looksLikeJsonObjectOrArray(text);
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

    if (command == "guard")
    {
        return handleGuardCommand(args);
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

    std::string storedAumid = aumid;
    if (appKind == AppKind::WinApp)
    {
        util::AppxAumidInfo appx{};
        std::string aumidError;
        if (util::deriveAumidForWindowsAppPath(actualPath, appx, aumidError))
        {
            if (storedAumid.empty())
            {
                storedAumid = appx.aumid;
            }
            else if (toLowerAscii(storedAumid) != toLowerAscii(appx.aumid))
            {
                Logger::warning("PGS: register rejected, AUMID mismatch for path=" + actualPath +
                                ", provided=" + storedAumid + ", derived=" + appx.aumid);
                return "ERR AUMID does not match AppxManifest.xml";
            }
        }
        else if (storedAumid.empty())
        {
            return "ERR missing AUMID for winapp: " + aumidError;
        }
    }

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
        updated.aumid = storedAumid;
        updated.restartWindowSec = restartWindowSec;
        updated.restartDelayMs = restartDelayMs;
        updated.backoff = backoff;
        updated.hangTimeoutMs = hangTimeoutMs;
        updated.killOnExit = killOnExit;
        updated.jobHandle = nullptr;
        if (existing != m_guards.end())
        {
            updated.healthCheckJson = existing->second.healthCheckJson;
            updated.healthStatus = existing->second.healthStatus;
            updated.healthLastMessage = existing->second.healthLastMessage;
            updated.healthLastCheckMs = existing->second.healthLastCheckMs;
            updated.healthLastOkMs = existing->second.healthLastOkMs;
            updated.healthLastFailureMs = existing->second.healthLastFailureMs;
            updated.healthNextCheckMs = existing->second.healthNextCheckMs;
            updated.healthFailureCount = existing->second.healthFailureCount;
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
            resetHealthRuntimeState(updated);
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
        if (finalAppKind == AppKind::WinApp)
        {
            util::AppxAumidInfo appx{};
            std::string aumidError;
            if (util::deriveAumidForWindowsAppPath(it->second.path, appx, aumidError))
            {
                if (finalAumid.empty())
                {
                    finalAumid = appx.aumid;
                }
                else if (toLowerAscii(finalAumid) != toLowerAscii(appx.aumid))
                {
                    return "ERR AUMID does not match AppxManifest.xml";
                }
            }
            else if (finalAumid.empty())
            {
                return "ERR missing AUMID for winapp: " + aumidError;
            }
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
    std::vector<std::uint64_t> activeGuardIds;
    activeGuardIds.reserve(m_guards.size());
    std::size_t extraArchived = 0;
    for (const auto &entry : m_guards)
    {
        activeGuardIds.push_back(entry.second.guardId);
    }
    for (const auto &entry : m_persistedGuards)
    {
        if (!entry.second.quarantined)
        {
            continue;
        }
        if (std::find(activeGuardIds.begin(), activeGuardIds.end(), entry.first) == activeGuardIds.end())
        {
            ++extraArchived;
        }
    }
    oss << "OK count=" << (m_guards.size() + extraArchived);
    for (const auto &entry : m_guards)
    {
        const auto policyIt = m_policyByGuardId.find(entry.second.guardId);
        const int restartCount = (policyIt == m_policyByGuardId.end()) ? 0 : policyIt->second.restartCount;
        const auto groupIt = entry.second.groupName.empty() ? m_guardGroups.end() : m_guardGroups.find(entry.second.groupName);
        const bool groupPaused = (groupIt != m_guardGroups.end() && groupIt->second.paused);
        oss << "\n" << makeGuardSummaryLine(entry.second, restartCount, groupPaused);
    }
    for (const auto &entry : m_persistedGuards)
    {
        const PersistedGuardState &guard = entry.second;
        if (!guard.quarantined || std::find(activeGuardIds.begin(), activeGuardIds.end(), entry.first) != activeGuardIds.end())
        {
            continue;
        }
        const auto policyIt = m_policyByGuardId.find(guard.guardId);
        const int restartCount = (policyIt == m_policyByGuardId.end()) ? 0 : policyIt->second.restartCount;
        const auto groupIt = guard.groupName.empty() ? m_guardGroups.end() : m_guardGroups.find(guard.groupName);
        const bool groupPaused = (groupIt != m_guardGroups.end() && groupIt->second.paused);
        oss << "\n" << makePersistedGuardSummaryLine(guard, restartCount, groupPaused);
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

void PGS::clearFailureState(GuardInfo &guard)
{
    guard.quarantined = false;
    guard.lastFailureCode.clear();
    guard.lastFailure.clear();
    guard.nextRetryMs = 0;
    guard.failureCount = 0;
}

void PGS::clearFailureState(PersistedGuardState &guard)
{
    guard.quarantined = false;
    guard.lastFailureCode.clear();
    guard.lastFailure.clear();
    guard.nextRetryMs = 0;
    guard.failureCount = 0;
}

void PGS::markGuardQuarantined(PersistedGuardState &guard, const std::string &code, const std::string &reason, std::int64_t nowMs)
{
    guard.quarantined = true;
    guard.lastFailureCode = code.empty() ? "restart.failed" : code;
    guard.lastFailure = reason.empty() ? "guard restart failed" : reason;
    guard.nextRetryMs = nowMs > 0 ? nowMs + 60000 : 0;
    if (guard.failureCount < std::numeric_limits<int>::max())
    {
        ++guard.failureCount;
    }
    guard.lastKnownPid = 0;
    guard.intentional = false;
}

void PGS::quarantineGuardLocked(const GuardInfo &guard, const std::string &code, const std::string &reason)
{
    auto &persisted = m_persistedGuards[guard.guardId];
    const int previousFailureCount = persisted.failureCount;
    copyGuardToPersisted(guard, persisted);
    persisted.failureCount = previousFailureCount;
    markGuardQuarantined(persisted, code, reason, currentEpochMs());
    m_guards.erase(guard.pid);
    recordEvent("guard.quarantine",
                "pid=" + std::to_string(guard.pid) +
                ";guard_id=" + std::to_string(guard.guardId) +
                ";path=" + guard.path +
                ";code=" + persisted.lastFailureCode +
                ";reason_b64=" + base64Encode(persisted.lastFailure));
}

std::string PGS::retryQuarantinedGuard(std::uint64_t guardId)
{
    PersistedGuardState persisted;
    {
        std::lock_guard<std::mutex> lock(m_guardsMutex);
        const auto it = m_persistedGuards.find(guardId);
        if (it == m_persistedGuards.end())
        {
            return "ERR guard id not found";
        }
        if (!it->second.quarantined)
        {
            return "ERR guard is not quarantined";
        }
        persisted = it->second;
    }

    GuardInfo desired = desiredGuardFromPersisted(persisted);
    desired.pid = 0;
    desired.handle = nullptr;
    desired.jobHandle = nullptr;
    desired.intentional = false;
    clearFailureState(desired);

    GuardInfo restarted;
    std::string failureCode;
    std::string failureMessage;
    if (!restartGuard(desired, 1, restarted, failureCode, failureMessage))
    {
        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            auto it = m_persistedGuards.find(guardId);
            if (it != m_persistedGuards.end())
            {
                markGuardQuarantined(it->second, failureCode.empty() ? "retry.failed" : failureCode,
                                     failureMessage.empty() ? "manual retry failed" : failureMessage, currentEpochMs());
            }
        }
        persistState();
        recordEvent("guard.retry-failed", "guard_id=" + std::to_string(guardId) + ";path=" + persisted.path);
        return "ERR guard retry failed";
    }

    {
        std::lock_guard<std::mutex> lock(m_guardsMutex);
        auto existing = m_guards.find(restarted.pid);
        if (existing != m_guards.end() && existing->second.handle)
        {
            CloseHandle(existing->second.handle);
        }
        m_guards[restarted.pid] = restarted;
        clearFailureState(m_guards[restarted.pid]);
        assignGuardToJob(m_guards[restarted.pid]);
        auto &policy = m_policyByGuardId[guardId];
        policy.maxRestarts = restarted.maxRestarts;
        policy.restartCount = 0;
        policy.recentRestartMs.clear();
        auto &stored = m_persistedGuards[guardId];
        copyGuardToPersisted(m_guards[restarted.pid], stored);
        clearFailureState(stored);
    }
    persistState();
    recordEvent("guard.retry", "guard_id=" + std::to_string(guardId) + ";pid=" + std::to_string(restarted.pid));
    return "OK guard retried guard_id=" + std::to_string(guardId) + ";pid=" + std::to_string(restarted.pid);
}

std::string PGS::clearQuarantinedGuard(std::uint64_t guardId)
{
    {
        std::lock_guard<std::mutex> lock(m_guardsMutex);
        const auto it = m_persistedGuards.find(guardId);
        if (it == m_persistedGuards.end())
        {
            return "ERR guard id not found";
        }
        if (!it->second.quarantined)
        {
            return "ERR guard is not quarantined";
        }
        m_persistedGuards.erase(it);
        m_policyByGuardId.erase(guardId);
    }
    closeGuardJob(guardId, true);
    persistState();
    recordEvent("guard.clear-quarantine", "guard_id=" + std::to_string(guardId) + ";retired=1");
    return "OK quarantine cleared guard_id=" + std::to_string(guardId) + ";retired=1";
}

std::string PGS::makeGuardSummaryLine(const GuardInfo &guard, int restartCount, bool groupPaused)
{
    const bool alive = (guard.handle && WaitForSingleObject(guard.handle, 0) == WAIT_TIMEOUT);
    const std::string status = guard.quarantined ? "quarantined" :
        ((guard.paused || groupPaused) ? "paused" : (alive ? "active" : "missing"));
    const std::int64_t nowMs = currentEpochMs();
    const std::int64_t cumulativeMs = effectiveCumulativeRunMs(guard, nowMs);
    const std::int64_t avgRestartIntervalMs = guard.restartIntervalCount > 0
        ? guard.restartIntervalSumMs / guard.restartIntervalCount
        : 0;
    std::ostringstream oss;
    oss << "PID=" << guard.pid
        << ";GUARD_ID=" << guard.guardId
        << ";STATUS=" << status
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
        << ";HEALTH_STATUS=" << (guard.healthStatus.empty() ? "disabled" : guard.healthStatus)
        << ";HEALTH_LAST_MESSAGE_B64=" << base64Encode(guard.healthLastMessage)
        << ";HEALTH_LAST_CHECK=" << guard.healthLastCheckMs
        << ";HEALTH_LAST_OK=" << guard.healthLastOkMs
        << ";HEALTH_LAST_FAILURE=" << guard.healthLastFailureMs
        << ";HEALTH_NEXT_CHECK=" << guard.healthNextCheckMs
        << ";HEALTH_FAILURE_COUNT=" << guard.healthFailureCount
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
        << ";RESTART_HOOK_B64=" << base64Encode(guard.restartHookJson)
        << ";QUARANTINED=" << (guard.quarantined ? "1" : "0")
        << ";LAST_FAILURE_CODE=" << (guard.lastFailureCode.empty() ? "-" : guard.lastFailureCode)
        << ";LAST_FAILURE_B64=" << base64Encode(guard.lastFailure)
        << ";NEXT_RETRY_MS=" << guard.nextRetryMs
        << ";FAILURE_COUNT=" << guard.failureCount;
    return oss.str();
}

std::string PGS::makePersistedGuardSummaryLine(const PersistedGuardState &guard, int restartCount, bool groupPaused)
{
    GuardInfo info = desiredGuardFromPersisted(guard);
    info.pid = guard.lastKnownPid;
    info.handle = nullptr;
    info.jobHandle = nullptr;
    return makeGuardSummaryLine(info, restartCount, groupPaused);
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

std::string PGS::handleModulePermissiveCommand(const std::string &rest)
{
    const std::vector<std::string> parts = splitByChar(trim(rest), ' ');
    const std::string action = parts.empty() || trim(parts[0]).empty()
        ? std::string("status")
        : toLowerAscii(trim(parts[0]));
    const auto loaded = m_modules.list().size();
    auto status = [&]() {
        return std::string("OK permissive=") + (m_modulesPermissive.load() ? "1" : "0") +
               ";loaded=" + std::to_string(loaded) +
               ";confirm_required_for_on=1";
    };
    if (action == "status" || action.empty())
    {
        return status();
    }
    if (action == "on" || action == "enable")
    {
        bool confirm = false;
        for (const std::string &part : parts)
        {
            const std::string item = toLowerAscii(trim(part));
            if (item == "--confirm" || item == "confirm=1")
            {
                confirm = true;
                break;
            }
        }
        if (!confirm)
        {
            return "ERR module permissive on requires confirm=1";
        }
        m_modulesPermissive.store(true);
        m_modulesPermissiveUserSet.store(true);
        m_modules.setPermissive(true);
        persistState();
        recordEvent("module.permissive-enabled", "loaded=" + std::to_string(loaded));
        return "OK permissive=1;loaded=" + std::to_string(loaded) + ";persisted=1";
    }
    if (action == "off" || action == "disable")
    {
        m_modulesPermissive.store(false);
        m_modulesPermissiveUserSet.store(true);
        m_modules.setPermissive(false);
        m_modules.ensureAllowlistLoaded(m_modulesDir);
        persistState();
        recordEvent("module.permissive-disabled", "loaded=" + std::to_string(loaded));
        return "OK permissive=0;loaded=" + std::to_string(loaded) + ";persisted=1";
    }
    return "ERR unknown module permissive subcommand";
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

    if (sub == "permissive")
    {
        return handleModulePermissiveCommand(rest);
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
        const std::filesystem::path stagingRoot = service_util::moduleStagingRootForModulesDir(m_modulesDir);
        const bool stagingExists = std::filesystem::exists(stagingRoot);
        const bool managerExists = std::filesystem::exists(root.parent_path() / L"module_managers");
        return std::string("OK modules_dir_b64=") + base64Encode(m_modulesDir) +
               ";modules_allow=" + (allowExists ? "1" : "0") +
               ";modules_lock=" + (lockExists ? "1" : "0") +
               ";modules_staging=" + (stagingExists ? "1" : "0") +
               ";module_managers=" + (managerExists ? "1" : "0") +
               ";permissive=" + (m_modulesPermissive.load() ? "1" : "0") +
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
            if (!entry.is_regular_file() || !service_util::pathHasExtension(entry.path(), ".dll"))
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
        return handleModuleInstallCommand(rest);
    }

    if (sub == "rollback")
    {
        return handleModuleRollbackCommand(rest);
    }
    if (sub == "artifact")
    {
        const auto sp = rest.find(' ');
        std::string action;
        std::string tail;
        if (sp == std::string::npos)
        {
            const std::string only = trim(rest);
            if (only == "chunk" || only == "cleanup" || only == "status" || only == "policy")
            {
                action = only;
            }
            else
            {
                action = "get";
                tail = only;
            }
        }
        else
        {
            action = trim(rest.substr(0, sp));
            tail = trim(rest.substr(sp + 1));
        }
        if (action == "chunk")
        {
            return handleArtifactChunkCommand(tail);
        }
        if (action == "cleanup")
        {
            return handleArtifactCleanupCommand(tail);
        }
        if (action == "status")
        {
            return handleArtifactStatusCommand(tail);
        }
        if (action == "policy")
        {
            return handleArtifactPolicyCommand(tail);
        }
        const std::string artifactId = (action == "get") ? tail : trim(rest);
        if (!isOpaqueId(artifactId, "art_"))
        {
            return "ERR module artifact get requires a valid artifact id";
        }
        const std::string rpc = handleCoreJsonRpc(
            "{\"jsonrpc\":\"2.0\",\"id\":\"artifact-get\",\"method\":\"pgs.artifact.get_meta\",\"params\":{\"artifact_id\":\"" +
            jsonEscapeLocal(artifactId) + "\"}}");
        if (rpc.find("\"result\"") == std::string::npos)
        {
            return "ERR " + rpc;
        }
        const std::string artifactJson = jsonRawValueLocal(rpc, "artifact");
        return "OK artifact_json_b64=" + base64Encode(artifactJson.empty() ? std::string("{}") : artifactJson);
    }

    if (sub == "op-status")
    {
        if (trim(rest).empty())
        {
            return "ERR module op-status requires an operation id";
        }
        const std::string operationId = trim(rest);
        if (!isOpaqueId(operationId, "op_"))
        {
            return "ERR invalid operation id";
        }
        const std::string rpc = handleCoreJsonRpc(
            "{\"jsonrpc\":\"2.0\",\"id\":\"op-status\",\"method\":\"pgs.operation.get\",\"params\":{\"operation_id\":\"" +
            jsonEscapeLocal(operationId) + "\"}}");
        if (rpc.find("\"result\"") == std::string::npos)
        {
            return "ERR " + rpc;
        }
        const std::string operationJson = jsonRawValueLocal(rpc, "operation");
        return "OK operation_json_b64=" + base64Encode(operationJson.empty() ? std::string("{}") : operationJson);
    }

    return "ERR unknown module subcommand";
}

std::string PGS::handleCoreJsonRpc(const std::string &requestJson)
{
    const std::string id = jsonStringValueLocal(requestJson, "id");
    const std::string method = jsonStringValueLocal(requestJson, "method");
    const std::string callerModule = jsonStringValueLocal(requestJson, "__caller_module");
    const std::string paramsRaw = jsonRawValueLocal(requestJson, "params");
    const std::string params = paramsRaw.empty() ? std::string("{}") : paramsRaw;
    const std::int64_t now = epochMs();

    auto cleanupOperationsLocked = [&]() {
        for (auto it = m_operations.begin(); it != m_operations.end(); )
        {
            if (it->second.expiresMs > 0 && it->second.expiresMs <= now)
            {
                it = m_operations.erase(it);
            }
            else
            {
                ++it;
            }
        }
        while (m_operations.size() >= kMaxOperations)
        {
            auto oldest = m_operations.begin();
            for (auto it = m_operations.begin(); it != m_operations.end(); ++it)
            {
                if (it->second.updatedMs < oldest->second.updatedMs)
                {
                    oldest = it;
                }
            }
            m_operations.erase(oldest);
        }
    };

    auto loadArtifactLocked = [&](const std::string &artifactId, ArtifactRecord &out) -> bool {
        const auto existing = m_artifacts.find(artifactId);
        if (existing != m_artifacts.end())
        {
            out = existing->second;
            return true;
        }
        const std::filesystem::path root = artifactRootForStateFile(m_stateFilePath);
        std::string meta;
        if (!readWholeFile(artifactMetaPath(root, artifactId), meta))
        {
            return false;
        }
        if (!artifactRecordFromJson(meta, out))
        {
            return false;
        }
        if (out.id != artifactId)
        {
            return false;
        }
        m_artifacts[out.id] = out;
        return true;
    };

    if (method == "pgs.operation.create")
    {
        if (callerModule.empty())
        {
            return jsonRpcError(id, "CALLER_REQUIRED", "operation.create must be called by a module");
        }
        OperationRecord rec;
        rec.id = makeOpaqueId("op_");
        rec.module = callerModule;
        rec.method = jsonStringValueLocal(params, "method");
        if (rec.method.empty()) rec.method = callerModule + ".operation";
        rec.status = jsonStringValueLocal(params, "status");
        if (rec.status.empty()) rec.status = "accepted";
        if (rec.status != "accepted" && rec.status != "running") rec.status = "accepted";
        rec.progress = static_cast<int>(std::clamp<std::int64_t>(jsonInt64Local(params, "progress", -1), -1, 100));
        rec.message = clampMessage(jsonStringValueLocal(params, "message"));
        rec.createdMs = now;
        rec.updatedMs = now;
        const std::int64_t ttl = std::clamp<std::int64_t>(jsonInt64Local(params, "ttl_ms", kDefaultOperationTtlMs), 60000, kDefaultOperationTtlMs * 7);
        rec.expiresMs = now + ttl;
        rec.traceId = jsonStringValueLocal(params, "trace_id");
        rec.caller = jsonStringValueLocal(params, "caller");
        {
            std::lock_guard<std::mutex> lock(m_operationMutex);
            cleanupOperationsLocked();
            m_operations[rec.id] = rec;
        }
        recordEvent("operation.create", "module=" + rec.module + ";operation_id=" + rec.id + ";method=" + rec.method);
        return jsonRpcResultLocal(id, "{\"operation_id\":\"" + jsonEscapeLocal(rec.id) + "\",\"operation\":" + operationRecordJson(rec) + "}");
    }

    if (method == "pgs.operation.get")
    {
        const std::string operationId = jsonStringValueLocal(params, "operation_id");
        if (!isOpaqueId(operationId, "op_"))
        {
            return jsonRpcError(id, "INVALID_OPERATION_ID", "operation_id is invalid");
        }
        std::lock_guard<std::mutex> lock(m_operationMutex);
        cleanupOperationsLocked();
        const auto it = m_operations.find(operationId);
        if (it == m_operations.end())
        {
            return jsonRpcError(id, "OPERATION_NOT_FOUND", "operation not found or expired");
        }
        if (!callerModule.empty() && callerModule != it->second.module)
        {
            return jsonRpcError(id, "OPERATION_FORBIDDEN", "module cannot read another module's operation");
        }
        return jsonRpcResultLocal(id, "{\"operation\":" + operationRecordJson(it->second) + "}");
    }

    if (method == "pgs.operation.update" || method == "pgs.operation.finish" || method == "pgs.operation.fail")
    {
        if (callerModule.empty())
        {
            return jsonRpcError(id, "CALLER_REQUIRED", "operation mutation must be called by a module");
        }
        const std::string operationId = jsonStringValueLocal(params, "operation_id");
        if (!isOpaqueId(operationId, "op_"))
        {
            return jsonRpcError(id, "INVALID_OPERATION_ID", "operation_id is invalid");
        }
        OperationRecord snapshot;
        {
            std::lock_guard<std::mutex> lock(m_operationMutex);
            cleanupOperationsLocked();
            auto it = m_operations.find(operationId);
            if (it == m_operations.end())
            {
                return jsonRpcError(id, "OPERATION_NOT_FOUND", "operation not found or expired");
            }
            if (callerModule != it->second.module)
            {
                return jsonRpcError(id, "OPERATION_FORBIDDEN", "module cannot mutate another module's operation");
            }
            if (isTerminalOperationStatus(it->second.status))
            {
                return jsonRpcError(id, "OPERATION_TERMINAL", "operation is already terminal");
            }
            if (method == "pgs.operation.update")
            {
                const std::string status = jsonStringValueLocal(params, "status");
                if (status == "accepted" || status == "running") it->second.status = status;
                const std::int64_t progress = jsonInt64Local(params, "progress", it->second.progress);
                it->second.progress = static_cast<int>(std::clamp<std::int64_t>(progress, -1, 100));
                const std::string message = jsonStringValueLocal(params, "message");
                if (!message.empty()) it->second.message = clampMessage(message);
            }
            else if (method == "pgs.operation.finish")
            {
                it->second.status = "succeeded";
                it->second.progress = 100;
                const std::string message = jsonStringValueLocal(params, "message");
                if (!message.empty()) it->second.message = clampMessage(message);
                std::string result = jsonRawValueLocal(params, "result");
                if (result.empty()) result = "{}";
                if (result.size() > 8192)
                {
                    return jsonRpcError(id, "RESULT_TOO_LARGE", "operation result is too large");
                }
                it->second.resultJson = result;
                it->second.artifactIds = jsonStringArrayLocal(params, "artifact_ids");
            }
            else
            {
                it->second.status = "failed";
                it->second.errorCode = jsonStringValueLocal(params, "code");
                if (it->second.errorCode.empty()) it->second.errorCode = "MODULE_ERROR";
                it->second.errorMessage = clampMessage(jsonStringValueLocal(params, "message"));
                it->second.message = it->second.errorMessage;
            }
            it->second.updatedMs = now;
            snapshot = it->second;
        }
        recordEvent("operation." + snapshot.status, "module=" + snapshot.module + ";operation_id=" + snapshot.id);
        return jsonRpcResultLocal(id, "{\"operation\":" + operationRecordJson(snapshot) + "}");
    }

    if (method == "pgs.artifact.put")
    {
        if (callerModule.empty())
        {
            return jsonRpcError(id, "CALLER_REQUIRED", "artifact.put must be called by a module");
        }
        const std::string content = base64Decode(jsonStringValueLocal(params, "content_b64"));
        if (content.size() > kMaxArtifactBytes)
        {
            return jsonRpcError(id, "ARTIFACT_TOO_LARGE", "artifact exceeds max size");
        }
        std::int64_t policyTtlMs = kDefaultOperationTtlMs;
        bool autoCleanup = true;
        {
            std::lock_guard<std::mutex> lock(m_artifactMutex);
            policyTtlMs = m_artifactRetentionTtlMs;
            autoCleanup = m_artifactAutoCleanup;
        }
        ArtifactRecord rec;
        rec.id = makeOpaqueId("art_");
        rec.module = callerModule;
        rec.method = jsonStringValueLocal(params, "method");
        if (rec.method.empty()) rec.method = callerModule + ".artifact";
        rec.contentType = jsonStringValueLocal(params, "content_type");
        if (rec.contentType.empty()) rec.contentType = "application/octet-stream";
        rec.filename = safeDisplayFilename(jsonStringValueLocal(params, "filename"));
        rec.sensitivity = jsonStringValueLocal(params, "sensitivity");
        const bool explicitSensitive = parseJsonBoolLocal(params, "sensitive", false);
        rec.size = static_cast<std::uint64_t>(content.size());
        rec.sha256 = sha256Hex(content);
        rec.storageHash = rec.sha256;
        rec.storageHashVerified = true;
        rec.createdMs = now;
        const std::int64_t requestedTtl = jsonInt64Local(params, "ttl_ms", policyTtlMs);
        if (rec.sensitivity.empty())
        {
            rec.sensitivity = defaultArtifactSensitivity(rec);
        }
        rec.sensitive = explicitSensitive || !rec.sensitivity.empty();
        std::int64_t ttlCap = kMaxArtifactRetentionTtlMs;
        if (rec.sensitivity == "high")
        {
            ttlCap = 6LL * 60LL * 60LL * 1000LL;
        }
        else if (rec.sensitivity == "medium")
        {
            ttlCap = 24LL * 60LL * 60LL * 1000LL;
        }
        const std::int64_t ttl = std::clamp<std::int64_t>(requestedTtl, kMinArtifactRetentionTtlMs, ttlCap);
        rec.expiresMs = now + ttl;
        rec.traceId = jsonStringValueLocal(params, "trace_id");
        rec.operationId = jsonStringValueLocal(params, "operation_id");
        if (!rec.operationId.empty() && !isOpaqueId(rec.operationId, "op_"))
        {
            return jsonRpcError(id, "INVALID_OPERATION_ID", "operation_id is invalid");
        }
        if (!rec.operationId.empty())
        {
            std::lock_guard<std::mutex> lock(m_operationMutex);
            cleanupOperationsLocked();
            const auto opIt = m_operations.find(rec.operationId);
            if (opIt == m_operations.end())
            {
                return jsonRpcError(id, "OPERATION_NOT_FOUND", "operation not found or expired");
            }
            if (opIt->second.module != callerModule)
            {
                return jsonRpcError(id, "OPERATION_FORBIDDEN", "module cannot attach artifact to another module's operation");
            }
        }
        const std::filesystem::path root = artifactRootForStateFile(m_stateFilePath);
        if (!secureCreateDirectory(root.string()))
        {
            return jsonRpcError(id, "ARTIFACT_STORE_UNAVAILABLE", "failed to secure artifact directory");
        }
        if (autoCleanup)
        {
            std::string cleanupDetail;
            std::lock_guard<std::mutex> lock(m_artifactMutex);
            cleanupArtifactsLocked(true, false, false, cleanupDetail);
        }
        std::uint64_t totalBytes = 0;
        std::error_code ec;
        for (const auto &entry : std::filesystem::directory_iterator(root, ec))
        {
            if (entry.is_regular_file(ec) && entry.path().extension() == L".bin")
            {
                totalBytes += static_cast<std::uint64_t>(entry.file_size(ec));
            }
        }
        if (totalBytes + rec.size > kMaxArtifactTotalBytes)
        {
            return jsonRpcError(id, "ARTIFACT_STORE_FULL", "artifact store total size limit reached");
        }
        const std::filesystem::path contentPath = artifactContentPath(root, rec.id);
        const std::filesystem::path metaPath = artifactMetaPath(root, rec.id);
        if (!writeWholeFile(contentPath, content) || !writeWholeFile(metaPath, artifactRecordJson(rec)))
        {
            std::filesystem::remove(contentPath, ec);
            std::filesystem::remove(metaPath, ec);
            return jsonRpcError(id, "ARTIFACT_WRITE_FAILED", "failed to write artifact");
        }
        secureApplyDacl(contentPath.string(), false);
        secureApplyDacl(metaPath.string(), false);
        {
            std::lock_guard<std::mutex> lock(m_artifactMutex);
            m_artifacts[rec.id] = rec;
        }
        if (!rec.operationId.empty())
        {
            std::lock_guard<std::mutex> lock(m_operationMutex);
            auto it = m_operations.find(rec.operationId);
            if (it != m_operations.end() && it->second.module == callerModule)
            {
                it->second.artifactIds.push_back(rec.id);
                it->second.updatedMs = now;
            }
        }
        recordEvent("artifact.put", "module=" + rec.module + ";artifact_id=" + rec.id + ";size=" + std::to_string(rec.size) +
                                 ";sensitive=" + (rec.sensitive ? std::string("1") : std::string("0")) +
                                 ";sensitivity=" + rec.sensitivity + ";ttl_ms=" + std::to_string(ttl));
        return jsonRpcResultLocal(id, "{\"artifact_id\":\"" + jsonEscapeLocal(rec.id) + "\",\"artifact\":" + artifactRecordJson(rec) + "}");
    }

    if (method == "pgs.artifact.get_meta")
    {
        const std::string artifactId = jsonStringValueLocal(params, "artifact_id");
        if (!isOpaqueId(artifactId, "art_"))
        {
            return jsonRpcError(id, "INVALID_ARTIFACT_ID", "artifact_id is invalid");
        }
        ArtifactRecord rec;
        {
            std::lock_guard<std::mutex> lock(m_artifactMutex);
            if (!loadArtifactLocked(artifactId, rec))
            {
                return jsonRpcError(id, "ARTIFACT_NOT_FOUND", "artifact not found");
            }
        }
        if (rec.expiresMs > 0 && rec.expiresMs <= now)
        {
            return jsonRpcError(id, "ARTIFACT_EXPIRED", "artifact expired");
        }
        if (!callerModule.empty() && callerModule != rec.module)
        {
            return jsonRpcError(id, "ARTIFACT_FORBIDDEN", "module cannot read another module's artifact");
        }
        return jsonRpcResultLocal(id, "{\"artifact\":" + artifactRecordJson(rec) + "}");
    }

    return jsonRpcError(id, "METHOD_NOT_FOUND", "unknown PGS core JSON method");
}

PGS::ArtifactStoreStatus PGS::artifactStoreStatusLocked(bool verifyContentHash, std::string &detail)
{
    ArtifactStoreStatus status;
    detail.clear();
    const std::int64_t now = epochMs();
    const std::filesystem::path root = artifactRootForStateFile(m_stateFilePath);
    std::error_code ec;
    status.storeExists = std::filesystem::exists(root, ec);
    if (!status.storeExists)
    {
        return status;
    }
    status.rootSecured = secureApplyDacl(root.string(), true);

    std::unordered_set<std::string> metaIds;
    for (const auto &entry : std::filesystem::directory_iterator(root, ec))
    {
        if (ec || !entry.is_regular_file(ec) || entry.path().extension() != L".json")
        {
            continue;
        }
        std::string meta;
        ArtifactRecord rec;
        if (!readWholeFile(entry.path(), meta) || !artifactRecordFromJson(meta, rec))
        {
            ++status.corrupt;
            appendCleanupDetail(detail, wideToUtf8(entry.path().filename().wstring()) + ":bad-meta");
            continue;
        }
        const std::string fileArtifactId = wideToUtf8(entry.path().stem().wstring());
        if (rec.id != fileArtifactId)
        {
            ++status.corrupt;
            appendCleanupDetail(detail, fileArtifactId + ":id-mismatch");
            continue;
        }
        metaIds.insert(rec.id);
        m_artifacts[rec.id] = rec;
        ++status.count;
        if (rec.sensitive)
        {
            ++status.sensitive;
        }
        if (rec.expiresMs > 0 && rec.expiresMs <= now)
        {
            ++status.expired;
        }
        const std::filesystem::path contentPath = artifactContentPath(root, rec.id);
        const std::uint64_t actualSize = regularFileSize(contentPath);
        status.totalBytes += actualSize;
        if (actualSize == 0 && rec.size != 0)
        {
            ++status.corrupt;
            appendCleanupDetail(detail, rec.id + ":missing-content");
            continue;
        }
        if (verifyContentHash)
        {
            std::string actualHash;
            const bool hashOk = sha256FileHex(wideToUtf8(contentPath.wstring()), actualHash);
            actualHash = toLowerAscii(actualHash);
            if (actualSize != rec.size || !hashOk || actualHash != toLowerAscii(rec.sha256))
            {
                ++status.corrupt;
                appendCleanupDetail(detail, rec.id + ":hash-mismatch");
            }
            else
            {
                rec.storageHash = actualHash;
                rec.storageHashVerified = true;
                m_artifacts[rec.id] = rec;
                writeWholeFile(artifactMetaPath(root, rec.id), artifactRecordJson(rec));
                ++status.verified;
            }
        }
    }

    for (const auto &entry : std::filesystem::directory_iterator(root, ec))
    {
        if (ec || !entry.is_regular_file(ec) || entry.path().extension() != L".bin")
        {
            continue;
        }
        const std::string artifactId = wideToUtf8(entry.path().stem().wstring());
        if (!isOpaqueId(artifactId, "art_") || metaIds.find(artifactId) == metaIds.end())
        {
            ++status.orphaned;
            status.totalBytes += regularFileSize(entry.path());
            appendCleanupDetail(detail, artifactId + ":orphan");
        }
    }
    return status;
}

void PGS::loadArtifactPolicyLocked()
{
    m_artifactRetentionTtlMs = kDefaultOperationTtlMs;
    m_artifactAutoCleanup = true;
    m_artifactVerifyOnStatus = false;
    std::string body;
    if (!readWholeFile(artifactPolicyPathForStateFile(m_stateFilePath), body))
    {
        return;
    }
    for (const std::string &line : splitByChar(body, '\n'))
    {
        const std::string item = trim(line);
        if (item.empty() || item[0] == '#')
        {
            continue;
        }
        const std::size_t eq = item.find('=');
        if (eq == std::string::npos)
        {
            continue;
        }
        const std::string key = toLowerAscii(trim(item.substr(0, eq)));
        const std::string value = trim(item.substr(eq + 1));
        if (key == "ttl_ms")
        {
            std::int64_t ttl = 0;
            if (parseTtlMsText(value, ttl))
            {
                m_artifactRetentionTtlMs = ttl;
            }
        }
        else if (key == "auto_cleanup")
        {
            bool parsed = false;
            if (parseArtifactBoolText(value, parsed))
            {
                m_artifactAutoCleanup = parsed;
            }
        }
        else if (key == "verify_on_status")
        {
            bool parsed = false;
            if (parseArtifactBoolText(value, parsed))
            {
                m_artifactVerifyOnStatus = parsed;
            }
        }
    }
}

bool PGS::saveArtifactPolicyLocked(std::string &error) const
{
    error.clear();
    const std::filesystem::path policyPath = artifactPolicyPathForStateFile(m_stateFilePath);
    std::error_code ec;
    if (!policyPath.parent_path().empty())
    {
        std::filesystem::create_directories(policyPath.parent_path(), ec);
        if (ec)
        {
            error = "failed to create artifact policy directory";
            return false;
        }
    }
    const std::string body = "ttl_ms=" + std::to_string(m_artifactRetentionTtlMs) + "\n" +
                             "auto_cleanup=" + std::string(m_artifactAutoCleanup ? "1" : "0") + "\n" +
                             "verify_on_status=" + std::string(m_artifactVerifyOnStatus ? "1" : "0") + "\n";
    if (!writeWholeFile(policyPath, body))
    {
        error = "failed to write artifact policy";
        return false;
    }
    secureApplyDacl(policyPath.string(), false);
    return true;
}

std::string PGS::artifactPolicySummaryLocked() const
{
    return artifactPolicySummaryValues(m_artifactRetentionTtlMs, m_artifactAutoCleanup, m_artifactVerifyOnStatus);
}

PGS::ArtifactCleanupResult PGS::cleanupArtifactsLocked(bool removeExpired, bool removeAll, bool verifyContentHash, std::string &detail)
{
    ArtifactCleanupResult result;
    detail.clear();
    const std::int64_t now = epochMs();
    const std::filesystem::path root = artifactRootForStateFile(m_stateFilePath);
    std::error_code ec;
    if (!std::filesystem::exists(root, ec))
    {
        return result;
    }

    for (const auto &entry : std::filesystem::directory_iterator(root, ec))
    {
        if (ec || !entry.is_regular_file(ec) || entry.path().extension() != L".json")
        {
            continue;
        }
        std::string meta;
        ArtifactRecord rec;
        const std::string fileArtifactId = wideToUtf8(entry.path().stem().wstring());
        if (readWholeFile(entry.path(), meta) && artifactRecordFromJson(meta, rec) && rec.id == fileArtifactId)
        {
            m_artifacts[rec.id] = rec;
        }
        else if (removeAll || verifyContentHash)
        {
            std::filesystem::remove(entry.path(), ec);
            ++result.corruptRemoved;
            appendCleanupDetail(detail, fileArtifactId + ":bad-meta");
        }
    }

    for (auto it = m_artifacts.begin(); it != m_artifacts.end(); )
    {
        ArtifactRecord rec = it->second;
        bool remove = false;
        bool corrupt = false;
        std::string reason;

        if (removeAll)
        {
            remove = true;
            reason = "all";
        }
        else if (removeExpired && rec.expiresMs > 0 && rec.expiresMs <= now)
        {
            remove = true;
            reason = "expired";
        }
        else if (verifyContentHash)
        {
            const std::filesystem::path contentPath = artifactContentPath(root, rec.id);
            const std::uint64_t actualSize = regularFileSize(contentPath);
            std::string actualHash;
            const bool hashOk = sha256FileHex(wideToUtf8(contentPath.wstring()), actualHash);
            actualHash = toLowerAscii(actualHash);
            if (actualSize != rec.size || !hashOk || actualHash != toLowerAscii(rec.sha256))
            {
                remove = true;
                corrupt = true;
                reason = "corrupt";
            }
            else
            {
                rec.storageHash = actualHash;
                rec.storageHashVerified = true;
                it->second = rec;
                writeWholeFile(artifactMetaPath(root, rec.id), artifactRecordJson(rec));
                ++result.verified;
            }
        }

        if (remove)
        {
            removeArtifactFiles(root, rec.id, result);
            if (corrupt)
            {
                ++result.corruptRemoved;
            }
            appendCleanupDetail(detail, rec.id + ":" + reason);
            it = m_artifacts.erase(it);
            continue;
        }
        ++it;
    }

    if (removeExpired || removeAll)
    {
        for (const auto &entry : std::filesystem::directory_iterator(root, ec))
        {
            if (ec || !entry.is_regular_file(ec) || entry.path().extension() != L".bin")
            {
                continue;
            }
            const std::string artifactId = wideToUtf8(entry.path().stem().wstring());
            if (!isOpaqueId(artifactId, "art_") || m_artifacts.find(artifactId) == m_artifacts.end())
            {
                removeArtifactFiles(root, artifactId, result);
                appendCleanupDetail(detail, artifactId + ":orphan");
            }
        }
    }

    return result;
}

void PGS::runArtifactMaintenanceIfDue(std::int64_t nowMs)
{
    constexpr std::int64_t kArtifactMaintenanceIntervalMs = 5LL * 60LL * 1000LL;
    ArtifactCleanupResult result;
    std::string detail;
    {
        std::lock_guard<std::mutex> lock(m_artifactMutex);
        if (!m_artifactAutoCleanup)
        {
            return;
        }
        if (m_lastArtifactMaintenanceMs > 0 && nowMs - m_lastArtifactMaintenanceMs < kArtifactMaintenanceIntervalMs)
        {
            return;
        }
        m_lastArtifactMaintenanceMs = nowMs;
        result = cleanupArtifactsLocked(true, false, false, detail);
    }
    if (result.removed > 0 || result.corruptRemoved > 0)
    {
        recordEvent("artifact.maintenance-cleanup", "removed=" + std::to_string(result.removed) +
                                                  ";sensitive_removed=" + std::to_string(result.sensitiveRemoved) +
                                                  ";reclaimed_bytes=" + std::to_string(result.reclaimedBytes) +
                                                  (detail.empty() ? std::string() : ";detail=" + detail));
    }
}

std::string PGS::handleArtifactCleanupCommand(const std::string &args)
{
    const std::string trimmed = trim(args);
    bool removeExpired = true;
    bool removeAll = false;
    bool verifyContentHash = false;
    if (!trimmed.empty())
    {
        const std::vector<std::string> parts = splitByChar(trimmed, ' ');
        for (const auto &part : parts)
        {
            const std::string opt = toLowerAscii(trim(part));
            if (opt == "--all")
            {
                removeAll = true;
                removeExpired = true;
                continue;
            }
            if (opt == "--verify" || opt == "--check-hash")
            {
                verifyContentHash = true;
                continue;
            }
            if (opt == "--expired")
            {
                removeExpired = true;
                continue;
            }
            if (opt == "--help")
            {
                return "OK artifact cleanup options: --expired --all --verify";
            }
            return "ERR unknown artifact cleanup option";
        }
    }
    std::string detail;
    ArtifactCleanupResult result;
    {
        std::lock_guard<std::mutex> lock(m_artifactMutex);
        result = cleanupArtifactsLocked(removeExpired, removeAll, verifyContentHash, detail);
    }
    recordEvent("artifact.cleanup", "removed=" + std::to_string(result.removed) +
                                      ";verified=" + std::to_string(result.verified) +
                                      ";corrupt_removed=" + std::to_string(result.corruptRemoved) +
                                      ";sensitive_removed=" + std::to_string(result.sensitiveRemoved));
    std::ostringstream out;
    out << "OK artifact cleanup removed=" << result.removed
        << ";verified=" << result.verified
        << ";corrupt_removed=" << result.corruptRemoved
        << ";sensitive_removed=" << result.sensitiveRemoved
        << ";reclaimed_bytes=" << result.reclaimedBytes;
    if (!detail.empty())
    {
        out << ";detail=" << detail;
    }
    return out.str();
}

std::string PGS::handleArtifactStatusCommand(const std::string &args)
{
    bool verifyContentHash = false;
    const std::vector<std::string> parts = splitByChar(trim(args), ' ');
    for (const auto &part : parts)
    {
        const std::string opt = toLowerAscii(trim(part));
        if (opt.empty())
        {
            continue;
        }
        if (opt == "--verify" || opt == "--check-hash")
        {
            verifyContentHash = true;
            continue;
        }
        if (opt == "--help")
        {
            return "OK artifact status options: --verify";
        }
        return "ERR unknown artifact status option";
    }
    ArtifactStoreStatus status;
    std::string detail;
    std::int64_t ttlMs = kDefaultOperationTtlMs;
    bool autoCleanup = true;
    bool verifyOnStatus = false;
    {
        std::lock_guard<std::mutex> lock(m_artifactMutex);
        const bool effectiveVerify = verifyContentHash || m_artifactVerifyOnStatus;
        status = artifactStoreStatusLocked(effectiveVerify, detail);
        ttlMs = m_artifactRetentionTtlMs;
        autoCleanup = m_artifactAutoCleanup;
        verifyOnStatus = m_artifactVerifyOnStatus;
    }
    const std::string statusJson = artifactStatusJson(status, ttlMs, autoCleanup, verifyOnStatus);
    std::ostringstream out;
    out << "OK artifact status store_exists=" << (status.storeExists ? "1" : "0")
        << ";root_secured=" << (status.rootSecured ? "1" : "0")
        << ";count=" << status.count
        << ";total_bytes=" << status.totalBytes
        << ";expired=" << status.expired
        << ";corrupt=" << status.corrupt
        << ";orphaned=" << status.orphaned
        << ";sensitive=" << status.sensitive
        << ";verified=" << status.verified
        << ";ttl_ms=" << ttlMs
        << ";auto_cleanup=" << (autoCleanup ? "1" : "0")
        << ";verify_on_status=" << (verifyOnStatus ? "1" : "0")
        << ";artifact_status_json_b64=" << base64Encode(statusJson);
    if (!detail.empty())
    {
        out << ";detail=" << detail;
    }
    return out.str();
}

std::string PGS::handleArtifactPolicyCommand(const std::string &args)
{
    std::int64_t ttlMs = 0;
    bool hasTtl = false;
    bool autoCleanup = false;
    bool hasAutoCleanup = false;
    bool verifyOnStatus = false;
    bool hasVerifyOnStatus = false;
    const std::vector<std::string> parts = splitByChar(trim(args), ' ');
    for (std::size_t i = 0; i < parts.size(); ++i)
    {
        const std::string opt = toLowerAscii(trim(parts[i]));
        if (opt.empty())
        {
            continue;
        }
        if (opt == "--ttl-ms")
        {
            if (i + 1 >= parts.size() || !parseTtlMsText(parts[++i], ttlMs))
            {
                return "ERR artifact policy --ttl-ms must be 60000..604800000";
            }
            hasTtl = true;
            continue;
        }
        if (opt == "--auto-cleanup")
        {
            autoCleanup = true;
            hasAutoCleanup = true;
            continue;
        }
        if (opt == "--no-auto-cleanup")
        {
            autoCleanup = false;
            hasAutoCleanup = true;
            continue;
        }
        if (opt == "--verify-on-status")
        {
            verifyOnStatus = true;
            hasVerifyOnStatus = true;
            continue;
        }
        if (opt == "--no-verify-on-status")
        {
            verifyOnStatus = false;
            hasVerifyOnStatus = true;
            continue;
        }
        if (opt == "--help")
        {
            return "OK artifact policy options: --ttl-ms N --auto-cleanup --no-auto-cleanup --verify-on-status --no-verify-on-status";
        }
        return "ERR unknown artifact policy option";
    }
    std::string policySummary;
    std::string policyJson;
    {
        std::lock_guard<std::mutex> lock(m_artifactMutex);
        if (hasTtl)
        {
            m_artifactRetentionTtlMs = ttlMs;
        }
        if (hasAutoCleanup)
        {
            m_artifactAutoCleanup = autoCleanup;
        }
        if (hasVerifyOnStatus)
        {
            m_artifactVerifyOnStatus = verifyOnStatus;
        }
        if (hasTtl || hasAutoCleanup || hasVerifyOnStatus)
        {
            std::string error;
            if (!saveArtifactPolicyLocked(error))
            {
                return "ERR " + error;
            }
        }
        policySummary = artifactPolicySummaryLocked();
        policyJson = artifactPolicyJson(m_artifactRetentionTtlMs, m_artifactAutoCleanup, m_artifactVerifyOnStatus);
    }
    if (hasTtl || hasAutoCleanup || hasVerifyOnStatus)
    {
        recordEvent("artifact.policy", policySummary);
    }
    return "OK artifact policy " + policySummary + ";artifact_policy_json_b64=" + base64Encode(policyJson);
}

std::string PGS::handleArtifactChunkCommand(const std::string &args)
{
    const std::vector<std::string> parts = splitByChar(trim(args), ' ');
    if (parts.size() < 3)
    {
        return "ERR module artifact chunk requires <artifact-id> <offset> <max-bytes>";
    }
    const std::string artifactId = parts[0];
    if (!isOpaqueId(artifactId, "art_"))
    {
        return "ERR invalid artifact id";
    }
    std::uint64_t offset = 0;
    std::uint64_t maxBytes = 0;
    if (!parseUnsignedLongLong(parts[1], offset) || !parseUnsignedLongLong(parts[2], maxBytes) || maxBytes == 0)
    {
        return "ERR invalid artifact chunk range";
    }
    maxBytes = std::min<std::uint64_t>(maxBytes, kMaxArtifactChunkBytes);
    const std::filesystem::path root = artifactRootForStateFile(m_stateFilePath);
    ArtifactRecord rec;
    {
        std::lock_guard<std::mutex> lock(m_artifactMutex);
        const auto existing = m_artifacts.find(artifactId);
        if (existing != m_artifacts.end())
        {
            rec = existing->second;
        }
        else
        {
            std::string meta;
            if (!readWholeFile(artifactMetaPath(root, artifactId), meta) || !artifactRecordFromJson(meta, rec))
            {
                return "ERR artifact not found";
            }
            m_artifacts[rec.id] = rec;
        }
    }
    const std::int64_t now = epochMs();
    if (rec.expiresMs > 0 && rec.expiresMs <= now)
    {
        recordEvent("artifact.download-expired", "artifact_id=" + artifactId + ";offset=" + std::to_string(offset));
        return "ERR artifact expired";
    }
    if (offset > rec.size)
    {
        recordEvent("artifact.download-invalid", "artifact_id=" + artifactId + ";offset=" + std::to_string(offset));
        return "ERR artifact offset beyond end";
    }
    const std::filesystem::path contentPath = artifactContentPath(root, artifactId);
    const std::uint64_t actualSize = regularFileSize(contentPath);
    std::string actualHash;
    const bool hashOk = sha256FileHex(wideToUtf8(contentPath.wstring()), actualHash);
    actualHash = toLowerAscii(actualHash);
    if (actualSize != rec.size || !hashOk || actualHash != toLowerAscii(rec.sha256))
    {
        recordEvent("artifact.integrity-failed", "artifact_id=" + artifactId);
        return "ERR artifact content hash mismatch";
    }
    if (!rec.storageHashVerified || rec.storageHash != actualHash)
    {
        rec.storageHash = actualHash;
        rec.storageHashVerified = true;
        std::lock_guard<std::mutex> lock(m_artifactMutex);
        m_artifacts[rec.id] = rec;
        writeWholeFile(artifactMetaPath(root, rec.id), artifactRecordJson(rec));
    }
    const std::uint64_t toRead = std::min<std::uint64_t>(maxBytes, rec.size - offset);
    std::string data(static_cast<std::size_t>(toRead), '\0');
    std::ifstream in(contentPath, std::ios::in | std::ios::binary);
    if (!in.is_open())
    {
        return "ERR artifact content missing";
    }
    in.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (toRead > 0)
    {
        in.read(&data[0], static_cast<std::streamsize>(toRead));
        data.resize(static_cast<std::size_t>(std::max<std::streamsize>(0, in.gcount())));
    }
    const std::uint64_t nextOffset = offset + static_cast<std::uint64_t>(data.size());
    if (offset == 0)
    {
        recordEvent("artifact.download-start", "artifact_id=" + artifactId +
                                             ";size=" + std::to_string(rec.size) +
                                             ";sensitive=" + (rec.sensitive ? std::string("1") : std::string("0")) +
                                             ";sensitivity=" + rec.sensitivity);
    }
    if (nextOffset >= rec.size)
    {
        recordEvent("artifact.download-complete", "artifact_id=" + artifactId +
                                                ";bytes=" + std::to_string(nextOffset) +
                                                ";sha256=" + actualHash +
                                                ";sensitive=" + (rec.sensitive ? std::string("1") : std::string("0")));
    }
    return "OK id=" + artifactId +
           ";offset=" + std::to_string(offset) +
           ";size=" + std::to_string(data.size()) +
           ";total=" + std::to_string(rec.size) +
           ";eof=" + (nextOffset >= rec.size ? std::string("1") : std::string("0")) +
           ";data_b64=" + base64Encode(data);
}

std::string PGS::handleGuardCommand(const std::string &args)
{
    const auto spacePos = args.find(' ');
    const std::string sub = (spacePos == std::string::npos) ? trim(args) : trim(args.substr(0, spacePos));
    const std::string rest = (spacePos == std::string::npos) ? std::string() : trim(args.substr(spacePos + 1));
    if (sub == "retry" || sub == "clear-quarantine")
    {
        std::uint64_t guardId = 0;
        if (!util::parseUnsignedLongLong(rest, guardId) || guardId == 0)
        {
            return "ERR guard " + sub + " requires <guard-id>";
        }
        return sub == "retry" ? retryQuarantinedGuard(guardId) : clearQuarantinedGuard(guardId);
    }
    return "ERR unknown guard subcommand";
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
        return "OK health_check_b64=" + base64Encode(it->second.healthCheckJson) +
               ";status=" + (it->second.healthStatus.empty() ? "disabled" : it->second.healthStatus) +
               ";last_message_b64=" + base64Encode(it->second.healthLastMessage) +
               ";last_check=" + std::to_string(it->second.healthLastCheckMs) +
               ";last_ok=" + std::to_string(it->second.healthLastOkMs) +
               ";last_failure=" + std::to_string(it->second.healthLastFailureMs) +
               ";next_check=" + std::to_string(it->second.healthNextCheckMs) +
               ";failure_count=" + std::to_string(it->second.healthFailureCount);
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
        std::string validationError;
        if (!validateHealthCheckConfig(configJson, validationError))
        {
            return "ERR invalid health-check config: " + validationError;
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
        resetHealthRuntimeState(it->second);
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
        m_healthCv.notify_all();
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
    {
        std::lock_guard<std::mutex> lock(m_eventsMutex);
        m_events.push_back(line);
        while (m_events.size() > kMaxEventHistory)
        {
            m_events.pop_front();
        }
    }
    if (type.rfind("notify.", 0) != 0)
    {
        std::lock_guard<std::mutex> lock(m_notifyMutex);
        if (m_notifyQueue.size() >= kMaxEventHistory)
        {
            m_notifyQueue.pop();
        }
        m_notifyQueue.emplace(type, detail);
        m_notifyCv.notify_one();
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
