#ifndef PGS_PROTOCOL_INTERNAL_H
#define PGS_PROTOCOL_INTERNAL_H

// File-local helpers shared by the pgs_core protocol translation units
// (PGSProtocol.cpp and PGSOperationStore.cpp). Everything here used to live
// in the anonymous namespace of PGSProtocol.cpp; it was promoted to inline
// definitions in namespace pgs_protocol when the protocol layer was split.

#include "Process_Guard/PGS.h"
#include "PGSServiceHelpers.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace ProcessGuard
{
namespace pgs_protocol
{

using namespace util;
inline std::string jsonEscapeLocal(const std::string &value)
{
    return service_util::jsonEscape(value);
}
inline std::string jsonStringValueLocal(const std::string &text, const std::string &key)
{
    return service_util::jsonStringValue(text, key);
}
inline std::string jsonRpcError(const std::string &id, const std::string &code, const std::string &message)
{
    return service_util::jsonRpcError(id, code, message);
}
inline std::string jsonRpcRequest(const std::string &module, const std::string &method, const std::string &paramsJsonB64)
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
inline std::int64_t epochMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

constexpr std::int64_t kDefaultOperationTtlMs = 24LL * 60LL * 60LL * 1000LL;
constexpr std::int64_t kMinArtifactRetentionTtlMs = 60LL * 1000LL;
constexpr std::int64_t kMaxArtifactRetentionTtlMs = 7LL * 24LL * 60LL * 60LL * 1000LL;
constexpr std::size_t kMaxOperations = 1024;
constexpr std::uint64_t kDefaultArtifactBytes = 16ull * 1024ull * 1024ull;
constexpr std::uint64_t kDefaultArtifactTotalBytes = 256ull * 1024ull * 1024ull;
constexpr std::uint64_t kMinArtifactBytes = 64ull * 1024ull;
constexpr std::uint64_t kMaxArtifactBytesLimit = 64ull * 1024ull * 1024ull;
constexpr std::uint64_t kMinArtifactTotalBytes = 1024ull * 1024ull;
constexpr std::uint64_t kMaxArtifactTotalBytesLimit = 1024ull * 1024ull * 1024ull;
constexpr std::uint64_t kMaxArtifactChunkBytes = 32768ull;
inline bool isOpaqueId(const std::string &id, const std::string &prefix)
{
    return service_util::isOpaqueId(id, prefix);
}
inline std::string jsonRawValueLocal(const std::string &text, const std::string &key)
{
    return service_util::jsonRawValue(text, key);
}
inline std::vector<std::string> jsonStringArrayLocal(const std::string &text, const std::string &key)
{
    return service_util::jsonStringArray(text, key);
}
inline std::int64_t jsonInt64Local(const std::string &text, const std::string &key, std::int64_t fallback)
{
    return service_util::jsonInt64(text, key, fallback);
}
inline std::string safeDisplayFilename(std::string value)
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
inline std::string defaultArtifactSensitivity(const PGS::ArtifactRecord &rec)
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
inline bool parseJsonBoolLocal(const std::string &text, const std::string &key, bool fallback = false)
{
    const std::string value = toLowerAscii(trim(jsonRawValueLocal(text, key)));
    if (value == "true" || value == "1") return true;
    if (value == "false" || value == "0") return false;
    return fallback;
}
inline std::filesystem::path artifactRootForStateFile(const std::string &stateFilePath)
{
    std::filesystem::path root = std::filesystem::path(stateFilePath).parent_path();
    if (root.empty()) root = L".";
    return root / L"artifacts";
}
inline std::filesystem::path artifactPolicyPathForStateFile(const std::string &stateFilePath)
{
    std::filesystem::path root = std::filesystem::path(stateFilePath).parent_path();
    if (root.empty()) root = L".";
    return root / L"artifact_policy.cfg";
}
inline std::filesystem::path artifactContentPath(const std::filesystem::path &root, const std::string &id)
{
    return root / utf8ToWide(id + ".bin");
}
inline std::filesystem::path artifactMetaPath(const std::filesystem::path &root, const std::string &id)
{
    return root / utf8ToWide(id + ".json");
}
inline std::string artifactRecordJson(const PGS::ArtifactRecord &rec)
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
inline std::string operationRecordJson(const PGS::OperationRecord &rec)
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
inline std::string jsonRpcResultLocal(const std::string &id, const std::string &resultJson)
{
    return service_util::jsonRpcResult(id, resultJson);
}
inline bool artifactRecordFromJson(const std::string &json, PGS::ArtifactRecord &rec)
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
inline bool readWholeFile(const std::filesystem::path &path, std::string &out)
{
    return service_util::readWholeFile(path, out);
}
inline bool writeWholeFile(const std::filesystem::path &path, const std::string &data)
{
    return service_util::writeWholeFile(path, data);
}
inline std::string makeOpaqueId(const std::string &prefix)
{
    std::string hex = randomBytesHex(16);
    if (hex.empty())
    {
        hex = sha256Hex(prefix + std::to_string(epochMs())).substr(0, 32);
    }
    return prefix + hex;
}
inline std::uint64_t regularFileSize(const std::filesystem::path &path)
{
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec))
    {
        return 0;
    }
    return static_cast<std::uint64_t>(std::filesystem::file_size(path, ec));
}
inline void removeArtifactFiles(const std::filesystem::path &root, const std::string &artifactId, PGS::ArtifactCleanupResult &result)
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
inline void appendCleanupDetail(std::string &detail, const std::string &item)
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
inline std::string artifactPolicySummaryValues(std::int64_t ttlMs, bool autoCleanup, bool verifyOnStatus,
                                        std::uint64_t maxArtifactBytes, std::uint64_t maxTotalBytes)
{
    return "ttl_ms=" + std::to_string(ttlMs) +
           ";auto_cleanup=" + (autoCleanup ? std::string("1") : std::string("0")) +
           ";verify_on_status=" + (verifyOnStatus ? std::string("1") : std::string("0")) +
           ";max_artifact_bytes=" + std::to_string(maxArtifactBytes) +
           ";max_total_bytes=" + std::to_string(maxTotalBytes);
}
inline std::string artifactPolicyJson(std::int64_t ttlMs, bool autoCleanup, bool verifyOnStatus,
                               std::uint64_t maxArtifactBytes, std::uint64_t maxTotalBytes)
{
    return "{\"ttl_ms\":" + std::to_string(ttlMs) +
           ",\"auto_cleanup\":" + std::string(autoCleanup ? "true" : "false") +
           ",\"verify_on_status\":" + std::string(verifyOnStatus ? "true" : "false") +
           ",\"max_artifact_bytes\":" + std::to_string(maxArtifactBytes) +
           ",\"max_total_bytes\":" + std::to_string(maxTotalBytes) + "}";
}
inline std::string artifactStatusJson(const PGS::ArtifactStoreStatus &status,
                               std::int64_t ttlMs,
                               bool autoCleanup,
                               bool verifyOnStatus,
                               std::uint64_t maxArtifactBytes,
                               std::uint64_t maxTotalBytes)
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
           ",\"max_artifact_bytes\":" + std::to_string(maxArtifactBytes) +
           ",\"max_total_bytes\":" + std::to_string(maxTotalBytes) + "}";
}
inline bool isTerminalOperationStatus(const std::string &status)
{
    return status == "succeeded" || status == "failed" || status == "cancelled" || status == "expired";
}
inline bool parseTtlMsText(const std::string &text, std::int64_t &out)
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
inline bool parseArtifactBoolText(const std::string &text, bool &out)
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
inline bool parseArtifactSizeText(const std::string &text, std::uint64_t minValue, std::uint64_t maxValue, std::uint64_t &out)
{
    const std::string value = trim(text);
    if (value.empty())
    {
        return false;
    }
    try
    {
        std::size_t used = 0;
        const unsigned long long parsed = std::stoull(value, &used, 10);
        if (used != value.size() || parsed < minValue || parsed > maxValue)
        {
            return false;
        }
        out = static_cast<std::uint64_t>(parsed);
        return true;
    }
    catch (const std::exception &)
    {
        return false;
    }
}
inline std::string clampMessage(std::string text)
{
    if (text.size() > 512)
    {
        text.resize(512);
    }
    return text;
}
inline std::string sanitizeGroupNameLocal(std::string name)
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
inline std::vector<std::string> splitCsvTrimmedLocal(const std::string &value)
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
inline std::string joinCsvLocal(const std::vector<std::string> &values)
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
inline bool looksLikeJsonObjectOrArrayLocal(const std::string &text)
{
    return service_util::looksLikeJsonObjectOrArray(text);
}
inline bool parseIntLocal(const std::string &text, int &out)
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
inline void closeLaunch(SuspendedLaunch &launch)
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
inline bool finalPathFromHandle(HANDLE handle, std::wstring &out, std::string &err)
{
    out.clear();
    std::vector<wchar_t> buffer(32768, L'\0');
    const DWORD len = GetFinalPathNameByHandleW(
        handle, buffer.data(), static_cast<DWORD>(buffer.size()),
        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (len == 0 || len >= buffer.size())
    {
        err = "GetFinalPathNameByHandleW failed: " + win32ErrorText(GetLastError());
        return false;
    }
    out.assign(buffer.data(), len);
    if (out.rfind(L"\\\\?\\UNC\\", 0) == 0)
    {
        out = L"\\\\" + out.substr(8);
    }
    else if (out.rfind(L"\\\\?\\", 0) == 0)
    {
        out = out.substr(4);
    }
    return true;
}
inline bool startSuspendedFromPath(const std::string &pathUtf8, const std::string &argsUtf8,
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
    HANDLE file = CreateFileW(fullPath.c_str(), GENERIC_READ | FILE_READ_ATTRIBUTES,
                              FILE_SHARE_READ | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        err = "target executable cannot be opened: " + win32ErrorText(GetLastError());
        return false;
    }
    BY_HANDLE_FILE_INFORMATION fileInfo{};
    if (!GetFileInformationByHandle(file, &fileInfo) ||
        (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        err = "target executable is not a file: " + wideToUtf8(fullPath);
        CloseHandle(file);
        return false;
    }
    std::wstring finalPath;
    if (!finalPathFromHandle(file, finalPath, err))
    {
        CloseHandle(file);
        return false;
    }
    CloseHandle(file);
    std::wstring command = quoteArgW(finalPath);
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
    const std::wstring workDir = std::filesystem::path(finalPath).parent_path().wstring();
    if (!CreateProcessW(finalPath.c_str(), writable.data(), nullptr, nullptr, FALSE,
                        CREATE_NEW_CONSOLE | CREATE_SUSPENDED, nullptr,
                        workDir.empty() ? nullptr : workDir.c_str(), &si, &pi))
    {
        err = "CreateProcessW failed: " + win32ErrorText(GetLastError());
        return false;
    }
    out.pid = pi.dwProcessId;
    out.pathUtf8 = wideToUtf8(finalPath);
    out.process = pi.hProcess;
    out.thread = pi.hThread;
    return true;
}

} // namespace pgs_protocol
} // namespace ProcessGuard

#endif // PGS_PROTOCOL_INTERNAL_H
