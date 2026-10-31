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
#include "PGSProtocolInternal.h"

namespace ProcessGuard
{

using namespace util;
using namespace pgs_protocol;


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
    m_artifactMaxBytes = kDefaultArtifactBytes;
    m_artifactMaxTotalBytes = kDefaultArtifactTotalBytes;
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
        else if (key == "max_artifact_bytes")
        {
            std::uint64_t parsed = 0;
            if (parseArtifactSizeText(value, kMinArtifactBytes, kMaxArtifactBytesLimit, parsed))
            {
                m_artifactMaxBytes = parsed;
            }
        }
        else if (key == "max_total_bytes")
        {
            std::uint64_t parsed = 0;
            if (parseArtifactSizeText(value, kMinArtifactTotalBytes, kMaxArtifactTotalBytesLimit, parsed))
            {
                m_artifactMaxTotalBytes = parsed;
            }
        }
    }
    if (m_artifactMaxTotalBytes < m_artifactMaxBytes)
    {
        m_artifactMaxTotalBytes = m_artifactMaxBytes;
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
                             "verify_on_status=" + std::string(m_artifactVerifyOnStatus ? "1" : "0") + "\n" +
                             "max_artifact_bytes=" + std::to_string(m_artifactMaxBytes) + "\n" +
                             "max_total_bytes=" + std::to_string(m_artifactMaxTotalBytes) + "\n";
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
    return artifactPolicySummaryValues(m_artifactRetentionTtlMs, m_artifactAutoCleanup,
                                       m_artifactVerifyOnStatus, m_artifactMaxBytes,
                                       m_artifactMaxTotalBytes);
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
    std::uint64_t maxArtifactBytes = kDefaultArtifactBytes;
    std::uint64_t maxTotalBytes = kDefaultArtifactTotalBytes;
    {
        std::lock_guard<std::mutex> lock(m_artifactMutex);
        const bool effectiveVerify = verifyContentHash || m_artifactVerifyOnStatus;
        status = artifactStoreStatusLocked(effectiveVerify, detail);
        ttlMs = m_artifactRetentionTtlMs;
        autoCleanup = m_artifactAutoCleanup;
        verifyOnStatus = m_artifactVerifyOnStatus;
        maxArtifactBytes = m_artifactMaxBytes;
        maxTotalBytes = m_artifactMaxTotalBytes;
    }
    const std::string statusJson = artifactStatusJson(status, ttlMs, autoCleanup, verifyOnStatus,
                                                      maxArtifactBytes, maxTotalBytes);
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
        << ";max_artifact_bytes=" << maxArtifactBytes
        << ";max_total_bytes=" << maxTotalBytes
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
    std::uint64_t maxArtifactBytes = 0;
    bool hasMaxArtifactBytes = false;
    std::uint64_t maxTotalBytes = 0;
    bool hasMaxTotalBytes = false;
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
        if (opt == "--max-artifact-bytes")
        {
            if (i + 1 >= parts.size() || !parseArtifactSizeText(parts[++i], kMinArtifactBytes, kMaxArtifactBytesLimit, maxArtifactBytes))
            {
                return "ERR artifact policy --max-artifact-bytes must be 65536..67108864";
            }
            hasMaxArtifactBytes = true;
            continue;
        }
        if (opt == "--max-total-bytes")
        {
            if (i + 1 >= parts.size() || !parseArtifactSizeText(parts[++i], kMinArtifactTotalBytes, kMaxArtifactTotalBytesLimit, maxTotalBytes))
            {
                return "ERR artifact policy --max-total-bytes must be 1048576..1073741824";
            }
            hasMaxTotalBytes = true;
            continue;
        }
        if (opt == "--help")
        {
            return "OK artifact policy options: --ttl-ms N --max-artifact-bytes N --max-total-bytes N --auto-cleanup --no-auto-cleanup --verify-on-status --no-verify-on-status";
        }
        return "ERR unknown artifact policy option";
    }
    std::string policySummary;
    std::string policyJson;
    {
        std::lock_guard<std::mutex> lock(m_artifactMutex);
        const std::uint64_t finalMaxArtifactBytes = hasMaxArtifactBytes ? maxArtifactBytes : m_artifactMaxBytes;
        const std::uint64_t finalMaxTotalBytes = hasMaxTotalBytes ? maxTotalBytes : m_artifactMaxTotalBytes;
        if (finalMaxTotalBytes < finalMaxArtifactBytes)
        {
            return "ERR artifact policy max-total-bytes must be greater than or equal to max-artifact-bytes";
        }
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
        if (hasMaxArtifactBytes)
        {
            m_artifactMaxBytes = finalMaxArtifactBytes;
        }
        if (hasMaxTotalBytes)
        {
            m_artifactMaxTotalBytes = finalMaxTotalBytes;
        }
        if (hasTtl || hasAutoCleanup || hasVerifyOnStatus || hasMaxArtifactBytes || hasMaxTotalBytes)
        {
            std::string error;
            if (!saveArtifactPolicyLocked(error))
            {
                return "ERR " + error;
            }
        }
        policySummary = artifactPolicySummaryLocked();
        policyJson = artifactPolicyJson(m_artifactRetentionTtlMs, m_artifactAutoCleanup,
                                        m_artifactVerifyOnStatus, m_artifactMaxBytes,
                                        m_artifactMaxTotalBytes);
    }
    if (hasTtl || hasAutoCleanup || hasVerifyOnStatus || hasMaxArtifactBytes || hasMaxTotalBytes)
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


} // namespace ProcessGuard
