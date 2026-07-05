/**
 * @file PGUtil.h
 * @brief Shared header-only utilities for ProcessGuard (encoding, hashing,
 *        path/process helpers, secure directory creation).
 *
 * Consolidates helpers that were previously duplicated across PGS.cpp,
 * pgs_bless.cpp, the examples, ModuleManager.cpp and pgs_service.cpp.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef PROCESS_GUARD_PG_UTIL_H
#define PROCESS_GUARD_PG_UTIL_H
#include <windows.h>
#include <bcrypt.h>
#include <sddl.h>
#include <aclapi.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#endif
namespace ProcessGuard
{
    namespace util
    {
        inline const std::string kBase64Chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/";

        inline std::string trim(std::string value)
        {
            const auto isNotSpace = [](unsigned char c) { return !std::isspace(c); };
            value.erase(value.begin(), std::find_if(value.begin(), value.end(), isNotSpace));
            value.erase(std::find_if(value.rbegin(), value.rend(), isNotSpace).base(), value.end());
            return value;
        }

        inline std::string toLowerAscii(std::string value)
        {
            std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
                return static_cast<char>(std::tolower(ch));
            });
            return value;
        }

        inline std::wstring utf8ToWide(const std::string &input)
        {
            if (input.empty())
            {
                return std::wstring();
            }
            const int needed = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, nullptr, 0);
            if (needed <= 0)
            {
                return std::wstring();
            }
            std::wstring out(static_cast<std::size_t>(needed), L'\0');
            if (MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, &out[0], needed) <= 0)
            {
                return std::wstring();
            }
            if (!out.empty() && out.back() == L'\0')
            {
                out.pop_back();
            }
            return out;
        }

        inline std::string wideToUtf8(const std::wstring &input)
        {
            if (input.empty())
            {
                return std::string();
            }
            const int needed = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, nullptr, 0, nullptr, nullptr);
            if (needed <= 0)
            {
                return std::string();
            }
            std::string out(static_cast<std::size_t>(needed), '\0');
            if (WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, &out[0], needed, nullptr, nullptr) <= 0)
            {
                return std::string();
            }
            if (!out.empty() && out.back() == '\0')
            {
                out.pop_back();
            }
            return out;
        }

        inline std::wstring narrowToWideBestEffort(const std::string &input)
        {
            if (input.empty())
            {
                return std::wstring();
            }
            auto convert = [&](UINT codePage) -> std::wstring {
                const int needed = MultiByteToWideChar(codePage, 0, input.c_str(), -1, nullptr, 0);
                if (needed <= 0)
                {
                    return std::wstring();
                }
                std::wstring out(static_cast<std::size_t>(needed), L'\0');
                if (MultiByteToWideChar(codePage, 0, input.c_str(), -1, &out[0], needed) <= 0)
                {
                    return std::wstring();
                }
                if (!out.empty() && out.back() == L'\0')
                {
                    out.pop_back();
                }
                return out;
            };
            std::wstring utf8 = convert(CP_UTF8);
            if (!utf8.empty())
            {
                return utf8;
            }
            std::wstring acp = convert(CP_ACP);
            if (!acp.empty())
            {
                return acp;
            }
            return std::wstring(input.begin(), input.end());
        }

        inline std::string base64Encode(const std::string &input)
        {
            std::string output;
            int val = 0;
            int valb = -6;
            for (unsigned char c : input)
            {
                val = (val << 8) + c;
                valb += 8;
                while (valb >= 0)
                {
                    output.push_back(kBase64Chars[(val >> valb) & 0x3F]);
                    valb -= 6;
                }
            }
            if (valb > -6)
            {
                output.push_back(kBase64Chars[((val << 8) >> (valb + 8)) & 0x3F]);
            }
            while (output.size() % 4 != 0)
            {
                output.push_back('=');
            }
            return output;
        }

        inline std::string base64Decode(const std::string &input)
        {
            std::string output;
            int val = 0;
            int valb = -8;
            for (unsigned char c : input)
            {
                if (c == '=')
                {
                    break;
                }
                const auto index = kBase64Chars.find(c);
                if (index == std::string::npos)
                {
                    break;
                }
                val = (val << 6) + static_cast<int>(index);
                valb += 6;
                if (valb >= 0)
                {
                    output.push_back(static_cast<char>((val >> valb) & 0xFF));
                    valb -= 8;
                }
            }
            return output;
        }

        inline std::vector<std::string> split(const std::string &value, char delimiter)
        {
            std::vector<std::string> parts;
            std::string current;
            for (char ch : value)
            {
                if (ch == delimiter)
                {
                    parts.push_back(current);
                    current.clear();
                }
                else
                {
                    current.push_back(ch);
                }
            }
            parts.push_back(current);
            return parts;
        }

        // Parse a decimal pid (digits only, 1..0xFFFFFFFF, 0 rejected). Shared by
        // the service core and the CLI so both apply the same strict validation.
        inline bool parsePid(const std::string &text, DWORD &outPid)
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
                const unsigned long parsed = std::stoul(value);
                if (parsed == 0 || parsed > 0xFFFFFFFFul)
                {
                    return false;
                }
                outPid = static_cast<DWORD>(parsed);
                return true;
            }
            catch (const std::exception &)
            {
                return false;
            }
        }

        // Parse max-restarts: "no" => -1 (unlimited), else a non-negative decimal.
        inline bool parseMaxRestarts(const std::string &text, int &outMaxRestarts)
        {
            const std::string value = trim(text);
            if (value == "no")
            {
                outMaxRestarts = -1;
                return true;
            }
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
                outMaxRestarts = std::stoi(value);
                return outMaxRestarts >= 0;
            }
            catch (const std::exception &)
            {
                return false;
            }
        }

        inline std::string maxRestartsLabel(int maxRestarts)
        {
            return maxRestarts < 0 ? std::string("no") : std::to_string(maxRestarts);
        }

        inline std::string replaceAll(std::string text, const std::string &from, const std::string &to)
        {
            if (from.empty())
            {
                return text;
            }
            std::size_t pos = 0;
            while ((pos = text.find(from, pos)) != std::string::npos)
            {
                text.replace(pos, from.length(), to);
                pos += to.length();
            }
            return text;
        }

        inline std::wstring quoteArgW(const std::wstring &arg)
        {
            if (arg.empty())
            {
                return L"\"\"";
            }
            bool needQuotes = false;
            for (wchar_t ch : arg)
            {
                if (ch == L' ' || ch == L'\t' || ch == L'"')
                {
                    needQuotes = true;
                    break;
                }
            }
            if (!needQuotes)
            {
                return arg;
            }
            std::wstring out = L"\"";
            int backslashes = 0;
            for (wchar_t ch : arg)
            {
                if (ch == L'\\')
                {
                    ++backslashes;
                    continue;
                }
                if (ch == L'"')
                {
                    out.append(backslashes * 2 + 1, L'\\');
                    out.push_back(L'"');
                    backslashes = 0;
                    continue;
                }
                if (backslashes > 0)
                {
                    out.append(backslashes, L'\\');
                    backslashes = 0;
                }
                out.push_back(ch);
            }
            if (backslashes > 0)
            {
                out.append(backslashes * 2, L'\\');
            }
            out.push_back(L'"');
            return out;
        }

        inline std::string normalizePathForCompareUtf8(const std::string &pathUtf8)
        {
            const std::wstring pathW = utf8ToWide(pathUtf8);
            if (pathW.empty())
            {
                return std::string();
            }
            std::vector<wchar_t> fullPathBuf(32768, L'\0');
            const DWORD fullLen = GetFullPathNameW(pathW.c_str(), static_cast<DWORD>(fullPathBuf.size()), fullPathBuf.data(), nullptr);
            if (fullLen == 0 || fullLen >= fullPathBuf.size())
            {
                return std::string();
            }
            std::wstring normalized(fullPathBuf.data(), fullLen);
            std::replace(normalized.begin(), normalized.end(), L'/', L'\\');
            std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](wchar_t ch) {
                return static_cast<wchar_t>(towlower(ch));
            });
            return wideToUtf8(normalized);
        }

        inline std::string parentDirectoryUtf8(const std::string &path)
        {
            const auto pos = path.find_last_of("\\/");
            if (pos == std::string::npos)
            {
                return std::string();
            }
            return path.substr(0, pos);
        }

        inline bool queryProcessPath(DWORD pid, std::string &outPath)
        {
            outPath.clear();
            HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!processHandle)
            {
                return false;
            }
            std::vector<wchar_t> buffer(32768, L'\0');
            DWORD size = static_cast<DWORD>(buffer.size());
            const BOOL ok = QueryFullProcessImageNameW(processHandle, 0, buffer.data(), &size);
            CloseHandle(processHandle);
            if (!ok || size == 0)
            {
                return false;
            }
            outPath = wideToUtf8(std::wstring(buffer.data(), buffer.data() + size));
            return !outPath.empty();
        }

        inline std::string win32ErrorText(DWORD code)
        {
            LPWSTR msgBuf = nullptr;
            const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
            const DWORD len = FormatMessageW(flags, nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                             reinterpret_cast<LPWSTR>(&msgBuf), 0, nullptr);
            std::wstring msgW;
            if (len > 0 && msgBuf)
            {
                msgW.assign(msgBuf, msgBuf + len);
                LocalFree(msgBuf);
            }
            std::string msg = trim(wideToUtf8(msgW));
            if (msg.empty())
            {
                msg = "Unknown error";
            }
            return "error=" + std::to_string(code) + " (" + msg + ")";
        }

        // SHA-256 of a byte string, returned as 64 lowercase hex chars.
        inline std::string sha256Hex(const std::string &data)
        {
            BCRYPT_ALG_HANDLE hAlg = nullptr;
            if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0 || !hAlg)
            {
                return std::string();
            }
            std::string result;
            BCRYPT_HASH_HANDLE hHash = nullptr;
            unsigned char hash[32];
            if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) == 0 && hHash)
            {
                if (BCryptHashData(hHash, const_cast<PUCHAR>(reinterpret_cast<const unsigned char *>(data.data())),
                                   static_cast<ULONG>(data.size()), 0) == 0 &&
                    BCryptFinishHash(hHash, hash, sizeof(hash), 0) == 0)
                {
                    std::ostringstream oss;
                    oss << std::hex << std::nouppercase << std::setfill('0');
                    for (unsigned char b : hash)
                    {
                        oss << std::setw(2) << static_cast<unsigned int>(b);
                    }
                    result = oss.str();
                }
                BCryptDestroyHash(hHash);
            }
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return result;
        }

        inline bool sha256FileHex(const std::string &pathUtf8, std::string &outHash)
        {
            const std::wstring pathW = utf8ToWide(pathUtf8);
            if (pathW.empty())
            {
                return false;
            }
            HANDLE file = CreateFileW(pathW.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE)
            {
                return false;
            }
            BCRYPT_ALG_HANDLE hAlg = nullptr;
            BCRYPT_HASH_HANDLE hHash = nullptr;
            unsigned char hash[32];
            bool ok = false;
            if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0 && hAlg &&
                BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) == 0 && hHash)
            {
                char buffer[8192];
                DWORD readBytes = 0;
                bool hashFailed = false;
                while (ReadFile(file, buffer, static_cast<DWORD>(sizeof(buffer)), &readBytes, nullptr) && readBytes > 0)
                {
                    if (BCryptHashData(hHash, reinterpret_cast<PUCHAR>(buffer), readBytes, 0) != 0)
                    {
                        hashFailed = true;
                        break;
                    }
                }
                if (!hashFailed && BCryptFinishHash(hHash, hash, sizeof(hash), 0) == 0)
                {
                    std::ostringstream oss;
                    oss << std::hex << std::nouppercase << std::setfill('0');
                    for (unsigned char b : hash)
                    {
                        oss << std::setw(2) << static_cast<unsigned int>(b);
                    }
                    outHash = oss.str();
                    ok = true;
                }
                BCryptDestroyHash(hHash);
            }
            if (hAlg)
            {
                BCryptCloseAlgorithmProvider(hAlg, 0);
            }
            CloseHandle(file);
            return ok;
        }

        // Cryptographically random bytes, returned as lowercase hex.
        inline std::string randomBytesHex(std::size_t numBytes)
        {
            if (numBytes == 0)
            {
                return std::string();
            }
            std::vector<unsigned char> buf(numBytes);
            if (BCryptGenRandom(nullptr, buf.data(), static_cast<ULONG>(numBytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
            {
                return std::string();
            }
            std::ostringstream oss;
            oss << std::hex << std::nouppercase << std::setfill('0');
            for (unsigned char b : buf)
            {
                oss << std::setw(2) << static_cast<unsigned int>(b);
            }
            return oss.str();
        }

        // Constant-time equality for fixed-length secrets/hashes. Leaks only the
        // length (acceptable for SHA-256 hex), never the first differing byte.
        inline bool constantTimeEquals(const std::string &a, const std::string &b)
        {
            if (a.size() != b.size())
            {
                return false;
            }
            unsigned char diff = 0;
            for (std::size_t i = 0; i < a.size(); ++i)
            {
                diff |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
            }
            return diff == 0;
        }

        // Create a directory (recursively) and apply a restrictive DACL granting
        // full control only to SYSTEM and Administrators (protected, no inherit).
        inline bool secureCreateDirectory(const std::string &utf8Path)
        {
            const std::wstring wpath = utf8ToWide(utf8Path);
            if (wpath.empty())
            {
                return false;
            }
            std::error_code ec;
            std::filesystem::create_directories(utf8Path, ec);
            if (!std::filesystem::is_directory(std::filesystem::path(utf8Path), ec))
            {
                return false;
            }

            // SDDL: protected DACL, SYSTEM + Administrators full (container/file inherit).
            PSECURITY_DESCRIPTOR psd = nullptr;
            ULONG sdSize = 0;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1, &psd, &sdSize) ||
                !psd)
            {
                return false;
            }
            BOOL daclPresent = FALSE;
            BOOL daclDefaulted = FALSE;
            PACL dacl = nullptr;
            GetSecurityDescriptorDacl(psd, &daclPresent, &dacl, &daclDefaulted);
            const DWORD rc = SetNamedSecurityInfoW(const_cast<LPWSTR>(wpath.c_str()), SE_FILE_OBJECT,
                                                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                                    nullptr, nullptr, dacl, nullptr);
            LocalFree(psd);
            return rc == ERROR_SUCCESS;
        }
        // ---- v3 hardening: testable pure helpers ---------------------------------

        // Numeric/bool parsing (mirror the file-local PGS.cpp helpers so unit
        // tests can exercise them without linking the whole service core).
        inline bool parseUnsignedLongLong(const std::string &value, std::uint64_t &out)
        {
            const std::string text = trim(value);
            if (text.empty())
            {
                return false;
            }
            try
            {
                const unsigned long long parsed = std::stoull(text);
                out = static_cast<std::uint64_t>(parsed);
                return true;
            }
            catch (const std::exception &)
            {
                return false;
            }
        }

        inline bool parseDwordValue(const std::string &value, DWORD &out)
        {
            std::uint64_t parsed = 0;
            if (!parseUnsignedLongLong(value, parsed) || parsed > 0xFFFFFFFFull)
            {
                return false;
            }
            out = static_cast<DWORD>(parsed);
            return true;
        }

        inline bool parseBoolFlag(const std::string &value, bool &out)
        {
            const std::string text = trim(value);
            if (text == "1")
            {
                out = true;
                return true;
            }
            if (text == "0")
            {
                out = false;
                return true;
            }
            return false;
        }

        // PackageFamilyName publisher hash (Microsoft-documented algorithm):
        //   1. SHA-256 of the publisher string (UTF-8)
        //   2. low-order 8 bytes (bytes 24..31 of the 32-byte digest)
        //   3. standard base64 of those 8 bytes, then URL-safe ( '+'->'-',
        //      '/'->'_' ) and strip '=' padding
        // Returns the 11-char suffix appended after "<Name>_" in a PFN.
        inline std::string pfnHashFromPublisher(const std::string &publisher)
        {
            const std::string sha = sha256Hex(publisher);
            if (sha.size() != 64)
            {
                return std::string();
            }
            std::string last8(8, '\0');
            for (int i = 0; i < 8; ++i)
            {
                unsigned int b = 0;
                std::istringstream iss(sha.substr(48 + i * 2, 2));
                iss >> std::hex >> b;
                last8[static_cast<std::size_t>(i)] = static_cast<char>(b);
            }
            std::string b64 = base64Encode(last8);
            for (char &c : b64)
            {
                if (c == '+')
                {
                    c = '-';
                }
                else if (c == '/')
                {
                    c = '_';
                }
            }
            const auto eq = b64.find('=');
            if (eq != std::string::npos)
            {
                b64.resize(eq);
            }
            return b64;
        }

        inline std::string packageFamilyNameFrom(const std::string &name, const std::string &publisher)
        {
            const std::string h = pfnHashFromPublisher(publisher);
            if (h.empty())
            {
                return std::string();
            }
            return name + "_" + h;
        }

        inline std::string deriveAumidFromParts(const std::string &name, const std::string &publisher, const std::string &appId)
        {
            const std::string pfn = packageFamilyNameFrom(name, publisher);
            if (pfn.empty())
            {
                return std::string();
            }
            return pfn + "!" + appId;
        }

        // Sliding-window restart pruning. windowSec<=0 means "lifetime count"
        // (legacy): return the vector untouched so restartCount never self-heals.
        // Else keep only timestamps strictly newer than (now - window*1000ms).
        inline std::vector<std::int64_t> pruneRestartWindow(const std::vector<std::int64_t> &times,
                                                            std::int64_t nowMs, int windowSec)
        {
            if (windowSec <= 0)
            {
                return times;
            }
            const std::int64_t cutoff = nowMs - static_cast<std::int64_t>(windowSec) * 1000;
            std::vector<std::int64_t> out;
            for (std::int64_t t : times)
            {
                if (t > cutoff)
                {
                    out.push_back(t);
                }
            }
            return out;
        }

        // Exponential restart backoff: delay * 2^min(index,6), capped at 60s.
        // baseDelayMs<=0 yields itself (no negative delays; 0 = immediate).
        inline int computeBackoffDelay(int baseDelayMs, int restartIndex)
        {
            if (baseDelayMs <= 0)
            {
                return baseDelayMs < 0 ? 0 : baseDelayMs;
            }
            const int shifts = restartIndex > 6 ? 6 : restartIndex;
            std::int64_t d = static_cast<std::int64_t>(baseDelayMs) << shifts;
            if (d > 60000)
            {
                d = 60000;
            }
            return static_cast<int>(d);
        }
    } // namespace util
} // namespace ProcessGuard

#endif // PROCESS_GUARD_PG_UTIL_H
