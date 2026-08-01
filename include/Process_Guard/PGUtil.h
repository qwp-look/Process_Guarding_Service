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
#include <fstream>
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
            return std::wstring();
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

        inline std::wstring currentUserSidString()
        {
            HANDLE token = nullptr;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
            {
                return std::wstring();
            }

            DWORD needed = 0;
            GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
            if (needed == 0)
            {
                CloseHandle(token);
                return std::wstring();
            }

            std::vector<unsigned char> buffer(needed);
            if (!GetTokenInformation(token, TokenUser, buffer.data(), needed, &needed))
            {
                CloseHandle(token);
                return std::wstring();
            }
            CloseHandle(token);

            auto *user = reinterpret_cast<TOKEN_USER *>(buffer.data());
            LPWSTR sidText = nullptr;
            if (!ConvertSidToStringSidW(user->User.Sid, &sidText) || !sidText)
            {
                return std::wstring();
            }
            std::wstring result(sidText);
            LocalFree(sidText);
            return result;
        }

        inline std::wstring secureDaclSddl(bool container)
        {
            std::wstring sddl = container
                ? L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
                : L"D:P(A;;FA;;;SY)(A;;FA;;;BA)";

            const std::wstring userSid = currentUserSidString();
            if (!userSid.empty() && userSid != L"S-1-5-18")
            {
                sddl += container ? L"(A;OICI;FA;;;" : L"(A;;FA;;;";
                sddl += userSid;
                sddl += L")";
            }
            return sddl;
        }

        inline bool secureApplyDacl(const std::string &utf8Path, bool container)
        {
            const std::wstring wpath = utf8ToWide(utf8Path);
            if (wpath.empty())
            {
                return false;
            }

            PSECURITY_DESCRIPTOR psd = nullptr;
            ULONG sdSize = 0;
            const std::wstring sddl = secureDaclSddl(container);
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.c_str(), SDDL_REVISION_1, &psd, &sdSize) ||
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

        // Create a directory recursively and apply a protected DACL granting full
        // control to SYSTEM, Administrators, and the current runtime identity.
        // The current identity entry keeps console/dev runs and custom service
        // accounts from locking themselves out after creating the directory.
        inline bool secureCreateDirectory(const std::string &utf8Path)
        {
            std::error_code ec;
            std::filesystem::create_directories(utf8Path, ec);
            if (!std::filesystem::is_directory(std::filesystem::path(utf8Path), ec))
            {
                return false;
            }
            return secureApplyDacl(utf8Path, true);
        }

        // ---- modules/ ACL audit + repair (P0-03) ---------------------------------
        // Production module loading boundary: only SYSTEM and Administrators may
        // own or write modules root, module dirs, DLLs, manifests, and modules.lock.
        // State-dir helpers above intentionally keep the runtime identity ACE;
        // modules tree uses the stricter SY+BA-only DACL.

        struct ModulesAclPath
        {
            std::string path; // UTF-8
            bool container = false;
        };

        struct ModulesAclAuditResult
        {
            bool ok = true;
            std::vector<std::string> badPaths; // UTF-8
            std::string reason;                // first failure reason (stable, machine-friendly)
        };

        // Fail-closed recursive walk result. Any filesystem error during construction,
        // type query, or increment sets ok=false — never silently skip unreadable nodes.
        struct ModulesAclEnumerateResult
        {
            bool ok = true;
            std::vector<ModulesAclPath> paths;
            std::string reason;    // empty when ok
            std::string errorPath; // UTF-8 path associated with the first error
        };

        // Write / ownership rights that must not be granted to non-admin principals.
        // Note: do NOT include FILE_ALL_ACCESS here — it is a composite constant and
        // would match read-only bits under a bitwise AND.
        inline DWORD modulesAclDangerousWriteMask()
        {
            return static_cast<DWORD>(
                FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY |
                FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | WRITE_DAC | WRITE_OWNER | DELETE |
                GENERIC_WRITE | GENERIC_ALL);
        }

        inline bool modulesAclSidIsSystemOrAdministrators(PSID sid)
        {
            if (!sid || !IsValidSid(sid))
            {
                return false;
            }
            return IsWellKnownSid(sid, WinLocalSystemSid) == TRUE ||
                   IsWellKnownSid(sid, WinBuiltinAdministratorsSid) == TRUE;
        }

        // True for well-known low-privilege trustees that must never write modules.
        inline bool modulesAclSidIsKnownNonAdmin(PSID sid)
        {
            if (!sid || !IsValidSid(sid))
            {
                return false;
            }
            return IsWellKnownSid(sid, WinWorldSid) == TRUE ||
                   IsWellKnownSid(sid, WinAuthenticatedUserSid) == TRUE ||
                   IsWellKnownSid(sid, WinBuiltinUsersSid) == TRUE ||
                   IsWellKnownSid(sid, WinBuiltinGuestsSid) == TRUE ||
                   IsWellKnownSid(sid, WinInteractiveSid) == TRUE ||
                   IsWellKnownSid(sid, WinNetworkSid) == TRUE ||
                   IsWellKnownSid(sid, WinBuiltinPowerUsersSid) == TRUE ||
                   IsWellKnownSid(sid, WinCreatorOwnerSid) == TRUE ||
                   IsWellKnownSid(sid, WinCreatorGroupSid) == TRUE ||
                   IsWellKnownSid(sid, WinBatchSid) == TRUE ||
                   IsWellKnownSid(sid, WinServiceSid) == TRUE;
        }

        // Best-effort: SID is the local Administrators group or a direct member.
        // Uses NetLocalGroupGetMembers via runtime LoadLibrary (no lm.h / link dep).
        // Falls back to "current process user matches sid and token is in Administrators".
        inline bool modulesAclSidIsAdministratorsMember(PSID sid)
        {
            if (!sid || !IsValidSid(sid))
            {
                return false;
            }
            if (modulesAclSidIsSystemOrAdministrators(sid))
            {
                return true;
            }

            // Fast path: current process user matches and token has Administrators.
            HANDLE token = nullptr;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) && token)
            {
                DWORD needed = 0;
                GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
                bool matchedCurrentUser = false;
                BOOL isMember = FALSE;
                if (needed > 0)
                {
                    std::vector<unsigned char> buffer(needed);
                    if (GetTokenInformation(token, TokenUser, buffer.data(), needed, &needed))
                    {
                        auto *user = reinterpret_cast<TOKEN_USER *>(buffer.data());
                        if (user && user->User.Sid && EqualSid(user->User.Sid, sid))
                        {
                            matchedCurrentUser = true;
                            PSID adminSid = nullptr;
                            SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
                            if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                                         DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                                         &adminSid) &&
                                adminSid)
                            {
                                CheckTokenMembership(nullptr, adminSid, &isMember);
                                FreeSid(adminSid);
                            }
                        }
                    }
                }
                CloseHandle(token);
                if (matchedCurrentUser && isMember)
                {
                    return true;
                }
            }

            // Enumerate local Administrators members (info level 0 => SID).
            // Minimal structs/constants to avoid depending on lm.h in this header.
            struct PgsLocalGroupMember0
            {
                PSID sid;
            };
            using NetLocalGroupGetMembersFn = DWORD(WINAPI *)(
                LPCWSTR server, LPCWSTR group, DWORD level, LPBYTE *bufptr, DWORD prefmaxlen,
                LPDWORD entriesread, LPDWORD totalentries, PDWORD_PTR resumehandle);
            using NetApiBufferFreeFn = DWORD(WINAPI *)(LPVOID buffer);

            HMODULE hNet = LoadLibraryW(L"netapi32.dll");
            if (!hNet)
            {
                return false;
            }
            auto getMembers = reinterpret_cast<NetLocalGroupGetMembersFn>(
                reinterpret_cast<void *>(GetProcAddress(hNet, "NetLocalGroupGetMembers")));
            auto freeBuf = reinterpret_cast<NetApiBufferFreeFn>(
                reinterpret_cast<void *>(GetProcAddress(hNet, "NetApiBufferFree")));
            if (!getMembers || !freeBuf)
            {
                FreeLibrary(hNet);
                return false;
            }

            LPBYTE buf = nullptr;
            DWORD entries = 0;
            DWORD total = 0;
            constexpr DWORD kMaxPreferredLength = static_cast<DWORD>(-1);
            constexpr DWORD kNerrSuccess = 0;
            const DWORD status = getMembers(
                nullptr, L"Administrators", 0, &buf, kMaxPreferredLength, &entries, &total, nullptr);
            bool found = false;
            if (status == kNerrSuccess && buf && entries > 0)
            {
                auto *members = reinterpret_cast<PgsLocalGroupMember0 *>(buf);
                for (DWORD i = 0; i < entries; ++i)
                {
                    if (members[i].sid && EqualSid(members[i].sid, sid))
                    {
                        found = true;
                        break;
                    }
                }
            }
            if (buf)
            {
                freeBuf(buf);
            }
            FreeLibrary(hNet);
            return found;
        }

        inline bool modulesAclSidIsTrustedPrincipal(PSID sid)
        {
            return modulesAclSidIsSystemOrAdministrators(sid) ||
                   modulesAclSidIsAdministratorsMember(sid);
        }

        inline std::wstring secureModulesDaclSddl(bool container)
        {
            // Modules trust boundary: SYSTEM + Administrators. When the host is not
            // LocalSystem, also grant the runtime identity so console/dev runs and
            // custom service accounts are not locked out by UAC filtered tokens.
            // auditModulesAcl() still requires that identity to be an Administrators
            // member — a standard-user ACE remains fail-closed.
            std::wstring sddl = container
                ? L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
                : L"D:P(A;;FA;;;SY)(A;;FA;;;BA)";
            const std::wstring userSid = currentUserSidString();
            if (!userSid.empty() && userSid != L"S-1-5-18")
            {
                sddl += container ? L"(A;OICI;FA;;;" : L"(A;;FA;;;";
                sddl += userSid;
                sddl += L")";
            }
            return sddl;
        }

        // Best-effort enable of privileges needed to reassign file ownership during
        // explicit repair (SeTakeOwnership / SeRestore). Safe no-op when absent.
        inline void enableModulesAclRepairPrivileges()
        {
            auto enableOne = [](LPCWSTR name) {
                HANDLE token = nullptr;
                if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token) ||
                    !token)
                {
                    return;
                }
                LUID luid{};
                if (!LookupPrivilegeValueW(nullptr, name, &luid))
                {
                    CloseHandle(token);
                    return;
                }
                TOKEN_PRIVILEGES tp{};
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
                CloseHandle(token);
            };
            // Use wide privilege names explicitly (MinGW may define the SE_*_NAME
            // macros as narrow char* even in UNICODE builds).
            enableOne(L"SeTakeOwnershipPrivilege");
            enableOne(L"SeRestorePrivilege");
        }

        // Explicit repair helper: set owner to Administrators (preferred) and apply
        // a protected modules DACL. Used only by doctor repair / secureModulesAclTree,
        // never by service startup (startup is audit-only fail-closed).
        inline bool secureApplyModulesDacl(const std::string &utf8Path, bool container)
        {
            const std::wstring wpath = utf8ToWide(utf8Path);
            if (wpath.empty())
            {
                return false;
            }

            PSECURITY_DESCRIPTOR psd = nullptr;
            ULONG sdSize = 0;
            const std::wstring sddl = secureModulesDaclSddl(container);
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.c_str(), SDDL_REVISION_1, &psd, &sdSize) ||
                !psd)
            {
                return false;
            }

            BOOL daclPresent = FALSE;
            BOOL daclDefaulted = FALSE;
            PACL dacl = nullptr;
            GetSecurityDescriptorDacl(psd, &daclPresent, &dacl, &daclDefaulted);

            enableModulesAclRepairPrivileges();

            DWORD adminSidBytes = SECURITY_MAX_SID_SIZE;
            std::vector<unsigned char> adminSidBuf(adminSidBytes);
            PSID adminSid = reinterpret_cast<PSID>(adminSidBuf.data());
            const bool haveAdminSid =
                CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, adminSid, &adminSidBytes) == TRUE;

            DWORD rc = ERROR_INVALID_PARAMETER;
            if (haveAdminSid)
            {
                // Prefer OWNER=Administrators + protected DACL in one shot.
                rc = SetNamedSecurityInfoW(
                    const_cast<LPWSTR>(wpath.c_str()), SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    adminSid, nullptr, dacl, nullptr);
            }
            if (rc != ERROR_SUCCESS)
            {
                // DACL still matters even when ownership transfer is denied.
                rc = SetNamedSecurityInfoW(
                    const_cast<LPWSTR>(wpath.c_str()), SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    nullptr, nullptr, dacl, nullptr);
                if (rc == ERROR_SUCCESS && haveAdminSid)
                {
                    // Second chance: owner-only after DACL grants WRITE_OWNER to BA/self.
                    SetNamedSecurityInfoW(
                        const_cast<LPWSTR>(wpath.c_str()), SE_FILE_OBJECT,
                        OWNER_SECURITY_INFORMATION,
                        adminSid, nullptr, nullptr, nullptr);
                }
            }
            LocalFree(psd);
            return rc == ERROR_SUCCESS;
        }

        // True recursive enumeration of the modules trust boundary:
        // - every directory at any depth
        // - files: *.dll, module.manifest, module.manifest.json, modules.lock
        // Fail-closed: do NOT use skip_permission_denied. Constructor / type query /
        // increment errors become ok=false with reason + errorPath.
        inline ModulesAclEnumerateResult enumerateModulesAclPaths(const std::string &modulesRoot)
        {
            ModulesAclEnumerateResult result;
            if (modulesRoot.empty())
            {
                result.ok = false;
                result.reason = "modules-root-empty";
                return result;
            }

            std::error_code ec;
            const std::filesystem::path root(modulesRoot);
            const bool rootExists = std::filesystem::exists(root, ec);
            if (ec)
            {
                result.ok = false;
                result.reason = "modules-tree-enumeration-failed";
                result.errorPath = modulesRoot;
                return result;
            }
            if (!rootExists)
            {
                result.ok = false;
                result.reason = "modules-root-missing";
                result.errorPath = modulesRoot;
                return result;
            }

            const bool rootIsDir = std::filesystem::is_directory(root, ec);
            if (ec)
            {
                result.ok = false;
                result.reason = "modules-entry-unreadable";
                result.errorPath = modulesRoot;
                return result;
            }
            result.paths.push_back({root.string(), rootIsDir});
            if (!rootIsDir)
            {
                return result;
            }

            auto isTrackedFile = [](const std::filesystem::path &p) -> bool {
                const std::string name = toLowerAscii(p.filename().string());
                if (name == "modules.lock" || name == "module.manifest" || name == "module.manifest.json")
                {
                    return true;
                }
                return p.has_extension() && toLowerAscii(p.extension().string()) == ".dll";
            };

            auto failEnum = [&](const std::string &reason, const std::string &errorPath) {
                result.ok = false;
                result.reason = reason;
                result.errorPath = errorPath;
            };

            // directory_options::none — permission errors must surface, not skip.
            std::filesystem::recursive_directory_iterator it(
                root,
                std::filesystem::directory_options::none,
                ec);
            if (ec)
            {
                failEnum("modules-tree-enumeration-failed", modulesRoot);
                return result;
            }

            const std::filesystem::recursive_directory_iterator end;
            while (it != end)
            {
                const std::filesystem::path entry = it->path();
                const std::string entryUtf8 = entry.string();
                std::error_code typeEc;

                if (it->is_directory(typeEc))
                {
                    if (typeEc)
                    {
                        failEnum("modules-entry-unreadable", entryUtf8);
                        result.paths.push_back({entryUtf8, true});
                        return result;
                    }
                    result.paths.push_back({entryUtf8, true});
                }
                else
                {
                    if (typeEc)
                    {
                        failEnum("modules-entry-unreadable", entryUtf8);
                        result.paths.push_back({entryUtf8, false});
                        return result;
                    }
                    const bool isFile = it->is_regular_file(typeEc);
                    if (typeEc)
                    {
                        failEnum("modules-entry-unreadable", entryUtf8);
                        result.paths.push_back({entryUtf8, false});
                        return result;
                    }
                    if (isFile && isTrackedFile(entry))
                    {
                        result.paths.push_back({entryUtf8, false});
                    }
                }

                it.increment(ec);
                if (ec)
                {
                    // Increment failed while descending/advancing — typically an
                    // unreadable child directory. Record the current entry path.
                    failEnum("modules-tree-enumeration-failed", entryUtf8);
                    return result;
                }
            }
            return result;
        }

        inline bool auditOneModulesAclPath(const std::string &utf8Path, std::string &reasonOut)
        {
            reasonOut.clear();
            const std::wstring wpath = utf8ToWide(utf8Path);
            if (wpath.empty())
            {
                reasonOut = "invalid-path";
                return false;
            }

            PSID owner = nullptr;
            PACL dacl = nullptr;
            PSECURITY_DESCRIPTOR sd = nullptr;
            const DWORD rc = GetNamedSecurityInfoW(
                const_cast<LPWSTR>(wpath.c_str()), SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &owner, nullptr, &dacl, nullptr, &sd);
            if (rc != ERROR_SUCCESS || !sd)
            {
                reasonOut = "get-security-info-failed:" + std::to_string(rc);
                if (sd)
                {
                    LocalFree(sd);
                }
                return false;
            }

            auto freeSd = [&]() {
                if (sd)
                {
                    LocalFree(sd);
                    sd = nullptr;
                }
            };

            if (!owner || !IsValidSid(owner))
            {
                reasonOut = "owner-missing";
                freeSd();
                return false;
            }
            if (!modulesAclSidIsTrustedPrincipal(owner))
            {
                reasonOut = "owner-not-admin-or-system";
                freeSd();
                return false;
            }

            BOOL daclPresent = FALSE;
            BOOL daclDefaulted = FALSE;
            PACL sdDacl = nullptr;
            if (!GetSecurityDescriptorDacl(sd, &daclPresent, &sdDacl, &daclDefaulted))
            {
                reasonOut = "dacl-read-failed";
                freeSd();
                return false;
            }
            // NULL DACL => everyone full access. Missing DACL => fail closed.
            if (!daclPresent)
            {
                reasonOut = "dacl-missing";
                freeSd();
                return false;
            }
            if (sdDacl == nullptr)
            {
                reasonOut = "dacl-null-everyone";
                freeSd();
                return false;
            }

            ACL_SIZE_INFORMATION aclInfo{};
            if (!GetAclInformation(sdDacl, &aclInfo, sizeof(aclInfo), AclSizeInformation))
            {
                reasonOut = "dacl-info-failed";
                freeSd();
                return false;
            }

            const DWORD dangerous = modulesAclDangerousWriteMask();
            for (DWORD i = 0; i < aclInfo.AceCount; ++i)
            {
                ACE_HEADER *aceHeader = nullptr;
                if (!GetAce(sdDacl, i, reinterpret_cast<LPVOID *>(&aceHeader)) || !aceHeader)
                {
                    reasonOut = "ace-read-failed";
                    freeSd();
                    return false;
                }
                if (aceHeader->AceType != ACCESS_ALLOWED_ACE_TYPE)
                {
                    continue;
                }
                auto *allow = reinterpret_cast<ACCESS_ALLOWED_ACE *>(aceHeader);
                PSID aceSid = reinterpret_cast<PSID>(&allow->SidStart);
                if ((allow->Mask & dangerous) == 0)
                {
                    continue;
                }
                if (modulesAclSidIsTrustedPrincipal(aceSid))
                {
                    continue;
                }
                // Explicit non-admin or unknown principal with write capability.
                if (modulesAclSidIsKnownNonAdmin(aceSid))
                {
                    reasonOut = "non-admin-write-ace";
                }
                else
                {
                    reasonOut = "untrusted-write-ace";
                }
                freeSd();
                return false;
            }

            freeSd();
            return true;
        }

        inline ModulesAclAuditResult auditModulesAcl(const std::string &modulesRoot)
        {
            ModulesAclAuditResult result;
            if (modulesRoot.empty())
            {
                result.ok = false;
                result.reason = "modules-root-empty";
                return result;
            }

            const ModulesAclEnumerateResult enumerated = enumerateModulesAclPaths(modulesRoot);
            if (!enumerated.ok)
            {
                result.ok = false;
                result.reason = enumerated.reason.empty() ? "modules-tree-enumeration-failed"
                                                         : enumerated.reason;
                result.badPaths.push_back(!enumerated.errorPath.empty() ? enumerated.errorPath
                                                                        : modulesRoot);
                return result;
            }
            if (enumerated.paths.empty())
            {
                result.ok = false;
                result.reason = "modules-root-unreadable";
                result.badPaths.push_back(modulesRoot);
                return result;
            }

            for (const ModulesAclPath &entry : enumerated.paths)
            {
                std::string reason;
                if (!auditOneModulesAclPath(entry.path, reason))
                {
                    result.ok = false;
                    result.badPaths.push_back(entry.path);
                    if (result.reason.empty())
                    {
                        result.reason = reason.empty() ? "acl-insecure" : reason;
                    }
                }
            }
            if (result.ok)
            {
                result.reason = "ok";
            }
            return result;
        }

        // Create modules root if needed and apply strict SY+BA ACL to the same
        // path set that auditModulesAcl() inspects. Enumeration failure => false.
        inline bool secureModulesAclTree(const std::string &modulesRoot)
        {
            if (modulesRoot.empty())
            {
                return false;
            }
            std::error_code ec;
            std::filesystem::create_directories(modulesRoot, ec);
            if (ec || !std::filesystem::is_directory(std::filesystem::path(modulesRoot), ec) || ec)
            {
                return false;
            }
            // Ensure root itself is secured even before children exist.
            if (!secureApplyModulesDacl(modulesRoot, true))
            {
                return false;
            }

            const ModulesAclEnumerateResult enumerated = enumerateModulesAclPaths(modulesRoot);
            if (!enumerated.ok)
            {
                return false;
            }
            if (enumerated.paths.empty())
            {
                return false;
            }

            bool ok = true;
            for (const ModulesAclPath &entry : enumerated.paths)
            {
                if (!secureApplyModulesDacl(entry.path, entry.container))
                {
                    ok = false;
                }
            }
            return ok;
        }

        // ---- bootstrap token file ACL audit + repair (P0-04) ---------------------
        // pgs_initial_token.txt holds a plaintext management token on first boot.
        // Unlike modules ACL (write-only concern), any non-admin *read or write*
        // ACE is fail-closed. Owner must still be SYSTEM / Administrators / trusted
        // Administrators-member identity (same trust set as modules).
        //
        // Repair/write DACL is SY+BA only (no interactive user ACE). State-dir ACL
        // still allows runtime identity so the tree is usable; the token secret is
        // stricter so doctor repair cannot widen a LocalSystem-written file.
        //
        // Missing file is not an error: token may not have been generated yet, or
        // an operator may have deleted it after first use. Doctor reports that as
        // info (reason=missing/not-generated).

        struct BootstrapTokenAclAuditResult
        {
            bool ok = true;       // true when missing OR present+secure
            bool present = false; // true only when the file exists on disk
            std::string reason;   // machine-friendly: ok | missing/not-generated | ...
            std::string path;     // UTF-8 path that was audited (may be empty)
        };

        // Any content/access right that would let a non-admin principal read or
        // mutate the bootstrap token. Do not include FILE_ALL_ACCESS (composite).
        inline DWORD bootstrapTokenAclDangerousAccessMask()
        {
            return static_cast<DWORD>(
                FILE_READ_DATA | FILE_READ_EA | FILE_WRITE_DATA | FILE_APPEND_DATA |
                FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | WRITE_DAC | WRITE_OWNER | DELETE |
                GENERIC_READ | GENERIC_WRITE | GENERIC_ALL);
        }

        // Read-only owner/DACL check for one bootstrap token file path.
        // Reuses modules trusted-principal helpers; differs only in the access mask
        // (read+write) and the stable reason codes for token leakage.
        inline bool auditOneBootstrapTokenAclPath(const std::string &utf8Path, std::string &reasonOut)
        {
            reasonOut.clear();
            const std::wstring wpath = utf8ToWide(utf8Path);
            if (wpath.empty())
            {
                reasonOut = "invalid-path";
                return false;
            }

            PSID owner = nullptr;
            PACL dacl = nullptr;
            PSECURITY_DESCRIPTOR sd = nullptr;
            const DWORD rc = GetNamedSecurityInfoW(
                const_cast<LPWSTR>(wpath.c_str()), SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &owner, nullptr, &dacl, nullptr, &sd);
            if (rc != ERROR_SUCCESS || !sd)
            {
                // ACCESS_DENIED is common for non-elevated doctor against a
                // SYSTEM+Administrators protected ProgramData token file. Keep a
                // stable reason so the CLI can map it to warn (cannot diagnose)
                // rather than a hard ACL error.
                if (rc == ERROR_ACCESS_DENIED)
                {
                    reasonOut = "acl-read-access-denied";
                }
                else
                {
                    reasonOut = "get-security-info-failed:" + std::to_string(rc);
                }
                if (sd)
                {
                    LocalFree(sd);
                }
                return false;
            }

            auto freeSd = [&]() {
                if (sd)
                {
                    LocalFree(sd);
                    sd = nullptr;
                }
            };

            if (!owner || !IsValidSid(owner))
            {
                reasonOut = "owner-missing";
                freeSd();
                return false;
            }
            if (!modulesAclSidIsTrustedPrincipal(owner))
            {
                reasonOut = "owner-not-admin-or-system";
                freeSd();
                return false;
            }

            BOOL daclPresent = FALSE;
            BOOL daclDefaulted = FALSE;
            PACL sdDacl = nullptr;
            if (!GetSecurityDescriptorDacl(sd, &daclPresent, &sdDacl, &daclDefaulted))
            {
                reasonOut = "dacl-read-failed";
                freeSd();
                return false;
            }
            if (!daclPresent)
            {
                reasonOut = "dacl-missing";
                freeSd();
                return false;
            }
            if (sdDacl == nullptr)
            {
                reasonOut = "dacl-null-everyone";
                freeSd();
                return false;
            }

            ACL_SIZE_INFORMATION aclInfo{};
            if (!GetAclInformation(sdDacl, &aclInfo, sizeof(aclInfo), AclSizeInformation))
            {
                reasonOut = "dacl-info-failed";
                freeSd();
                return false;
            }

            const DWORD dangerous = bootstrapTokenAclDangerousAccessMask();
            for (DWORD i = 0; i < aclInfo.AceCount; ++i)
            {
                ACE_HEADER *aceHeader = nullptr;
                if (!GetAce(sdDacl, i, reinterpret_cast<LPVOID *>(&aceHeader)) || !aceHeader)
                {
                    reasonOut = "ace-read-failed";
                    freeSd();
                    return false;
                }
                if (aceHeader->AceType != ACCESS_ALLOWED_ACE_TYPE)
                {
                    continue;
                }
                auto *allow = reinterpret_cast<ACCESS_ALLOWED_ACE *>(aceHeader);
                PSID aceSid = reinterpret_cast<PSID>(&allow->SidStart);
                if ((allow->Mask & dangerous) == 0)
                {
                    continue;
                }
                if (modulesAclSidIsTrustedPrincipal(aceSid))
                {
                    continue;
                }
                if (modulesAclSidIsKnownNonAdmin(aceSid))
                {
                    reasonOut = "non-admin-token-access-ace";
                }
                else
                {
                    reasonOut = "untrusted-token-access-ace";
                }
                freeSd();
                return false;
            }

            freeSd();
            return true;
        }

        // Audit the bootstrap token file at utf8Path.
        // - missing  => ok=true, present=false, reason=missing/not-generated
        // - present  => present=true; ok mirrors auditOneBootstrapTokenAclPath
        inline BootstrapTokenAclAuditResult auditBootstrapTokenAcl(const std::string &utf8Path)
        {
            BootstrapTokenAclAuditResult result;
            result.path = utf8Path;
            if (utf8Path.empty())
            {
                result.ok = false;
                result.present = false;
                result.reason = "invalid-path";
                return result;
            }

            std::error_code ec;
            const std::filesystem::path path(utf8Path);
            const bool exists = std::filesystem::exists(path, ec);
            if (ec)
            {
                result.ok = false;
                result.present = false;
                result.reason = "path-stat-failed";
                return result;
            }
            if (!exists)
            {
                result.ok = true;
                result.present = false;
                result.reason = "missing/not-generated";
                return result;
            }
            // A directory at this path is corrupt for token purposes.
            const bool isRegular = std::filesystem::is_regular_file(path, ec);
            if (ec || !isRegular)
            {
                result.ok = false;
                result.present = true;
                result.reason = ec ? "path-stat-failed" : "not-a-regular-file";
                return result;
            }

            result.present = true;
            std::string reason;
            if (!auditOneBootstrapTokenAclPath(utf8Path, reason))
            {
                result.ok = false;
                result.reason = reason.empty() ? "acl-insecure" : reason;
                return result;
            }
            result.ok = true;
            result.reason = "ok";
            return result;
        }

        // Bootstrap token DACL is intentionally stricter than state-dir ACL:
        // SYSTEM + Administrators only. Do NOT inject the interactive/doctor
        // process user SID — repair must not widen a LocalSystem-written secret
        // so medium-IL malware in an admin session can ReadFile the token.
        // (State directories still use secureDaclSddl with runtime identity so
        // console/dev hosts are not locked out of the tree itself.)
        inline std::wstring secureBootstrapTokenDaclSddl()
        {
            return L"D:P(A;;FA;;;SY)(A;;FA;;;BA)";
        }

        // Explicit repair / post-write protect for an existing bootstrap token file:
        // protected SY+BA-only DACL (never inject interactive user), and best-effort
        // OWNER=Administrators. Final success is re-audit: owner must be a trusted
        // principal and DACL must have no non-admin read/write ACEs. Does not create
        // the file if missing.
        inline bool secureBootstrapTokenAcl(const std::string &utf8Path)
        {
            if (utf8Path.empty())
            {
                return false;
            }
            std::error_code ec;
            if (!std::filesystem::is_regular_file(std::filesystem::path(utf8Path), ec) || ec)
            {
                return false;
            }

            const std::wstring wpath = utf8ToWide(utf8Path);
            if (wpath.empty())
            {
                return false;
            }

            PSECURITY_DESCRIPTOR psd = nullptr;
            ULONG sdSize = 0;
            const std::wstring sddl = secureBootstrapTokenDaclSddl();
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.c_str(), SDDL_REVISION_1, &psd, &sdSize) ||
                !psd)
            {
                return false;
            }

            BOOL daclPresent = FALSE;
            BOOL daclDefaulted = FALSE;
            PACL dacl = nullptr;
            GetSecurityDescriptorDacl(psd, &daclPresent, &dacl, &daclDefaulted);

            // Same privilege enable path as modules repair (SeTakeOwnership/SeRestore).
            enableModulesAclRepairPrivileges();

            DWORD adminSidBytes = SECURITY_MAX_SID_SIZE;
            std::vector<unsigned char> adminSidBuf(adminSidBytes);
            PSID adminSid = reinterpret_cast<PSID>(adminSidBuf.data());
            const bool haveAdminSid =
                CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, adminSid, &adminSidBytes) == TRUE;

            DWORD rc = ERROR_INVALID_PARAMETER;
            if (haveAdminSid)
            {
                // Prefer OWNER=BA + protected DACL in one shot when privileges allow.
                rc = SetNamedSecurityInfoW(
                    const_cast<LPWSTR>(wpath.c_str()), SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    adminSid, nullptr, dacl, nullptr);
            }
            if (rc != ERROR_SUCCESS)
            {
                // DACL is mandatory. Owner reassignment is best-effort afterward —
                // non-elevated admin-owned files often cannot become BA-owned, but
                // an Administrators-member owner remains trusted by audit.
                rc = SetNamedSecurityInfoW(
                    const_cast<LPWSTR>(wpath.c_str()), SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    nullptr, nullptr, dacl, nullptr);
                if (rc == ERROR_SUCCESS && haveAdminSid)
                {
                    SetNamedSecurityInfoW(
                        const_cast<LPWSTR>(wpath.c_str()), SE_FILE_OBJECT,
                        OWNER_SECURITY_INFORMATION,
                        adminSid, nullptr, nullptr, nullptr);
                }
            }
            LocalFree(psd);
            if (rc != ERROR_SUCCESS)
            {
                return false;
            }

            // Fail closed on residual untrusted owner or lingering non-admin ACEs.
            std::string reason;
            return auditOneBootstrapTokenAclPath(utf8Path, reason);
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

        inline std::string packageFamilyNameFromPackageFullName(const std::string &packageFullName)
        {
            const std::string full = trim(packageFullName);
            const std::size_t publisherSep = full.rfind("__");
            const std::size_t firstSep = full.find('_');
            if (publisherSep == std::string::npos || firstSep == std::string::npos ||
                firstSep == 0 || publisherSep + 2 >= full.size())
            {
                return std::string();
            }
            return full.substr(0, firstSep) + "_" + full.substr(publisherSep + 2);
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

        struct AppxAumidInfo
        {
            std::string packageName;
            std::string publisher;
            std::string packageFamilyName;
            std::string appId;
            std::string executable;
            std::string aumid;
        };

        inline std::string xmlUnescape(std::string value)
        {
            value = replaceAll(value, "&quot;", "\"");
            value = replaceAll(value, "&apos;", "'");
            value = replaceAll(value, "&lt;", "<");
            value = replaceAll(value, "&gt;", ">");
            value = replaceAll(value, "&amp;", "&");
            return value;
        }

        inline std::string xmlAttrValue(const std::string &tag, const std::string &name)
        {
            const std::string needle = name + "=";
            std::size_t pos = 0;
            while ((pos = tag.find(needle, pos)) != std::string::npos)
            {
                if (pos != 0)
                {
                    const unsigned char prev = static_cast<unsigned char>(tag[pos - 1]);
                    if (std::isalnum(prev) || tag[pos - 1] == '_' || tag[pos - 1] == '-' || tag[pos - 1] == ':')
                    {
                        pos += needle.size();
                        continue;
                    }
                }
                pos += needle.size();
                if (pos >= tag.size() || (tag[pos] != '"' && tag[pos] != '\''))
                {
                    continue;
                }
                const char quote = tag[pos++];
                const std::size_t end = tag.find(quote, pos);
                if (end == std::string::npos)
                {
                    return std::string();
                }
                return xmlUnescape(tag.substr(pos, end - pos));
            }
            return std::string();
        }

        inline std::string readSmallTextFileBestEffort(const std::filesystem::path &path, std::size_t maxBytes = 1024 * 1024)
        {
            std::ifstream in(path, std::ios::in | std::ios::binary);
            if (!in.is_open())
            {
                return std::string();
            }
            std::ostringstream oss;
            char buffer[4096];
            std::size_t total = 0;
            while (in.good() && total < maxBytes)
            {
                in.read(buffer, static_cast<std::streamsize>(std::min<std::size_t>(sizeof(buffer), maxBytes - total)));
                const std::streamsize got = in.gcount();
                if (got <= 0)
                {
                    break;
                }
                oss.write(buffer, got);
                total += static_cast<std::size_t>(got);
            }
            std::string data = oss.str();
            if (data.size() >= 3 &&
                static_cast<unsigned char>(data[0]) == 0xEF &&
                static_cast<unsigned char>(data[1]) == 0xBB &&
                static_cast<unsigned char>(data[2]) == 0xBF)
            {
                data.erase(0, 3);
            }
            if (data.size() >= 2 &&
                ((static_cast<unsigned char>(data[0]) == 0xFF && static_cast<unsigned char>(data[1]) == 0xFE) ||
                 (static_cast<unsigned char>(data[0]) == 0xFE && static_cast<unsigned char>(data[1]) == 0xFF)))
            {
                const bool littleEndian = static_cast<unsigned char>(data[0]) == 0xFF;
                std::wstring wide;
                for (std::size_t i = 2; i + 1 < data.size(); i += 2)
                {
                    const unsigned char a = static_cast<unsigned char>(data[i]);
                    const unsigned char b = static_cast<unsigned char>(data[i + 1]);
                    const wchar_t ch = static_cast<wchar_t>(littleEndian ? (a | (b << 8)) : (b | (a << 8)));
                    wide.push_back(ch);
                }
                return wideToUtf8(wide);
            }
            return data;
        }

        inline std::filesystem::path findAppxManifestForExecutable(const std::string &exePathUtf8)
        {
            std::filesystem::path path = narrowToWideBestEffort(exePathUtf8);
            std::error_code ec;
            if (path.empty() || std::filesystem::is_directory(path, ec))
            {
                return std::filesystem::path();
            }
            path = path.parent_path();
            for (int depth = 0; depth < 8 && !path.empty(); ++depth)
            {
                const std::filesystem::path manifest = path / L"AppxManifest.xml";
                if (std::filesystem::is_regular_file(manifest, ec))
                {
                    return manifest;
                }
                path = path.parent_path();
            }
            return std::filesystem::path();
        }

        inline bool deriveAumidFromAppxManifestText(const std::string &manifestXml,
                                                   const std::string &exePathUtf8,
                                                   AppxAumidInfo &out,
                                                   std::string &err)
        {
            out = AppxAumidInfo{};
            err.clear();
            const std::size_t identityOpen = manifestXml.find("<Identity");
            if (identityOpen == std::string::npos)
            {
                err = "AppxManifest.xml is missing <Identity>";
                return false;
            }
            const std::size_t identityClose = manifestXml.find('>', identityOpen);
            if (identityClose == std::string::npos)
            {
                err = "AppxManifest.xml has an unterminated <Identity>";
                return false;
            }
            const std::string identityTag = manifestXml.substr(identityOpen, identityClose - identityOpen + 1);
            out.packageName = xmlAttrValue(identityTag, "Name");
            out.publisher = xmlAttrValue(identityTag, "Publisher");
            if (out.packageName.empty() || out.publisher.empty())
            {
                err = "AppxManifest.xml Identity requires Name and Publisher";
                return false;
            }
            out.packageFamilyName = packageFamilyNameFrom(out.packageName, out.publisher);
            if (out.packageFamilyName.empty())
            {
                err = "failed to compute PackageFamilyName";
                return false;
            }

            const std::filesystem::path exePath = narrowToWideBestEffort(exePathUtf8);
            const std::string exeFile = toLowerAscii(wideToUtf8(exePath.filename().wstring()));
            std::size_t pos = 0;
            std::string firstAppId;
            std::string matchedAppId;
            std::string matchedExecutable;
            while ((pos = manifestXml.find("<Application", pos)) != std::string::npos)
            {
                const std::size_t tagEnd = manifestXml.find('>', pos);
                if (tagEnd == std::string::npos)
                {
                    break;
                }
                const std::string tag = manifestXml.substr(pos, tagEnd - pos + 1);
                const std::string id = xmlAttrValue(tag, "Id");
                const std::string executable = xmlAttrValue(tag, "Executable");
                if (!id.empty() && firstAppId.empty())
                {
                    firstAppId = id;
                }
                if (!id.empty() && !executable.empty())
                {
                    const std::filesystem::path executablePath = narrowToWideBestEffort(executable);
                    const std::string executableFile = toLowerAscii(wideToUtf8(executablePath.filename().wstring()));
                    if (executableFile == exeFile || toLowerAscii(executable) == exeFile)
                    {
                        matchedAppId = id;
                        matchedExecutable = executable;
                        break;
                    }
                }
                pos = tagEnd + 1;
            }
            out.appId = !matchedAppId.empty() ? matchedAppId : firstAppId;
            out.executable = matchedExecutable;
            if (out.appId.empty())
            {
                err = "AppxManifest.xml has no Application Id";
                return false;
            }
            out.aumid = out.packageFamilyName + "!" + out.appId;
            return true;
        }

        inline bool deriveAumidFromAppxManifestFile(const std::filesystem::path &manifestPath,
                                                   const std::string &exePathUtf8,
                                                   AppxAumidInfo &out,
                                                   std::string &err)
        {
            const std::string xml = readSmallTextFileBestEffort(manifestPath);
            if (xml.empty())
            {
                err = "failed to read AppxManifest.xml";
                return false;
            }
            return deriveAumidFromAppxManifestText(xml, exePathUtf8, out, err);
        }

        inline bool deriveAumidForWindowsAppPath(const std::string &exePathUtf8, AppxAumidInfo &out, std::string &err)
        {
            const std::filesystem::path manifest = findAppxManifestForExecutable(exePathUtf8);
            if (manifest.empty())
            {
                err = "AppxManifest.xml not found above executable";
                return false;
            }
            if (!deriveAumidFromAppxManifestFile(manifest, exePathUtf8, out, err))
            {
                return false;
            }
            const std::string packageFullName = wideToUtf8(manifest.parent_path().filename().wstring());
            const std::string pfnFromPath = packageFamilyNameFromPackageFullName(packageFullName);
            if (!pfnFromPath.empty())
            {
                out.packageFamilyName = pfnFromPath;
                out.aumid = out.packageFamilyName + "!" + out.appId;
            }
            return true;
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
