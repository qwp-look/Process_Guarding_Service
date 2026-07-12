/*
 * SiriusDriverClient.h — minimal Sirius kernel-driver client for the PGS PPL module.
 *
 * Derived from StarlightGUI's DriverUtils::LoadKernelDriver and
 * KernelInstance::GetDriverDevice / SetPPL / SiQueryProcessInformation
 * (Apache-2.0, author "Stars"). Adapted to a self-contained header with only
 * the PPL-protection operations. See ../../NOTICE for attribution.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef PGS_SIRIUS_DRIVER_CLIENT_H
#define PGS_SIRIUS_DRIVER_CLIENT_H

#include <windows.h>
#include <winsvc.h>
#include <algorithm>
#include <cwctype>
#include <string>
#include <vector>

#include "SiriusIO.h"

namespace pgs_ppl
{

    // Service name used by StarlightGUI to register Sirius.sys. Reused so PGS
    // shares the same driver instance if StarlightGUI already loaded it.
    inline const wchar_t *kSiriusServiceName = L"Sirius for StarlightGUI";
    inline const wchar_t *kSiriusDeviceName = L"\\\\.\\Sirius";

    class SiriusDriverClient
    {
    public:
        // hSelfModule is the HMODULE of the PPL module DLL, used to locate
        // Sirius.sys beside the module. May be nullptr (falls back to main exe).
        SiriusDriverClient();
        ~SiriusDriverClient();
        void setSelfModule(HMODULE hSelf) { m_hSelf = hSelf; }

        // Lazily load the driver (if needed) and open the device. Returns true
        // when the device handle is ready. Thread-safe (single mutex).
        bool ensureDevice(std::string &err);

        // Set process protection. type = PS_PROTECTED_TYPE, signer = PS_PROTECTED_SIGNER.
        bool setPPL(ULONG pid, UCHAR type, UCHAR signer, std::string &err);

        // Query process protection into out/outSigner.
        bool getPPL(ULONG pid, UCHAR &outType, UCHAR &outSigner, std::string &err);

        // Release the device handle and, if PGS created the Sirius service,
        // stop + delete it so the ARK-class driver does not stay loaded.
        void shutdown();

    private:
        HMODULE m_hSelf = nullptr;
        bool m_weCreatedService = false;
        HANDLE m_device = nullptr;
        std::wstring m_driverPath;
        CRITICAL_SECTION m_lock;

        // The critical section is initialized in the constructor (not lazily)
        // so concurrent first-callers cannot race on InitializeCriticalSection.
        void lock() { EnterCriticalSection(&m_lock); }
        void unlock() { LeaveCriticalSection(&m_lock); }


        std::wstring resolveDriverPath();
        bool loadSiriusDriver(const std::wstring &driverPath, std::string &err);
        static std::string toUtf8(const std::wstring &w);
        static std::wstring dirOf(HMODULE hModule);
        static std::wstring normalizePathForCompare(std::wstring path);
        static bool serviceImagePathMatches(SC_HANDLE service, const std::wstring &expectedPath, std::string &err);
    };

    inline SiriusDriverClient::SiriusDriverClient()
{
    InitializeCriticalSection(&m_lock);
}

inline SiriusDriverClient::~SiriusDriverClient()
{
    shutdown();
    DeleteCriticalSection(&m_lock);
}
inline std::string SiriusDriverClient::toUtf8(const std::wstring &w)
    {
        if (w.empty())
            return std::string();
        int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string out(n > 0 ? n - 1 : 0, '\0');
        if (n > 0)
            WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, out.data(), n, nullptr, nullptr);
        return out;
    }

    inline std::wstring SiriusDriverClient::dirOf(HMODULE hModule)
    {
        wchar_t buf[MAX_PATH] = {0};
        DWORD len = GetModuleFileNameW(hModule, buf, MAX_PATH);
        if (len == 0 || len >= MAX_PATH)
            return L"";
        std::wstring p(buf);
        std::size_t slash = p.find_last_of(L"\\/");
        return (slash == std::wstring::npos) ? std::wstring(L".") : p.substr(0, slash);
    }

    inline std::wstring SiriusDriverClient::normalizePathForCompare(std::wstring path)
    {
        while (path.size() >= 2 && path.front() == L'"' && path.back() == L'"')
        {
            path = path.substr(1, path.size() - 2);
        }
        if (path.rfind(L"\\??\\", 0) == 0)
        {
            path = path.substr(4);
        }
        else if (path.rfind(L"\\\\?\\", 0) == 0)
        {
            path = path.substr(4);
        }

        std::vector<wchar_t> full(MAX_PATH, L'\0');
        DWORD len = GetFullPathNameW(path.c_str(), static_cast<DWORD>(full.size()), full.data(), nullptr);
        if (len >= full.size())
        {
            full.assign(len + 1, L'\0');
            len = GetFullPathNameW(path.c_str(), static_cast<DWORD>(full.size()), full.data(), nullptr);
        }
        std::wstring normalized = (len > 0 && len < full.size()) ? std::wstring(full.data(), len) : path;
        std::replace(normalized.begin(), normalized.end(), L'/', L'\\');
        std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](wchar_t ch) {
            return static_cast<wchar_t>(std::towlower(ch));
        });
        return normalized;
    }

    inline bool SiriusDriverClient::serviceImagePathMatches(SC_HANDLE service, const std::wstring &expectedPath, std::string &err)
    {
        DWORD needed = 0;
        QueryServiceConfigW(service, nullptr, 0, &needed);
        if (needed == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            err = "QueryServiceConfig(Sirius) failed, error=" + std::to_string(GetLastError());
            return false;
        }

        std::vector<BYTE> buffer(needed);
        auto *config = reinterpret_cast<QUERY_SERVICE_CONFIGW *>(buffer.data());
        if (!QueryServiceConfigW(service, config, needed, &needed))
        {
            err = "QueryServiceConfig(Sirius) failed, error=" + std::to_string(GetLastError());
            return false;
        }

        const std::wstring actual = config->lpBinaryPathName ? config->lpBinaryPathName : L"";
        if (normalizePathForCompare(actual) != normalizePathForCompare(expectedPath))
        {
            err = "existing Sirius service points to unexpected driver: " + toUtf8(actual);
            return false;
        }
        return true;
    }

    // Find Sirius.sys: prefer beside this module DLL, then beside the main
    // exe. Returns the first existing candidate; if none exists, falls back to
    // the module directory so the subsequent load fails with a clear error.
    inline std::wstring SiriusDriverClient::resolveDriverPath()
    {
        // Prefer Sirius.sys beside this module DLL, then beside the main exe.
        std::wstring dirs[2] = {dirOf(m_hSelf), dirOf(nullptr)};
        for (const std::wstring &d : dirs)
        {
            if (d.empty())
                continue;
            std::wstring candidate = d + L"\\Sirius.sys";
            if (GetFileAttributesW(candidate.c_str()) != INVALID_FILE_ATTRIBUTES)
                return candidate;
        }
        // Fallback: assume beside module even if not present (load will fail with a clear error).
        std::wstring d = dirs[0].empty() ? std::wstring(L".") : dirs[0];
        return d + L"\\Sirius.sys";
    }

    // Load (or attach to) the Sirius driver service. Mirrors StarlightGUI's
    // DriverUtils::LoadKernelDriver: open the SCM, open/create the service named
    // "Sirius for StarlightGUI", start it if stopped. Reusing the same service
    // name means PGS piggybacks on a driver StarlightGUI already loaded. Returns
    // true if the service is (now) running; the caller still opens the device
    // separately. err is set only on hard SCM failures.
    inline bool SiriusDriverClient::loadSiriusDriver(const std::wstring &driverPath, std::string &err)
    {
        SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!hSCM)
        {
            err = "OpenSCManager failed, error=" + std::to_string(GetLastError());
            return false;
        }

        SC_HANDLE hService = OpenServiceW(hSCM, kSiriusServiceName, SERVICE_ALL_ACCESS);
        if (hService)
        {
            // Pre-existing service (e.g. loaded by StarlightGUI): we did NOT
            // create it, so shutdown() must leave it alone. Do not trust the
            // service name alone: require the ImagePath to match the Sirius.sys
            // that ships beside this module.
            m_weCreatedService = false;
            if (!serviceImagePathMatches(hService, driverPath, err))
            {
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCM);
                return false;
            }
            SERVICE_STATUS status{};
            if (QueryServiceStatus(hService, &status))
            {
                if (status.dwCurrentState == SERVICE_STOPPED)
                    StartServiceW(hService, 0, nullptr);
            }
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return true;
        }

        hService = CreateServiceW(hSCM, kSiriusServiceName, kSiriusServiceName, SERVICE_ALL_ACCESS,
                                  SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                                  driverPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!hService)
        {
            DWORD le = GetLastError();
            CloseServiceHandle(hSCM);
            err = "CreateService failed, error=" + std::to_string(le);
            return false;
        }
        // We created this service, so shutdown() is allowed to stop + delete it
        // to avoid leaving the ARK-class driver loaded after PGS exits.
        m_weCreatedService = true;
        StartServiceW(hService, 0, nullptr);
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return true;
    }

    // Lazily make the device handle ready. Idempotent and thread-safe
    // (CRITICAL_SECTION). Resolves Sirius.sys beside the module DLL (else beside
    // the main exe), asks the SCM to load it, then opens \\.\Sirius. The SCM
    // step must succeed or attach to a verified service before we open the
    // device. Otherwise a pre-existing unrelated \\.\Sirius device could be
    // mistaken for the bundled driver.
    inline bool SiriusDriverClient::ensureDevice(std::string &err)
    {
        lock();
        if (m_device && m_device != INVALID_HANDLE_VALUE)
        {
            unlock();
            return true;
        }
        if (m_driverPath.empty())
            m_driverPath = resolveDriverPath();

        if (!loadSiriusDriver(m_driverPath, err))
        {
            unlock();
            return false;
        }

        HANDLE device = CreateFileW(kSiriusDeviceName, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                    OPEN_EXISTING, 0, nullptr);
        if (device == INVALID_HANDLE_VALUE)
        {
            if (err.empty())
                err = "CreateFile(" + toUtf8(kSiriusDeviceName) + ") failed, error=" + std::to_string(GetLastError());
            unlock();
            return false;
        }
        m_device = device;
        err.clear();
        unlock();
        return true;
    }

    // Set process protection. Fills SI_PROCESS_PROTECTION{type, signer} and
    // issues IOCTL_SIRIUS_SET_PROCESS_INFORMATION with
    // ProcessSetInformation::Protection. The driver reads the protection struct
    // via the Buffer pointer inside the METHOD_BUFFERED request (same contract
    // StarlightGUI uses). type = PS_PROTECTED_TYPE, signer = PS_PROTECTED_SIGNER.
    inline bool SiriusDriverClient::setPPL(ULONG pid, UCHAR type, UCHAR signer, std::string &err)
    {
        std::string e;
        if (!ensureDevice(e))
        {
            err = e.empty() ? std::string("driver device not available") : e;
            return false;
        }
        SI_PROCESS_PROTECTION prot{};
        prot.ProtectionType = type;
        prot.ProtectionLevel = signer;

        SI_PROCESS_INFORMATION request{};
        request.ProcessInformation = (ULONG)ProcessSetInformation::Protection;
        request.PID = pid;
        request.Buffer = &prot;
        request.Argument = 0;

        BOOL status = DeviceIoControl(m_device, IOCTL_SIRIUS_SET_PROCESS_INFORMATION,
                                      &request, sizeof(request), nullptr, 0, nullptr, nullptr);
        if (!status)
        {
            err = "DeviceIoControl(set Protection) failed, error=" + std::to_string(GetLastError());
            return false;
        }
        return true;
    }

    // Query process protection. Same IOCTL shape as set but with the QUERY
    // code and ProcessGetInformation::Protection; the driver writes the current
    // protection back into the caller-provided SI_PROCESS_PROTECTION.
    inline bool SiriusDriverClient::getPPL(ULONG pid, UCHAR &outType, UCHAR &outSigner, std::string &err)
    {
        std::string e;
        if (!ensureDevice(e))
        {
            err = e.empty() ? std::string("driver device not available") : e;
            return false;
        }
        SI_PROCESS_PROTECTION prot{};
        SI_PROCESS_INFORMATION request{};
        request.ProcessInformation = (ULONG)ProcessGetInformation::Protection;
        request.PID = pid;
        request.Buffer = &prot;
        request.Argument = 0;

        BOOL status = DeviceIoControl(m_device, IOCTL_SIRIUS_QUERY_PROCESS_INFORMATION,
                                      &request, sizeof(request), &request, sizeof(request), nullptr, nullptr);
        if (!status)
        {
            err = "DeviceIoControl(query Protection) failed, error=" + std::to_string(GetLastError());
            return false;
        }
        outType = prot.ProtectionType;
        outSigner = prot.ProtectionLevel;
        return true;
    }

    // Release the device handle. If PGS created the Sirius service itself,
    // stop and delete it so the powerful ARK-class kernel driver does not stay
    // loaded (and reopenable by other local principals) after PGS exits. If the
    // service pre-existed (e.g. StarlightGUI loaded it), it is left untouched.
    inline void SiriusDriverClient::shutdown()
    {
        lock();
        if (m_device && m_device != INVALID_HANDLE_VALUE)
        {
            CloseHandle(m_device);
            m_device = nullptr;
        }
        const bool weCreated = m_weCreatedService;
        m_weCreatedService = false;
        unlock();

        if (weCreated)
        {
            SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
            if (!hSCM)
                return;
            SC_HANDLE hService = OpenServiceW(hSCM, kSiriusServiceName,
                                              SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
            if (hService)
            {
                SERVICE_STATUS status{};
                ControlService(hService, SERVICE_CONTROL_STOP, &status);
                DeleteService(hService);
                CloseServiceHandle(hService);
            }
            CloseServiceHandle(hSCM);
        }
    }
} // namespace pgs_ppl

#endif // PGS_SIRIUS_DRIVER_CLIENT_H
