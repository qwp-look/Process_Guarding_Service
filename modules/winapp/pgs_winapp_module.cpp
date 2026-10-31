/*
 * pgs_winapp_module.cpp - WindowsApps (AUMID) launcher provider (ABI v2).
 *
 * Provider-class module (manifest class="provider", default opt-in). It owns
 * the WindowsApps activation mechanics — IApplicationActivationManager
 * ActivateApplication with a ShellExecuteExW("shell:AppsFolder\<AUMID>")
 * fallback — so the service core keeps only the generic Win32 restart path
 * plus session-token plumbing around the provider call.
 *
 * Contract (KV request via PG_Invoke):
 *   op=activate;aumid_b64=<b64>;args_b64=<b64>
 * Response:
 *   OK pid=<pid>            on success (caller opens its own process handle)
 *   ERR <reason>            on failure
 *
 * The caller is responsible for impersonating the target user before invoking:
 * ActivateApplication runs under the calling thread token, so the service
 * restart path sets its impersonation token around the call and the CLI simply
 * runs in the interactive session.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#define PG_MODULE_EXPORTS

// MinGW only exposes IApplicationActivationManager with NTDDI >= Win8; define
// it here so the module builds without per-target build-script flags.
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x06020000
#endif

#include <windows.h>
#include <objbase.h>
#include <initguid.h>
#include <shobjidl.h>
#include <shlobj.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "Process_Guard/PGModule.h"

namespace
{
    std::string trim(std::string value)
    {
        const char *ws = " \t\r\n";
        const std::size_t first = value.find_first_not_of(ws);
        if (first == std::string::npos) return std::string();
        const std::size_t last = value.find_last_not_of(ws);
        return value.substr(first, last - first + 1);
    }

    std::string lower(std::string value)
    {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });
        return value;
    }

    std::string requestValue(const std::string &request, const std::string &key)
    {
        const std::string needle = key + "=";
        std::size_t pos = request.find(needle);
        if (pos == std::string::npos) return std::string();
        pos += needle.size();
        const std::size_t end = request.find(';', pos);
        return end == std::string::npos ? request.substr(pos) : request.substr(pos, end - pos);
    }

    void setResponse(char *responseBuf, size_t responseBufSize, const std::string &text)
    {
        if (!responseBuf || responseBufSize == 0) return;
        const std::size_t n = std::min(responseBufSize - 1, text.size());
        std::memcpy(responseBuf, text.data(), n);
        responseBuf[n] = '\0';
    }

    std::string base64Decode(const std::string &input)
    {
        static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::vector<int> table(256, -1);
        for (int i = 0; i < 64; ++i) table[static_cast<unsigned char>(chars[i])] = i;
        std::string out;
        int val = 0;
        int valb = -8;
        for (unsigned char c : input)
        {
            if (c == '=') break;
            if (table[c] < 0) continue;
            val = (val << 6) + table[c];
            valb += 6;
            if (valb >= 0)
            {
                out.push_back(static_cast<char>((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        return out;
    }

    std::wstring narrowToWide(const std::string &utf8)
    {
        if (utf8.empty()) return std::wstring();
        const int size = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
        if (size <= 0) return std::wstring();
        std::wstring out(static_cast<std::size_t>(size), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &out[0], size);
        out.pop_back();
        return out;
    }

    std::string hresultText(HRESULT hr)
    {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%08lX", static_cast<unsigned long>(hr));
        return std::string(buf);
    }

    // Activate the AUMID and return the new pid. Activation mechanics only:
    // the caller opens its own process handle with the access it needs.
    int activateAumid(const std::string &aumidUtf8, const std::string &argsUtf8, std::string &outError)
    {
        if (aumidUtf8.empty())
        {
            outError = "AUMID is empty";
            return 0;
        }
        const std::wstring aumidW = narrowToWide(aumidUtf8);
        const std::wstring argsW = narrowToWide(argsUtf8);
        if (aumidW.empty())
        {
            outError = "AUMID conversion failed";
            return 0;
        }

        DWORD activatedPid = 0;
        HRESULT comInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        const bool comUsable = SUCCEEDED(comInit) || comInit == RPC_E_CHANGED_MODE;
        if (comUsable)
        {
            IApplicationActivationManager *act = nullptr;
            HRESULT hr = CoCreateInstance(CLSID_ApplicationActivationManager, nullptr,
                                          CLSCTX_LOCAL_SERVER | CLSCTX_NO_FAILURE_LOG,
                                          IID_PPV_ARGS(&act));
            if (SUCCEEDED(hr) && act)
            {
                hr = act->ActivateApplication(aumidW.c_str(), argsW.empty() ? L"" : argsW.c_str(), AO_NONE, &activatedPid);
                act->Release();
                if (SUCCEEDED(hr) && activatedPid != 0)
                {
                    if (comInit == S_OK || comInit == S_FALSE)
                    {
                        CoUninitialize();
                    }
                    return static_cast<int>(activatedPid);
                }
                outError = "ActivateApplication failed: " + hresultText(hr);
            }
            else
            {
                outError = "CoCreateInstance(ApplicationActivationManager) failed: " + hresultText(hr);
            }
            if (comInit == S_OK || comInit == S_FALSE)
            {
                CoUninitialize();
            }
        }
        else
        {
            outError = "CoInitializeEx failed: " + hresultText(comInit);
        }

        // Fallback: ShellExecuteExW("shell:AppsFolder\<AUMID>"). The broker
        // often does not hand back hProcess, so this path is best-effort.
        std::wstring file = L"shell:AppsFolder\\" + aumidW;
        std::vector<wchar_t> paramsBuf(argsW.begin(), argsW.end());
        paramsBuf.push_back(L'\0');
        SHELLEXECUTEINFOW sei{};
        sei.cbSize = sizeof(sei);
        sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC;
        sei.lpFile = file.c_str();
        sei.lpParameters = argsW.empty() ? nullptr : paramsBuf.data();
        sei.nShow = SW_SHOWNORMAL;
        if (ShellExecuteExW(&sei))
        {
            if (sei.hProcess)
            {
                activatedPid = GetProcessId(sei.hProcess);
                CloseHandle(sei.hProcess);
            }
            if (activatedPid != 0)
            {
                outError.clear();
                return static_cast<int>(activatedPid);
            }
        }
        outError += outError.empty() ? std::string("ShellExecuteExW failed") : std::string("; ShellExecuteExW failed");
        return 0;
    }
} // namespace

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}

extern "C" {

PG_MODULE_API const char *PG_GetName(void) { return "winapp"; }
PG_MODULE_API const char *PG_GetVersion(void) { return "1.0.0"; }
PG_MODULE_API unsigned int PG_GetAbiVersion(void) { return PG_MODULE_ABI_VERSION; }
PG_MODULE_API const char *PG_GetManifest(void)
{
    return "name=winapp;version=1.0.0;abi=2;class=provider;"
           "summary=WindowsApps AUMID launcher provider;"
           "capabilities=launcher.winapp";
}

PG_MODULE_API int PG_Init(void * /*reserved*/)
{
    // Stateless provider: no host services needed.
    return 0;
}

PG_MODULE_API void PG_Shutdown(void)
{
}

PG_MODULE_API int PG_Invoke(const char *request, char *responseBuf, size_t responseBufSize)
{
    const std::string req = request ? request : "";
    const std::string op = lower(trim(requestValue(req, "op").empty() ? "activate" : requestValue(req, "op")));
    if (op != "activate")
    {
        setResponse(responseBuf, responseBufSize, "ERR unknown winapp op");
        return 1;
    }

    const std::string aumid = base64Decode(requestValue(req, "aumid_b64"));
    const std::string args = base64Decode(requestValue(req, "args_b64"));
    std::string error;
    const int pid = activateAumid(aumid, args, error);
    if (pid <= 0)
    {
        setResponse(responseBuf, responseBufSize, "ERR " + (error.empty() ? std::string("activation failed") : error));
        return 1;
    }
    setResponse(responseBuf, responseBufSize, "OK pid=" + std::to_string(pid));
    return 0;
}

} // extern "C"
