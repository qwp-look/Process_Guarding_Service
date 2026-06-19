/*
 * pgs_ppl_module.cpp — PGS PPL module.
 *
 * Implements the PGModule C ABI to provide process PPL (Protected Process Light)
 * protection control: set / get / clear. Internally reuses the StarlightGUI
 * Sirius.sys kernel driver via SiriusDriverClient (Apache-2.0, author "Stars").
 *
 * Request KV examples (forwarded by PGS "ppl" / "module call ppl" commands):
 *   op=set;pid=1234;signer=Antimalware
 *   op=get;pid=1234
 *   op=clear;pid=1234
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#define PG_MODULE_EXPORTS

#include <windows.h>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>

#include "Process_Guard/PGModule.h"
#include "SiriusDriverClient.h"

namespace
{
    HMODULE g_hSelfModule = nullptr;
    pgs_ppl::SiriusDriverClient g_driver;

    // PPL is always Protected Light, matching StarlightGUI's SetPPL behavior
    // (SetPPL hardcodes PsProtectedTypeProtectedLight and lets only the signer vary).
    // "clear" is the exception: it sets type=None to remove protection entirely.
    constexpr UCHAR kProtectionType = PsProtectedTypeProtectedLight;

    struct SignerMap
    {
        const char *name;
        UCHAR value;
    };
    // String -> PS_PROTECTED_SIGNER mapping. Accepted case-insensitively by
    // parseSigner; "CodeGen"/"Codegen" are both listed for convenience. Numeric
    // 0..255 also accepted so callers can pass raw enum values. signerName() is
    // the reverse lookup for human-readable responses.
    const SignerMap kSigners[] = {
        {"None", PsProtectedSignerNone},
        {"Authenticode", PsProtectedSignerAuthenticode},
        {"CodeGen", PsProtectedSignerCodeGen},
        {"Codegen", PsProtectedSignerCodeGen},
        {"Antimalware", PsProtectedSignerAntimalware},
        {"Lsa", PsProtectedSignerLsa},
        {"Windows", PsProtectedSignerWindows},
        {"WinTcb", PsProtectedSignerWinTcb},
        {"WinSystem", PsProtectedSignerWinSystem},
        {"App", PsProtectedSignerApp},
    };

    const char *signerName(UCHAR value)
    {
        for (const SignerMap &s : kSigners)
        {
            if (s.value == value)
                return s.name;
        }
        return "Unknown";
    }

    bool parseSigner(const std::string &text, UCHAR &out)
    {
        for (const SignerMap &s : kSigners)
        {
            if (_stricmp(text.c_str(), s.name) == 0)
            {
                out = s.value;
                return true;
            }
        }
        // Also accept raw numeric signer values.
        char *end = nullptr;
        long v = std::strtol(text.c_str(), &end, 10);
        if (end != text.c_str() && *end == '\0' && v >= 0 && v <= 255)
        {
            out = static_cast<UCHAR>(v);
            return true;
        }
        return false;
    }

    // Minimal KV parser for "op=set;pid=1234;signer=Antimalware". Returns the
    // value for `key` (up to the next ';' or end). Empty string if absent.
    std::string kvValue(const std::string &kv, const std::string &key)
    {
        std::string needle = key + "=";
        std::size_t pos = kv.find(needle);
        if (pos == std::string::npos)
            return std::string();
        pos += needle.size();
        std::size_t end = kv.find(';', pos);
        return (end == std::string::npos) ? kv.substr(pos) : kv.substr(pos, end - pos);
    }

    bool parseUlong(const std::string &s, ULONG &out)
    {
        if (s.empty())
            return false;
        char *end = nullptr;
        unsigned long v = std::strtoul(s.c_str(), &end, 10);
        if (end == s.c_str() || *end != '\0')
            return false;
        out = static_cast<ULONG>(v);
        return true;
    }

    void setResponse(char *buf, size_t bufsize, const std::string &msg)
    {
        if (!buf || bufsize == 0)
            return;
        size_t n = msg.size();
        if (n >= bufsize)
            n = bufsize - 1;
        std::memcpy(buf, msg.c_str(), n);
        buf[n] = '\0';
    }
} // namespace

extern "C" BOOL WINAPI DllMain(HINSTANCE hInstDLL, DWORD reason, LPVOID /*reserved*/)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        g_hSelfModule = hInstDLL;
        DisableThreadLibraryCalls(hInstDLL);
    }
    return TRUE;
}

PG_MODULE_API const char *PG_GetName(void)
{
    return "ppl";
}

PG_MODULE_API const char *PG_GetVersion(void)
{
    return "1.0.0";
}

PG_MODULE_API unsigned int PG_GetAbiVersion(void)
{
    return PG_MODULE_ABI_VERSION;
}

// PG_Init: store the module's own HMODULE (set in DllMain) on the driver
// client so it can locate Sirius.sys beside the DLL. We deliberately do NOT
// open the device here: the driver may not be loadable yet (test-signing off),
// and failing PG_Init would reject the whole module. Defer to first PG_Invoke.
PG_MODULE_API int PG_Init(void * /*reserved*/)
{
    g_driver.setSelfModule(g_hSelfModule);
    // Do not open the device at init: Sirius.sys may not be loadable yet (e.g.
    // test-signing not enabled). Defer to first use so "ppl get" can still
    // return a clean error instead of failing module load.
    return 0;
}

PG_MODULE_API void PG_Shutdown(void)
{
    // Device handle leaks at process exit; nothing to do here.
}

// PG_Invoke: parse "op=<set|get|clear>;pid=N[;signer=X]" and dispatch.
//   set   -> SiriusDriverClient::setPPL(pid, Light, signer)
//   get   -> SiriusDriverClient::getPPL(pid, ...)  (returns type+signer)
//   clear -> setPPL(pid, None, None)               (removes protection)
// All failures are returned as "ERR <reason>" with non-zero rc; the module
// never throws into PGS.
PG_MODULE_API int PG_Invoke(const char *request, char *responseBuf, size_t responseBufSize)
{
    std::string req = request ? request : "";
    std::string op = kvValue(req, "op");
    std::string pidText = kvValue(req, "pid");

    ULONG pid = 0;
    if (!parseUlong(pidText, pid))
    {
        setResponse(responseBuf, responseBufSize, "ERR invalid or missing pid");
        return 1;
    }

    if (op == "set")
    {
        std::string signerText = kvValue(req, "signer");
        UCHAR signer = 0;
        if (!parseSigner(signerText, signer))
        {
            setResponse(responseBuf, responseBufSize, "ERR invalid signer: " + signerText);
            return 1;
        }
        std::string err;
        if (g_driver.setPPL(pid, kProtectionType, signer, err))
        {
            setResponse(responseBuf, responseBufSize,
                        std::string("OK set type=Light signer=") + signerName(signer));
            return 0;
        }
        setResponse(responseBuf, responseBufSize, "ERR " + err);
        return 1;
    }

    if (op == "get")
    {
        UCHAR type = 0, signer = 0;
        std::string err;
        if (g_driver.getPPL(pid, type, signer, err))
        {
            const char *typeName =
                (type == PsProtectedTypeNone) ? "None" :
                (type == PsProtectedTypeProtectedLight) ? "Light" :
                (type == PsProtectedTypeProtected) ? "Protected" : "Unknown";
            setResponse(responseBuf, responseBufSize,
                        std::string("OK type=") + typeName + " signer=" + signerName(signer));
            return 0;
        }
        setResponse(responseBuf, responseBufSize, "ERR " + err);
        return 1;
    }

    if (op == "clear")
    {
        std::string err;
        // Clearing = remove protection. Set signer None with type None so the
        // process is no longer protected.
        if (g_driver.setPPL(pid, PsProtectedTypeNone, PsProtectedSignerNone, err))
        {
            setResponse(responseBuf, responseBufSize, "OK cleared");
            return 0;
        }
        setResponse(responseBuf, responseBufSize, "ERR " + err);
        return 1;
    }

    setResponse(responseBuf, responseBufSize, "ERR unknown op: " + op);
    return 1;
}
