/*
 * pgs_ppl_module.cpp — PGS PPL module.
 *
 * Implements the PGModule C ABI to provide process PPL (Protected Process Light)
 * protection control: set / get / clear. Internally reuses the StarlightGUI
 * Sirius.sys kernel driver via SiriusDriverClient (Apache-2.0, author "Stars").
 *
 * Request examples (PGS "ppl" compatibility routes through module invoke; KV stays supported):
 *   {"jsonrpc":"2.0","module":"ppl","method":"ppl.set","params":{"pid":1234,"signer":"Antimalware"}}
 *   op=set;pid=1234;signer=Antimalware
 *   op=get;pid=1234
 *   op=clear;pid=1234
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#define PG_MODULE_EXPORTS

#include <windows.h>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>

#include "Process_Guard/PGModule.h"
#include "Process_Guard/PGUtil.h"
#include "SiriusDriverClient.h"

namespace
{
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
    // parseSigner; "CodeGen"/"Codegen" are both listed for convenience.
    // Numeric raw values are rejected so the module stays on the documented
    // signer names instead of an open-ended 0..255 enum surface.
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
        return false;
    }

    // Parse PID strictly in the documented 1..DWORD_MAX range. Rejects zero,
    // overflow, and any non-digit input.
    bool parsePid(const std::string &s, ULONG &out)
    {
        if (s.empty())
            return false;
        for (char c : s)
        {
            if (c < '0' || c > '9')
                return false;
        }
        try
        {
            const unsigned long long v = std::stoull(s);
            if (v < 1ull || v > 0xFFFFFFFFull)
                return false;
            out = static_cast<ULONG>(v);
            return true;
        }
        catch (...)
        {
            return false;
        }
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

    std::string jsonStringValue(const std::string &text, const std::string &key)
    {
        const std::string needle = "\"" + key + "\"";
        std::size_t pos = text.find(needle);
        if (pos == std::string::npos)
            return std::string();
        pos = text.find(':', pos + needle.size());
        if (pos == std::string::npos)
            return std::string();
        ++pos;
        while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos])))
            ++pos;
        if (pos >= text.size() || text[pos] != '"')
            return std::string();
        ++pos;
        std::string out;
        bool escaped = false;
        for (; pos < text.size(); ++pos)
        {
            const char ch = text[pos];
            if (escaped)
            {
                out.push_back(ch);
                escaped = false;
                continue;
            }
            if (ch == '\\')
            {
                escaped = true;
                continue;
            }
            if (ch == '"')
                break;
            out.push_back(ch);
        }
        return out;
    }

    std::string jsonNumberValue(const std::string &text, const std::string &key)
    {
        const std::string quoted = jsonStringValue(text, key);
        if (!quoted.empty())
            return quoted;
        const std::string needle = "\"" + key + "\"";
        std::size_t pos = text.find(needle);
        if (pos == std::string::npos)
            return std::string();
        pos = text.find(':', pos + needle.size());
        if (pos == std::string::npos)
            return std::string();
        ++pos;
        while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos])))
            ++pos;
        std::size_t end = pos;
        while (end < text.size() && text[end] >= '0' && text[end] <= '9')
            ++end;
        return end > pos ? text.substr(pos, end - pos) : std::string();
    }

    std::string jsonEscape(const std::string &value)
    {
        std::string out;
        for (char ch : value)
        {
            if (ch == '\\' || ch == '"')
                out.push_back('\\');
            if (ch == '\n')
            {
                out += "\\n";
                continue;
            }
            out.push_back(ch);
        }
        return out;
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

#ifndef PGS_ENABLE_TEST_HOOKS
    HMODULE g_hSelfModule = nullptr;
    pgs_ppl::SiriusDriverClient g_driver;
#endif
} // namespace

#ifdef PGS_ENABLE_TEST_HOOKS
namespace pgs_ppl_test
{
    bool parsePidForTest(const std::string &text, ULONG &out)
    {
        return parsePid(text, out);
    }

    bool parseSignerForTest(const std::string &text, UCHAR &out)
    {
        return parseSigner(text, out);
    }

    const char *signerNameForTest(UCHAR value)
    {
        return signerName(value);
    }
} // namespace pgs_ppl_test
#endif

#ifndef PGS_ENABLE_TEST_HOOKS

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
    return PG_MODULE_ABI_VERSION_JSON;
}

PG_MODULE_API const char *PG_GetManifest(void)
{
    return "name=ppl;version=1.0.0;abi=3;"
           "summary=Protected Process Light control backed by Sirius.sys;"
           "capabilities=driver.kernel,process.ppl.set,process.ppl.clear,ppl.set,ppl.get,ppl.clear,driver.sirius.load";
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
    // Close the device handle and, if PGS created the Sirius service, stop +
    // delete it so the ARK-class kernel driver does not stay loaded after exit.
    g_driver.shutdown();
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
    std::string signerText = kvValue(req, "signer");
    const std::string paramsJsonB64 = kvValue(req, "params_json_b64");
    if (!paramsJsonB64.empty())
    {
        const std::string requestJson = ProcessGuard::util::base64Decode(paramsJsonB64);
        if (pidText.empty())
        {
            pidText = jsonNumberValue(requestJson, "pid");
        }
        if (signerText.empty())
        {
            signerText = jsonStringValue(requestJson, "signer");
        }
    }

    ULONG pid = 0;
    if (!parsePid(pidText, pid))
    {
        setResponse(responseBuf, responseBufSize, "ERR invalid or missing pid");
        return 1;
    }

    if (op == "set")
    {
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

PG_MODULE_API int PG_InvokeJson(const char *requestJson, char *responseBuf, size_t responseBufSize)
{
    const std::string request = requestJson ? requestJson : "";
    const std::string method = jsonStringValue(request, "method");
    const std::string id = jsonStringValue(request, "id");
    const std::string pidText = jsonNumberValue(request, "pid");
    const std::string signerText = jsonStringValue(request, "signer");
    std::string op;
    if (method == "ppl.set")
        op = "set";
    else if (method == "ppl.get")
        op = "get";
    else if (method == "ppl.clear")
        op = "clear";
    else
    {
        setResponse(responseBuf, responseBufSize, "{\"jsonrpc\":\"2.0\",\"id\":\"" + jsonEscape(id) + "\",\"error\":{\"code\":\"UNKNOWN_METHOD\",\"message\":\"unknown PPL method\"}}");
        return 1;
    }
    std::string kv = "op=" + op + ";pid=" + pidText;
    if (op == "set")
    {
        kv += ";signer=" + signerText;
    }
    char legacy[1024] = {0};
    const int rc = PG_Invoke(kv.c_str(), legacy, sizeof(legacy));
    const std::string raw(legacy);
    if (rc != 0 || raw.rfind("ERR", 0) == 0)
    {
        setResponse(responseBuf, responseBufSize, "{\"jsonrpc\":\"2.0\",\"id\":\"" + jsonEscape(id) + "\",\"error\":{\"code\":\"PPL_ERROR\",\"message\":\"" + jsonEscape(raw) + "\"}}");
        return 1;
    }
    setResponse(responseBuf, responseBufSize, "{\"jsonrpc\":\"2.0\",\"id\":\"" + jsonEscape(id) + "\",\"result\":{\"legacy_response\":\"" + jsonEscape(raw) + "\"}}");
    return 0;
}
#endif // !PGS_ENABLE_TEST_HOOKS
