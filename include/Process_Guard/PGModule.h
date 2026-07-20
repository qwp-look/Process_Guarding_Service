/**
 * @file PGModule.h
 * @brief ProcessGuard Service (PGS) loadable module C ABI.
 *
 * @section overview Overview
 * A PGS module is a Windows DLL that exports the functions declared below.
 * PGS discovers modules in <service-dir>/modules/ at startup (and on demand
 * via the "module load" management command), loads them with LoadLibrary, and
 * invokes them through PG_Invoke or the optional JSON-RPC entry PG_InvokeJson.
 * This lets PGS gain new capabilities without baking them into the core; PPL
 * is treated as a high-risk module rather than a core service feature.
 *
 * @section abi ABI design
 *  - Pure C linkage (extern "C") so modules built by any compiler/language
 *    that can produce a Windows DLL with these exports are compatible.
 *  - ABI v2 request/response uses the historical "KEY=VALUE;..." UTF-8 KV
 *    style. ABI v3 adds an optional JSON-RPC-style PG_InvokeJson entry point
 *    so module semantics can evolve independently from the transport.
 *  - Functions are split into metadata (Name/Version/AbiVersion/Manifest),
 *    lifecycle (Init/Shutdown), and the workhorse (Invoke). Only Name + Invoke
 *    are strictly required; the others are optional and NULL-safe on the PGS
 *    side.
 *
 * @section contract Invocation contract
 *  - PGS calls PG_Invoke with a NUL-terminated UTF-8 request and a response
 *    buffer of responseBufSize bytes. The module writes a NUL-terminated
 *    UTF-8 response and returns 0 on success, non-zero on failure.
 *  - On success the response conventionally starts with "OK"; on failure with
 *    "ERR ...". PGS treats the return code as the success/failure signal and
 *    forwards the response text to the client verbatim.
 *  - PG_Invoke MUST be thread-safe: PGS worker threads call it concurrently.
 *
 * @section derivation Derivation
 * The reference module pgs_ppl_module is derived from StarlightGUI's Sirius
 * driver client (Apache-2.0, author "Stars"). This header itself is original
 * PGS code. See ../../NOTICE for attribution details.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef PROCESS_GUARD_PG_MODULE_H
#define PROCESS_GUARD_PG_MODULE_H

#include <cstddef>

/* ABI version. Increment on incompatible changes to this header or the
 * expected behaviour of the functions below. Modules report the version they
 * were built against via PG_GetAbiVersion so PGS can reject mismatches. */
#define PG_MODULE_ABI_VERSION 2
#define PG_MODULE_ABI_VERSION_JSON 3
#define PG_MODULE_ABI_MIN_SUPPORTED 2
#define PG_MODULE_DEFAULT_MAX_JSON_BYTES (64u * 1024u)
#define PG_MODULE_DEFAULT_DEADLINE_MS 5000u
#define PG_MODULE_MAX_DEADLINE_MS 60000u

/* Export macro. Modules define PG_MODULE_EXPORTS when compiling so the
 * functions are dllexport'd. PGS does NOT define it (it only resolves the
 * symbols via GetProcAddress), so the dllimport branch is never used in
 * practice but keeps the header self-consistent if included by a consumer. */
#ifdef _WIN32
#ifdef PG_MODULE_EXPORTS
#define PG_MODULE_API __declspec(dllexport)
#else
#define PG_MODULE_API __declspec(dllimport)
#endif
#else
#define PG_MODULE_API
#endif

/* ABI v2: services struct passed to PG_Init via the `reserved` argument.
 *
 * A module built against ABI v1 ignores `reserved` (it was NULL). A module
 * built against ABI v2 casts `reserved` to PGS_Services* and may use the
 * callbacks to call back into PGS - this is what enables stateful modules
 * such as the scheduler (modules/sched/), which needs to trigger guard
 * operations on its own background thread.
 *
 * Forward compatibility: PGS sets `size` to sizeof(PGS_Services) at build
 * time. A module compiled against an older (smaller) layout must not read
 * fields beyond the size it knows; a module compiled against a newer layout
 * sees a possibly-smaller `size` and treats trailing fields as unavailable.
 */
struct PGS_Services
{
    /* Size of this struct in bytes. Set by PGS; modules consult this before
     * touching any field added after their compile-time layout. */
    unsigned int size;
    /* Opaque PGS instance pointer, passed back as the first argument of every
     * callback so the PGS-side thunk can route to the right core. */
    void *context;
    /* Execute one PGS line-protocol command (same semantics as a TCP client
     * request minus the auth envelope, e.g. "bless 1234|-1" or "list").
     * On success returns 0 and writes a NUL-terminated response ("OK ..." or
     * "ERR ...") into `response`. On transport failure returns non-zero.
     * Thread-safe; may be called from any thread, including a module's own
     * background thread. Re-entrancy from within PG_Invoke is allowed but
     * modules should avoid nesting module load/unload (write-locked). */
    int (*call)(void *context, const char *request, char *response, size_t response_size);
    /* Wall-clock epoch milliseconds (GetSystemTimeAsFileTime based). Provided
     * so schedule arithmetic is consistent and mockable. */
    long long (*now_ms)(void *context);
};

/* ABI v3 services. The first fields intentionally mirror PGS_Services so a
 * host can pass this struct to older modules without changing their v2 reads.
 * v3 modules should check `size` before using fields after now_ms. */
struct PGS_ServicesV3
{
    unsigned int size;
    void *context;
    int (*call)(void *context, const char *request, char *response, size_t response_size);
    long long (*now_ms)(void *context);
    int (*call_json)(void *context, const char *request_json, char *response_json, size_t response_size);
    int (*emit_event)(void *context, const char *event_json);
    const char *(*get_data_dir)(void *context);
    void (*log)(void *context, int level, const char *message);
};

#ifdef __cplusplus
extern "C" {
#endif

/* Short, stable module name (UTF-8, static storage). Example: "ppl".
 * Used as the lookup key by PGS (case-insensitive) and as the human-facing
 * identifier in "module list". Required. */
PG_MODULE_API const char *PG_GetName(void);

/* Module version string (UTF-8, static storage). Example: "1.0.0".
 * Optional; returns "" or a static empty string if unused. */
PG_MODULE_API const char *PG_GetVersion(void);

/* ABI version the module was built against. Should equal
 * PG_MODULE_ABI_VERSION. Optional but recommended for compatibility checks. */
PG_MODULE_API unsigned int PG_GetAbiVersion(void);

/* Optional ABI v2 manifest string (UTF-8, static storage). The format is the
 * same lightweight KV style used by module requests:
 *
 *   name=ppl;version=1.0.0;abi=2;summary=...;capabilities=ppl.set,ppl.get
 *
 * Recognized keys today are name, version, abi, summary and capabilities.
 * Capabilities are comma-separated advisory tags used for inspection and for
 * future host-enforced policy. If name or abi is present, PGS validates it
 * against PG_GetName / PG_GetAbiVersion before accepting the module. Modules
 * that omit PG_GetManifest remain fully compatible with ABI v2. */
PG_MODULE_API const char *PG_GetManifest(void);

/*
 * Called once right after the DLL is loaded, before any PG_Invoke.
 * Return 0 on success. Any non-zero return causes PGS to call PG_Shutdown
 * (if present), FreeLibrary the module, and report a load failure.
 * `reserved` is NULL for ABI v1 modules. For ABI v2 modules PGS passes a
 * pointer to a PGS_Services struct so the module can call back into PGS
 * (e.g. the scheduler triggering bless/unbless). A v2 module MUST check
 * `reserved != NULL` before dereferencing it.
 *
 * Avoid heavy/possibly-failing initialisation here (opening drivers, network,
 * etc.). Defer it to first PG_Invoke so a missing runtime prerequisite
 * returns a clean error instead of failing the whole module load.
 */
PG_MODULE_API int PG_Init(void *reserved);

/* Called once before the DLL is unloaded (on PGS shutdown or "module unload").
 * Release resources acquired during Init/Invoke. May be absent (PGS checks
 * the pointer before calling). Must not call back into PGS. */
PG_MODULE_API void PG_Shutdown(void);

/*
 * Invoke a module-defined operation. The workhorse entry point.
 *
 * request         NUL-terminated UTF-8 KV string.
 *                  Example: "op=set;pid=1234;signer=Antimalware"
 * responseBuf     caller-provided buffer for a NUL-terminated UTF-8 response.
 * responseBufSize size of responseBuf in bytes (PGS provides 8192).
 *
 * Returns 0 on success, non-zero on failure. On success write a response such
 * as "OK" or "OK type=Light signer=Antimalware". On failure write an
 * "ERR <reason>" message if possible (PGS fills a generic one if the buffer
 * is left empty on a non-zero return).
 *
 * Thread-safety: PGS worker threads may call this concurrently. Any shared
 * state inside the module must be protected by the module itself.
 */
PG_MODULE_API int PG_Invoke(const char *request, char *responseBuf, size_t responseBufSize);

/* Optional ABI v3 JSON-RPC invocation entry point. Modules that implement it
 * export the same signature under the symbol name PG_InvokeJson. PGS probes it
 * dynamically, so ABI v2 modules do not need to define it.
 *
 * Request example:
 *   {"jsonrpc":"2.0","id":"...","module":"profile","method":"profile.apply","params":{...}}
 * Response examples:
 *   {"jsonrpc":"2.0","id":"...","result":{...}}
 *   {"jsonrpc":"2.0","id":"...","error":{"code":"ERR_CODE","message":"..."}}
 */
typedef int (*PG_InvokeJsonFn)(const char *requestJson, char *responseJson, size_t responseJsonSize);
PG_MODULE_API int PG_InvokeJson(const char *requestJson, char *responseJson, size_t responseJsonSize);

#ifdef __cplusplus
}
#endif

#endif /* PROCESS_GUARD_PG_MODULE_H */
