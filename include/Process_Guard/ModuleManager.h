/**
 * @file ModuleManager.h
 * @brief Thread-safe registry of loaded PGS modules (DLL plugins).
 *
 * @section role Role
 * ModuleManager discovers, loads, unloads, and dispatches calls to module
 * DLLs that implement the PGModule C ABI (see PGModule.h). It is owned by the
 * PGS service core (PGS::m_modules) and used by the "module" / "ppl"
 * management commands.
 *
 * @section threading Threading
 * All public methods take a process-wide mutex (m_mutex). PGS runs a pool of
 * 4 client-worker threads that may call invoke() concurrently, so:
 *  - invoke()/list() take a shared lock so multiple worker threads can call
 *  - load()/unload() mutate the table under the same lock, so a concurrent
 *    invoke() will either see the old or the new module set, never a torn one.
 *  - Module code itself is responsible for its own internal thread-safety.
 *
 * @section loading Loading model
 *  - loadFromDirectory() scans <dir>\*.dll and loads each as a module. A
 *    single failing DLL is silently skipped so one bad plugin cannot prevent
 *    the rest from loading. Returns the count newly loaded this call.
 *  - load() loads one DLL by path. It validates required exports (PG_GetName +
 *    PG_Invoke), rejects duplicate names (case-insensitive), and calls
 *    PG_Init; any failure frees the library and returns an error string.
 *  - unload() calls PG_Shutdown then FreeLibrary.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef PROCESS_GUARD_MODULE_MANAGER_H
#define PROCESS_GUARD_MODULE_MANAGER_H

#include "PGModule.h"

#include <windows.h>

#include <condition_variable>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <utility>
#include <vector>

namespace ProcessGuard
{

    class ModuleManager
    {
    public:
        ModuleManager();
        ~ModuleManager();

        ModuleManager(const ModuleManager &) = delete;
        ModuleManager &operator=(const ModuleManager &) = delete;
        ModuleManager(ModuleManager &&) = delete;
        ModuleManager &operator=(ModuleManager &&) = delete;

        /*
         * Load every *.dll found under dir as a module. Files that fail to
         * load or initialise are skipped without aborting the scan. Modules
         * already loaded (by name) are skipped and not counted. Returns the
         * number of modules successfully loaded during this scan.
         */
        int loadFromDirectory(const std::string &dir);

        /*
         * Load a single module DLL by absolute/relative path. Returns true on
         * success. On failure returns false and sets err to a human-readable
         * reason (e.g. "LoadLibrary failed, error=126", "missing required PG_
         * exports", "module already loaded: ppl", "PG_Init failed, rc=1").
         */
        bool load(const std::string &path, std::string &err);

        /*
         * Ensure the module allowlist from <dir>\modules.allow has been read.
         * Explicit module load commands use this because normal startup may
         * skip directory scanning when PPL/module loading is not opted in.
         */
        void ensureAllowlistLoaded(const std::string &dir);

        /* Unload a module by name (case-insensitive). Calls PG_Shutdown first.
         * Returns true on success; false + err if not found. */
        bool unload(const std::string &name, std::string &err);

        /* Snapshot of a loaded module. */
        struct ModuleInfo
        {
            std::string name;
            std::string version;
        };
        /* Snapshot of currently loaded modules (name, version). */
        std::vector<ModuleInfo> list() const;

        /*
         * Invoke a module by name (case-insensitive).
         * request is forwarded verbatim to the module's PG_Invoke.
         * Returns true if the module was found AND called (regardless of
         * whether the module reported its own success/failure in response);
         * in that case response holds whatever the module wrote (e.g. "OK ..."
         * or "ERR ..."). Returns false only if no module with that name is
         * loaded (err set to "module not found: <name>").
         */
        bool invoke(const std::string &name, const std::string &request,
                    std::string &response, std::string &err);

        // v3 security: permissive mode (default false) bypasses the allowlist so
        // the legacy "load any DLL" behaviour is available for development. The
        // operator opt-in flag lives on PGS (m_modulesPermissive) and is pushed
        // here before loadFromDirectory().
        void setPermissive(bool v) { m_permissive = v; }

        // ABI v2: services struct handed to every module's PG_Init. PGS sets
        // this before loadFromDirectory() so modules receive callbacks. When
        // not ready (m_servicesReady false), PG_Init receives NULL and v1
        // modules keep working unchanged.
        void setServices(const PGS_Services &s) { m_services = s; m_servicesReady = true; }

        // Return the allowlist key a module path maps to. Exposed for tests and
        // diagnostics; loading still uses the private helper below.
        static std::string allowlistKeyForPath(const std::string &path);

    private:
        // Resolved function-pointer types and runtime data for one loaded DLL.
        struct Entry
        {
            std::string name;     // from PG_GetName
            std::string version;  // from PG_GetVersion (may be empty)
            std::string path;     // original DLL path; useful for diagnostics
            HMODULE handle = nullptr;
            const char *(*getName)(void) = nullptr;
            const char *(*getVersion)(void) = nullptr;
            unsigned int (*getAbiVersion)(void) = nullptr;
            int (*init)(void *) = nullptr;
            void (*shutdown)(void) = nullptr;
            int (*invoke)(const char *, char *, size_t) = nullptr;
            struct RuntimeState
            {
                std::mutex mutex;
                std::condition_variable cv;
                int activeInvokes = 0;
                bool unloading = false;
            };
            std::shared_ptr<RuntimeState> runtime;
        };

        mutable std::shared_mutex m_mutex;
        std::vector<Entry> m_modules; // lookup by lowercased name (linear; set is tiny)

        // Internal load assuming the caller already holds m_mutex. Used by both
        // load() and loadFromDirectory() so the scan can batch under one lock.
        bool loadLocked(const std::string &path, std::string &err);

        static std::string lower(const std::string &s); // ASCII lowercase for name keys
        // v3: module allowlist (one entry per allowed module name). Loaded from
        // <modules-dir>\modules.allow. Empty + non-permissive => fail-closed.
        struct AllowEntry
        {
            std::string name;          // module key (folder name, ASCII lower)
            std::string sha256;        // optional pinned file hash (hex); empty = any
            bool requireSigned = false; // require a valid Authenticode signature
        };
        std::vector<AllowEntry> m_allowlist;
        bool m_allowlistLoaded = false;
        bool m_permissive = false;
        PGS_Services m_services{};
        bool m_servicesReady = false;
        void loadAllowlist(const std::string &dir);
        const AllowEntry *findAllowEntry(const std::string &moduleKey) const;
        static std::string moduleKeyFromPath(const std::string &path);
        static bool verifySignature(const std::wstring &path);

        // Probe a candidate DLL for an export via an image-resource map (no DllMain).
        static bool hasExportByName(const std::wstring &path, const char *exportName);
    };

} // namespace ProcessGuard

#endif // PROCESS_GUARD_MODULE_MANAGER_H
