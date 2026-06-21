/**
 * @file ModuleManager.cpp
 * @brief Implementation of the PGS module registry (ModuleManager).
 *
 * Loading pipeline:
 *   LoadLibraryW -> GetProcAddress(PG_GetName/Invoke/...) -> name lookup
 *   (reject duplicates) -> PG_Init -> store Entry.
 *
 * The directory scan (loadFromDirectory) holds the lock for the whole scan so
 * that "module list" never observes a half-loaded set. Individual load() also
 * locks, so the two paths share loadLocked() for the actual work.
 *
 * Note on GetProcAddress casts: MinGW warns on direct FARPROC->fnptr casts
 * (-Wcast-function-type), so we cast through void* first. Functionally
 * identical, just silences the warning.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "Process_Guard/PGModule.h"
#include "Process_Guard/ModuleManager.h"
#include "Process_Guard/PGUtil.h"

#include <algorithm>
#include <cctype>
#include <cwchar>
#include <string>
#include <vector>
#include <cstring>

namespace ProcessGuard
{


    ModuleManager::ModuleManager() = default;

    // On destruction, shut every module down and free its DLL. Order does not
    // matter; modules must not call back into PGS during shutdown.
    ModuleManager::~ModuleManager()
    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        for (Entry &e : m_modules)
        {
            if (e.shutdown)
                e.shutdown();
            if (e.handle)
                FreeLibrary(e.handle);
        }
        m_modules.clear();
    }

    // ASCII lowercase for case-insensitive module-name keys. Module names are
    // short ASCII identifiers, so locale-insensitive tolower is intentional.
    std::string ModuleManager::lower(const std::string &s)
    {
        std::string out = s;
        std::transform(out.begin(), out.end(), out.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return out;
    }
    // Probe whether a candidate DLL exports the given symbol WITHOUT running its
    // DllMain or loading/initializing its dependencies. We map it with
    // DONT_RESOLVE_DLL_REFERENCES: per MSDN the system maps the image, makes its
    // exports resolvable via GetProcAddress, but does NOT call DllMain and does
    // NOT load referenced modules. This is the only safe way to inspect a
    // candidate before a real LoadLibraryW: loading a second copy of a runtime
    // DLL (e.g. libstdc++-6.dll placed beside a module) would re-run its
    // DllMain/static init and deadlock the loader. Only DLLs that actually
    // export PG_GetName (a mandatory PGS module export) get a real load.
    bool ModuleManager::hasExportByName(const std::wstring &path, const char *exportName)
    {
        HMODULE h = LoadLibraryExW(path.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (!h)
        {
            return false;
        }
        const bool found = (GetProcAddress(h, exportName) != nullptr);
        FreeLibrary(h);
        return found;
    }


    bool ModuleManager::loadLocked(const std::string &path, std::string &err)
    {
        const std::wstring wpath = util::utf8ToWide(path);
        HMODULE handle = LoadLibraryW(wpath.c_str());
        if (!handle)
        {
            err = "LoadLibrary failed, error=" + std::to_string(GetLastError());
            return false;
        }

        // Resolve every export. PG_GetName + PG_Invoke are mandatory; the rest
        // are optional (NULL-safe). Cast via void* to silence -Wcast-function-type.
        Entry e{};
        e.handle = handle;
        e.getName = reinterpret_cast<const char *(*)(void)>(reinterpret_cast<void *>(GetProcAddress(handle, "PG_GetName")));
        e.getVersion = reinterpret_cast<const char *(*)(void)>(reinterpret_cast<void *>(GetProcAddress(handle, "PG_GetVersion")));
        e.getAbiVersion = reinterpret_cast<unsigned int (*)(void)>(reinterpret_cast<void *>(GetProcAddress(handle, "PG_GetAbiVersion")));
        e.init = reinterpret_cast<int (*)(void *)>(reinterpret_cast<void *>(GetProcAddress(handle, "PG_Init")));
        e.shutdown = reinterpret_cast<void (*)(void)>(reinterpret_cast<void *>(GetProcAddress(handle, "PG_Shutdown")));
        e.invoke = reinterpret_cast<int (*)(const char *, char *, size_t)>(reinterpret_cast<void *>(GetProcAddress(handle, "PG_Invoke")));

        // A module without an invoke entry is useless to PGS.
        if (!e.getName || !e.invoke)
        {
            FreeLibrary(handle);
            err = "missing required PG_ exports";
            return false;
        }

        e.name = e.getName();
        e.version = e.getVersion ? e.getVersion() : "";
        if (e.name.empty())
        {
            FreeLibrary(handle);
            err = "module returned empty name";
            return false;
        }

        // Reject duplicate names (case-insensitive) so a re-scan or explicit
        // load cannot double-register the same plugin.
        const std::string key = lower(e.name);
        for (const Entry &existing : m_modules)
        {
            if (lower(existing.name) == key)
            {
                if (e.shutdown)
                    e.shutdown();
                FreeLibrary(handle);
                err = "module already loaded: " + e.name;
                return false;
            }
        }

        // Run the module's one-time init. A non-zero return aborts the load.
        if (e.init)
        {
            const int rc = e.init(nullptr);
            if (rc != 0)
            {
                if (e.shutdown)
                    e.shutdown();
                FreeLibrary(handle);
                err = "PG_Init failed, rc=" + std::to_string(rc);
                return false;
            }
        }

        m_modules.push_back(std::move(e));
        return true;
    }

    bool ModuleManager::load(const std::string &path, std::string &err)
    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        return loadLocked(path, err);
    }

    bool ModuleManager::unload(const std::string &name, std::string &err)
    {
        const std::string key = lower(name);
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        for (auto it = m_modules.begin(); it != m_modules.end(); ++it)
        {
            if (lower(it->name) == key)
            {
                // Erase from the table first so a (theoretical) re-entrant call
                // cannot double-unload, then release the DLL.
                if (it->shutdown)
                    it->shutdown();
                HMODULE handle = it->handle;
                m_modules.erase(it);
                if (handle)
                    FreeLibrary(handle);
                return true;
            }
        }
        err = "module not found: " + name;
        return false;
    }

    // Scan <dir> for modules: load loose *.dll directly under <dir> AND descend
    // one level into subdirectories (modules\<name>\<name>.dll layout, where each
    // folder also holds the module's UI HTML / assets). Silently skips failures
    // so one bad DLL cannot block the rest. Holds the lock for the whole scan so
    // observers (module list) never see a partial set.
    int ModuleManager::loadFromDirectory(const std::string &dir)
    {
        const std::wstring wdir = util::utf8ToWide(dir);
        auto ensureSep = [](std::wstring &p) {
            if (!p.empty() && p.back() != L'\\' && p.back() != L'/')
                p += L'\\';
        };

        int loaded = 0;
        std::unique_lock<std::shared_mutex> lock(m_mutex);

        // Load a DLL given by a wide path: widen->UTF-8->loadLocked (caller holds lock).
        auto loadWide = [&](const std::wstring &full) {
            // Skip DLLs that are not PGS modules. A full LoadLibraryW on a
            // non-module DLL (e.g. libstdc++-6.dll placed beside a module) would
            // load a second copy of a runtime library, re-run its DllMain/static
            // init and can deadlock the loader. Probe for the mandatory PG_GetName
            // export via an image-resource map (no DllMain) first.
            if (!hasExportByName(full, "PG_GetName"))
            {
                return;
            }
            int len = WideCharToMultiByte(CP_UTF8, 0, full.c_str(), -1, nullptr, 0, nullptr, nullptr);
            std::string utf8(len > 0 ? len - 1 : 0, '\0');
            if (len > 0)
                WideCharToMultiByte(CP_UTF8, 0, full.c_str(), -1, utf8.data(), len, nullptr, nullptr);
            std::string err;
            if (loadLocked(utf8, err))
                ++loaded;
        };

        std::wstring topPattern = wdir;
        ensureSep(topPattern);
        topPattern += L"*";

        WIN32_FIND_DATAW fd{};
        HANDLE hFind = FindFirstFileW(topPattern.c_str(), &fd);
        if (hFind == INVALID_HANDLE_VALUE)
            return 0;

        do
        {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                // Skip "." / ".."
                if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
                    continue;
                // modules\<sub>\*.dll
                std::wstring subPattern = wdir;
                ensureSep(subPattern);
                subPattern += fd.cFileName;
                subPattern += L"\\*.dll";
                WIN32_FIND_DATAW sfd{};
                HANDLE hSub = FindFirstFileW(subPattern.c_str(), &sfd);
                if (hSub == INVALID_HANDLE_VALUE)
                    continue;
                do
                {
                    if (sfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                        continue;
                    std::wstring full = wdir;
                    ensureSep(full);
                    full += fd.cFileName;
                    full += L"\\";
                    full += sfd.cFileName;
                    loadWide(full);
                } while (FindNextFileW(hSub, &sfd));
                FindClose(hSub);
            }
            else
            {
                // Loose *.dll directly under <dir>
                const wchar_t *dot = wcsrchr(fd.cFileName, L'.');
                if (dot && _wcsicmp(dot, L".dll") == 0)
                {
                    std::wstring full = wdir;
                    ensureSep(full);
                    full += fd.cFileName;
                    loadWide(full);
                }
            }
        } while (FindNextFileW(hFind, &fd));

        FindClose(hFind);
        return loaded;
    }

    std::vector<ModuleManager::ModuleInfo> ModuleManager::list() const
    {
        std::shared_lock<std::shared_mutex> lock(m_mutex);
        std::vector<ModuleInfo> out;
        out.reserve(m_modules.size());
        for (const Entry &e : m_modules)
            out.push_back({e.name, e.version});
        return out;
    }

    // Dispatch a call to the named module. 8 KB response buffer is plenty for
    // the short KV status lines modules produce. Returns false ONLY when the
    // module is not found; module-internal errors are delivered via response.
    bool ModuleManager::invoke(const std::string &name, const std::string &request,
                               std::string &response, std::string &err)
    {
        const std::string key = lower(name);
        std::shared_lock<std::shared_mutex> lock(m_mutex);
        for (const Entry &e : m_modules)
        {
            if (lower(e.name) == key)
            {
                std::vector<char> buf(8192, '\0');
                const int rc = e.invoke(request.c_str(), buf.data(), buf.size());
                response.assign(buf.data());
                if (rc != 0 && response.empty())
                    response = "ERR module invoke failed rc=" + std::to_string(rc);
                return true;
            }
        }
        err = "module not found: " + name;
        return false;
    }

} // namespace ProcessGuard
