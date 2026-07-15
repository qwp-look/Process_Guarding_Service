/*
 * PGModuleManager.h - PGS module-manager extension ABI.
 *
 * Manager extensions are policy helpers only: repository index parsing,
 * install planning, trust evaluation, and version compatibility checks. They
 * never receive callbacks that execute PGS management commands and they never
 * load ordinary modules directly. The core PGS loader keeps final allow/deny
 * authority.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef PROCESS_GUARD_PG_MODULE_MANAGER_H
#define PROCESS_GUARD_PG_MODULE_MANAGER_H

#include <cstddef>

#define PG_MANAGER_ABI_VERSION 1
#define PG_MANAGER_MAX_JSON_BYTES (64u * 1024u)

#ifdef _WIN32
#ifdef PG_MANAGER_EXPORTS
#define PG_MANAGER_API __declspec(dllexport)
#else
#define PG_MANAGER_API __declspec(dllimport)
#endif
#else
#define PG_MANAGER_API
#endif

struct PGM_Services
{
    unsigned int size;
    void *context;
    long long (*now_ms)(void *context);
    void (*log)(void *context, int level, const char *message);
};

#ifdef __cplusplus
extern "C" {
#endif

PG_MANAGER_API const char *PGM_GetName(void);
PG_MANAGER_API const char *PGM_GetVersion(void);
PG_MANAGER_API const char *PGM_GetManifest(void);
PG_MANAGER_API int PGM_Init(void *services);
PG_MANAGER_API int PGM_PlanInstall(const char *requestJson, char *responseJson, size_t responseSize);
PG_MANAGER_API int PGM_EvaluateTrust(const char *requestJson, char *responseJson, size_t responseSize);
PG_MANAGER_API void PGM_Shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* PROCESS_GUARD_PG_MODULE_MANAGER_H */
