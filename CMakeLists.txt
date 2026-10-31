cmake_minimum_required(VERSION 3.20)

project(ProcessGuardService LANGUAGES CXX)

option(PGS_BUILD_TESTS "Build PGS unit tests" ON)
option(PGS_COPY_MINGW_RUNTIME "Copy MinGW runtime DLLs beside selected outputs" OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MINGW)
    add_compile_options(-Wall -Wextra)
endif()

add_compile_definitions(NTDDI_VERSION=0x06020000)

set(PGS_ROOT ${CMAKE_CURRENT_SOURCE_DIR})
set(PGS_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR})

function(pgs_copy_if_exists target source destination)
    if(EXISTS "${source}")
        add_custom_command(TARGET ${target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory "${destination}"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different "${source}" "${destination}")
    endif()
endfunction()

function(pgs_copy_mingw_runtime target destination)
    if(PGS_COPY_MINGW_RUNTIME AND MINGW)
        foreach(runtime libstdc++-6.dll libgcc_s_seh-1.dll libwinpthread-1.dll)
            string(MAKE_C_IDENTIFIER "${runtime}" runtime_var)
            find_file(PGS_RUNTIME_${runtime_var} NAMES ${runtime} PATHS ENV PATH NO_CACHE)
            if(PGS_RUNTIME_${runtime_var})
                add_custom_command(TARGET ${target} POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${PGS_RUNTIME_${runtime_var}}" "${destination}")
            endif()
        endforeach()
    endif()
endfunction()

add_library(pgs_logger STATIC src/common/PGLogger.cpp)
target_include_directories(pgs_logger PUBLIC include)

add_library(pgs_client STATIC src/common/PGSClient.cpp)
target_include_directories(pgs_client PUBLIC include)
target_link_libraries(pgs_client PUBLIC ws2_32 bcrypt advapi32)

add_library(pgs_module_manager STATIC src/modules/ModuleManager.cpp)
target_include_directories(pgs_module_manager PUBLIC include)
target_link_libraries(pgs_module_manager PUBLIC pgs_logger wintrust ole32 bcrypt)

add_library(pgs_core STATIC
    src/service/PGS.cpp
    src/service/PGSServer.cpp
    src/service/PGSMonitor.cpp
    src/service/PGSHealth.cpp
    src/service/PGSGuardStore.cpp
    src/service/PGSSqliteStore.cpp
    src/service/PGSProtocol.cpp
    src/service/PGSOperationStore.cpp
    src/service/PGSModuleInstall.cpp)
target_include_directories(pgs_core PUBLIC include)
target_link_libraries(pgs_core PUBLIC pgs_logger pgs_module_manager ws2_32 winhttp advapi32 wtsapi32 userenv bcrypt wintrust ole32 shell32 sqlite3)

add_executable(pgs_service src/service/pgs_service.cpp)
target_link_libraries(pgs_service PRIVATE pgs_core)

add_executable(pgs_bless tools/pgs_bless.cpp tools/PGSRegistryInstall.cpp)
target_link_libraries(pgs_bless PRIVATE pgs_client pgs_module_manager pgs_logger ws2_32 winhttp advapi32 bcrypt wintrust ole32 shell32)

add_executable(guard_example examples/guard_example.cpp)
target_include_directories(guard_example PRIVATE include)
target_link_libraries(guard_example PRIVATE ws2_32 advapi32 bcrypt)

add_executable(quick_start examples/quick_start.cpp)
target_include_directories(quick_start PRIVATE include)
target_link_libraries(quick_start PRIVATE ws2_32 advapi32 bcrypt)

add_executable(smoke_worker examples/smoke_worker.cpp)
target_link_libraries(smoke_worker PRIVATE ws2_32)

foreach(exe pgs_service pgs_bless guard_example quick_start smoke_worker)
    set_target_properties(${exe} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PGS_BUILD_DIR}")
    pgs_copy_mingw_runtime(${exe} "$<TARGET_FILE_DIR:${exe}>")
endforeach()

function(pgs_module target module_dir output_name)
    add_library(${target} SHARED ${ARGN})
    target_include_directories(${target} PRIVATE include modules/${module_dir})
    set_target_properties(${target} PROPERTIES
        PREFIX ""
        OUTPUT_NAME "${output_name}"
        RUNTIME_OUTPUT_DIRECTORY "${PGS_BUILD_DIR}/modules/${module_dir}"
        LIBRARY_OUTPUT_DIRECTORY "${PGS_BUILD_DIR}/modules/${module_dir}")
    pgs_copy_if_exists(${target} "${PGS_ROOT}/modules/${module_dir}/module.html" "${PGS_BUILD_DIR}/modules/${module_dir}")
    pgs_copy_if_exists(${target} "${PGS_ROOT}/modules/${module_dir}/module.manifest.json" "${PGS_BUILD_DIR}/modules/${module_dir}")
    pgs_copy_mingw_runtime(${target} "$<TARGET_FILE_DIR:${target}>")
endfunction()

pgs_module(pgs_sched_module sched pgs_sched_module modules/sched/SchedCron.cpp modules/sched/pgs_sched_module.cpp)
pgs_module(pgs_health_module health pgs_health_module modules/health/pgs_health_module.cpp)
pgs_module(pgs_report_module report pgs_report_module modules/report/pgs_report_module.cpp)
pgs_module(pgs_notify_module notify pgs_notify_module modules/notify/pgs_notify_module.cpp)
target_link_libraries(pgs_notify_module PRIVATE advapi32 user32)
pgs_module(pgs_metrics_module metrics pgs_metrics_module modules/metrics/pgs_metrics_module.cpp)
pgs_module(pgs_backup_module backup pgs_backup_module modules/backup/pgs_backup_module.cpp)
pgs_module(pgs_eventlog_module eventlog pgs_eventlog_module modules/eventlog/pgs_eventlog_module.cpp)
target_link_libraries(pgs_eventlog_module PRIVATE advapi32)
pgs_module(pgs_dump_module dump pgs_dump_module modules/dump/pgs_dump_module.cpp)
target_link_libraries(pgs_dump_module PRIVATE dbghelp)
pgs_module(pgs_service_guard_module service_guard pgs_service_guard_module modules/service_guard/pgs_service_guard_module.cpp)
target_link_libraries(pgs_service_guard_module PRIVATE advapi32)
pgs_module(pgs_file_watch_module file_watch pgs_file_watch_module modules/file_watch/pgs_file_watch_module.cpp)
target_link_libraries(pgs_file_watch_module PRIVATE bcrypt)
pgs_module(pgs_policy_module policy pgs_policy_module modules/policy/pgs_policy_module.cpp)
pgs_module(pgs_winapp_module winapp pgs_winapp_module modules/winapp/pgs_winapp_module.cpp)
target_link_libraries(pgs_winapp_module PRIVATE ole32 shell32 user32)

file(MAKE_DIRECTORY "${PGS_BUILD_DIR}/modules")
file(WRITE "${PGS_BUILD_DIR}/modules/modules.allow" "sched\nhealth\nreport\nnotify\nmetrics\nbackup\neventlog\ndump\nservice_guard\nfile_watch\npolicy\nwinapp\n")
add_custom_target(pgs_bundled_modules_lock ALL
    COMMAND ${CMAKE_COMMAND}
        -DPGS_MODULES_ROOT=${PGS_BUILD_DIR}/modules
        -DPGS_MODULES_LOCK_OUT=${PGS_BUILD_DIR}/modules/modules.lock
        -P ${PGS_ROOT}/cmake/WriteBundledModulesLock.cmake
    DEPENDS pgs_sched_module pgs_health_module pgs_report_module pgs_notify_module pgs_metrics_module pgs_backup_module pgs_eventlog_module pgs_dump_module pgs_service_guard_module pgs_file_watch_module pgs_policy_module pgs_winapp_module
    COMMENT "Writing modules.lock for bundled modules")

if(PGS_BUILD_TESTS)
    enable_testing()

    add_executable(test_pgs_core tests/test_pgs_core.cpp modules/sched/pgs_sched_module.cpp)
    target_compile_definitions(test_pgs_core PRIVATE PGS_ENABLE_TEST_HOOKS)
    target_include_directories(test_pgs_core PRIVATE include modules/sched)
    target_link_libraries(test_pgs_core PRIVATE bcrypt advapi32)
    add_test(NAME pgs_core COMMAND test_pgs_core)

    add_executable(test_module_manager tests/test_module_manager.cpp)
    target_link_libraries(test_module_manager PRIVATE pgs_module_manager pgs_logger)
    add_test(NAME module_manager COMMAND test_module_manager)

    add_executable(test_sched_cron tests/test_sched_cron.cpp modules/sched/SchedCron.cpp)
    target_include_directories(test_sched_cron PRIVATE include modules/sched)
    add_test(NAME sched_cron COMMAND test_sched_cron)

    add_executable(test_state_db tests/test_state_db.cpp src/service/PGSSqliteStore.cpp src/common/PGLogger.cpp)
    target_include_directories(test_state_db PRIVATE include src/service)
    target_link_libraries(test_state_db PRIVATE sqlite3)
    add_test(NAME state_db COMMAND test_state_db)
endif()
