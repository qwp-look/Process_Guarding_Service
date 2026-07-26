#include "Process_Guard/PGS.h"

#include <winsvc.h>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>

#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#endif

using ProcessGuard::Logger;
using ProcessGuard::PGS;

namespace
{
constexpr DWORD kServiceRecoveryResetSeconds = 24 * 60 * 60;
constexpr DWORD kServiceRecoveryDelayMs = 5000;
constexpr DWORD kConsolePollIntervalMs = 200;
constexpr DWORD kServiceStopTimeoutMs = 30000;

// This host intentionally stays thin:
// - SCM / console lifecycle lives here
// - actual guard logic stays inside PGS
//
// That separation keeps the service entrypoint boring and predictable while the
// more complex state machine remains testable in the core service class.
class PGSServiceHost
{
public:
    explicit PGSServiceHost(std::string serviceName, std::string logPath)
        : m_serviceName(std::move(serviceName)), m_logPath(std::move(logPath))
    {
        ZeroMemory(&m_status, sizeof(m_status));
        m_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        m_status.dwCurrentState = SERVICE_STOPPED;
        m_status.dwControlsAccepted = 0;
        m_status.dwWin32ExitCode = NO_ERROR;
    }

    int run(int argc, char *argv[])
    {
        ParsedArgs args;
        if (!parseArguments(argc, argv, args))
        {
            return printHelp(argv[0]);
        }
        // If no token is explicitly provided, let PGS decide whether it should
        // restore the previous persisted token hash or generate a fresh random
        // token. Passing an always-hashed empty string here would hide that
        // distinction from the core service. Token hash is SHA-256 (via CNG).
        m_bootTokenHash = args.hasToken ? ProcessGuard::util::sha256Hex(args.token) : std::string();

        if (args.enableModules || std::getenv("PGS_ENABLE_MODULES") != nullptr)
        {
            m_pgs.setModulesEnabled(true);
        }
        // Compatibility: --enable-ppl still works, but the new model names the
        // real risk boundary as kernel/high-risk modules.
        if (args.enablePpl || args.enableKernelModules ||
            std::getenv("PGS_ENABLE_PPL") != nullptr ||
            std::getenv("PGS_ENABLE_KERNEL_MODULES") != nullptr)
        {
            m_pgs.setKernelModulesEnabled(true);
            m_pgs.setPplEnabled(true);
        }

        // v3: apply host-supplied policy overrides BEFORE initialize() so the
        // core honours them at startup. setModulesPermissive marks the choice
        // as user-set so it survives loadPersistedState() (which would otherwise
        // restore the archived MODULES_PERMISSIVE value).
        if (args.port > 0)
        {
            m_pgs.setServerPort(static_cast<std::uint16_t>(args.port));
        }
        if (args.allowAllModules)
        {
            m_pgs.setModulesPermissive(true);
        }

        if (!args.command.empty())
        {
            if (args.command == "install")
                return installService(args) ? 0 : 1;
            if (args.command == "uninstall")
                return uninstallService() ? 0 : 1;
            if (args.command == "start")
                return startService() ? 0 : 1;
            if (args.command == "stop")
                return stopService() ? 0 : 1;
            if (args.command == "status")
                return printStatus();
            if (args.command == "run")
            {
                return runAsProcess();
            }
            if (args.command != "--service")
                return printHelp(argv[0]);
        }

        return runAsWindowsService();
    }

private:
    struct ParsedArgs
    {
        std::string command;
        bool hasToken{false};
        std::string token;
        bool enablePpl{false};
        bool enableModules{false};
        bool enableKernelModules{false};
        // v3 G: install/run can bind an explicit port; install embeds it into
        // the service binPath so SCM startup honours it. Default 0 = use the
        // PGS default / restored-from-archive port.
        int port = 0;
        // v3 G: optional low-privilege service account. Empty = LocalSystem
        // (default; required for full cross-session restart). WARNING: a non-
        // LocalSystem account loses restartGuardInSession() ability and the
        // fallback launches the process in Session 0 (no user desktop).
        std::string serviceAccount;
        std::string servicePassword;
        // v3 E: permissive module-loading escape hatch (fails the allowlist).
        bool allowAllModules{false};
    };

    std::string m_serviceName;
    std::string m_logPath;
    std::string m_bootTokenHash;
    SERVICE_STATUS_HANDLE m_statusHandle = nullptr;
    SERVICE_STATUS m_status{};
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_stopping{false};
    std::atomic<bool> m_consoleStopRequested{false};
    PGS m_pgs;
    std::thread m_worker;
    std::mutex m_statusMutex;

    inline static PGSServiceHost *s_instance = nullptr;
    inline static PGSServiceHost *s_consoleInstance = nullptr;

    bool installService(const ParsedArgs &args)
    {
        SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
        if (!scm)
        {
            std::cerr << "OpenSCManager failed: " << GetLastError() << "\n";
            return false;
        }

        char exePath[MAX_PATH]{};
        GetModuleFileNameA(nullptr, exePath, MAX_PATH);
        std::string binPath = "\"" + std::string(exePath) + "\" --service";
        // v3 G: persist the chosen listen port into the service command line so
        // SCM-started instances bind the same port without needing --port again.
        if (args.port > 0)
        {
            binPath += " --port " + std::to_string(args.port);
        }
        if (args.enableModules)
        {
            binPath += " --enable-modules";
        }
        if (args.enablePpl)
        {
            binPath += " --enable-ppl";
        }
        if (args.enableKernelModules)
        {
            binPath += " --enable-kernel-modules";
        }
        if (args.allowAllModules)
        {
            binPath += " --allow-all-modules";
        }

        // v3 G: optional low-privilege service account. LocalSystem (nullptr)
        // is the default and is REQUIRED for full cross-session
        // restartGuardInSession() — a non-LocalSystem account will lose that
        // ability and the fallback launches guarded processes in Session 0.
        const char *account = args.serviceAccount.empty() ? nullptr : args.serviceAccount.c_str();
        const char *password = args.servicePassword.empty() ? nullptr : args.servicePassword.c_str();
        if (account)
        {
            std::cout << "WARNING: installing with a non-LocalSystem account; cross-session guard restart will be limited to the Session-0 fallback.\n";
        }

        SC_HANDLE service = CreateServiceA(
            scm,
            m_serviceName.c_str(),
            "ProcessGuard Service",
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            binPath.c_str(),
            nullptr,
            nullptr,
            nullptr,
            account,
            password);

        if (!service)
        {
            std::cerr << "CreateService failed: " << GetLastError() << "\n";
            CloseServiceHandle(scm);
            return false;
        }

        SERVICE_DESCRIPTIONA description{};
        description.lpDescription = const_cast<char *>("ProcessGuard service mode");
        ChangeServiceConfig2A(service, SERVICE_CONFIG_DESCRIPTION, &description);

        // Service self-guard is delegated to Windows SCM recovery instead of
        // trying to let the service "watch itself". A crashed process cannot
        // run its own recovery code, but SCM can restart it from outside.
        if (!configureServiceRecovery(service))
        {
            DeleteService(service);
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return false;
        }

        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        std::cout << "Service installed (SCM recovery enabled)\n";
        return true;
    }

    bool uninstallService()
    {
        SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm)
        {
            std::cerr << "OpenSCManager failed: " << GetLastError() << "\n";
            return false;
        }

        SC_HANDLE service = OpenServiceA(scm, m_serviceName.c_str(), DELETE);
        if (!service)
        {
            std::cerr << "OpenService failed: " << GetLastError() << "\n";
            CloseServiceHandle(scm);
            return false;
        }

        const bool ok = DeleteService(service) == TRUE;
        if (!ok)
        {
            std::cerr << "DeleteService failed: " << GetLastError() << "\n";
        }
        else
        {
            std::cout << "Service uninstalled\n";
        }

        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return ok;
    }

    bool startService()
    {
        SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm)
        {
            std::cerr << "OpenSCManager failed: " << GetLastError() << "\n";
            return false;
        }

        SC_HANDLE service = OpenServiceA(scm, m_serviceName.c_str(), SERVICE_START);
        if (!service)
        {
            std::cerr << "OpenService failed: " << GetLastError() << "\n";
            CloseServiceHandle(scm);
            return false;
        }

        const bool ok = StartServiceA(service, 0, nullptr) == TRUE;
        if (!ok)
        {
            std::cerr << "StartService failed: " << GetLastError() << "\n";
        }
        else
        {
            std::cout << "Service started\n";
        }

        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return ok;
    }

    bool stopService()
    {
        SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm)
        {
            std::cerr << "OpenSCManager failed: " << GetLastError() << "\n";
            return false;
        }

        SC_HANDLE service = OpenServiceA(scm, m_serviceName.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (!service)
        {
            std::cerr << "OpenService failed: " << GetLastError() << "\n";
            CloseServiceHandle(scm);
            return false;
        }

        SERVICE_STATUS status{};
        if (!QueryServiceStatus(service, &status))
        {
            std::cerr << "QueryServiceStatus failed: " << GetLastError() << "\n";
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return false;
        }

        if (status.dwCurrentState != SERVICE_STOPPED)
        {
            const bool ok = ControlService(service, SERVICE_CONTROL_STOP, &status) == TRUE;
            if (!ok)
            {
                std::cerr << "ControlService(STOP) failed: " << GetLastError() << "\n";
                CloseServiceHandle(service);
                CloseServiceHandle(scm);
                return false;
            }
        }

        const ULONGLONG deadline = GetTickCount64() + kServiceStopTimeoutMs;
        while (status.dwCurrentState != SERVICE_STOPPED)
        {
            DWORD waitMs = status.dwWaitHint / 10;
            if (waitMs < 250)
                waitMs = 250;
            if (waitMs > 2000)
                waitMs = 2000;
            Sleep(waitMs);

            if (!QueryServiceStatus(service, &status))
            {
                std::cerr << "QueryServiceStatus failed while stopping: " << GetLastError() << "\n";
                CloseServiceHandle(service);
                CloseServiceHandle(scm);
                return false;
            }

            if (GetTickCount64() > deadline)
            {
                std::cerr << "Timed out waiting for service to stop\n";
                CloseServiceHandle(service);
                CloseServiceHandle(scm);
                return false;
            }
        }

        std::cout << "Service stopped\n";
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return true;
    }

    int printStatus()
    {
        SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm)
        {
            std::cerr << "OpenSCManager failed: " << GetLastError() << "\n";
            return 1;
        }

        SC_HANDLE service = OpenServiceA(scm, m_serviceName.c_str(), SERVICE_QUERY_STATUS);
        if (!service)
        {
            std::cout << "Status: Not installed\n";
            CloseServiceHandle(scm);
            return 0;
        }

        SERVICE_STATUS status{};
        if (!QueryServiceStatus(service, &status))
        {
            std::cerr << "QueryServiceStatus failed: " << GetLastError() << "\n";
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return 1;
        }

        std::string state = "Unknown";
        switch (status.dwCurrentState)
        {
        case SERVICE_STOPPED:
            state = "Stopped";
            break;
        case SERVICE_START_PENDING:
            state = "StartPending";
            break;
        case SERVICE_STOP_PENDING:
            state = "StopPending";
            break;
        case SERVICE_RUNNING:
            state = "Running";
            break;
        default:
            break;
        }

        std::cout << "Status: " << state << "\n";
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 0;
    }

    int printHelp(const char *exe) const
    {
        std::cout
            << "Usage: " << exe << " [install|uninstall|start|stop|status|run|--service] [options]\n"
            << "Options: --token <value> --port <1-65535> --enable-modules --enable-kernel-modules\n"
            << "         --enable-risk critical --enable-ppl (legacy alias) --allow-all-modules --no-allow-all-modules\n"
            << "       Set PGS_SERVICE_TOKEN to provide the service token without exposing it on the command line.\n";
        return 1;
    }

    int runAsProcess()
    {
        s_consoleInstance = this;
        m_consoleStopRequested = false;
        const bool handlerInstalled = SetConsoleCtrlHandler(&PGSServiceHost::staticConsoleCtrlHandler, TRUE) == TRUE;
        if (!handlerInstalled)
        {
            std::cerr << "SetConsoleCtrlHandler failed: " << GetLastError() << "\n";
        }

        if (!m_pgs.initialize(m_logPath, m_bootTokenHash))
        {
            if (handlerInstalled)
            {
                SetConsoleCtrlHandler(&PGSServiceHost::staticConsoleCtrlHandler, FALSE);
            }
            if (s_consoleInstance == this)
            {
                s_consoleInstance = nullptr;
            }
            return 1;
        }

        if (!m_pgs.start())
        {
            if (handlerInstalled)
            {
                SetConsoleCtrlHandler(&PGSServiceHost::staticConsoleCtrlHandler, FALSE);
            }
            if (s_consoleInstance == this)
            {
                s_consoleInstance = nullptr;
            }
            return 1;
        }

        std::cout << "PGS running in console mode. Press Ctrl+C to stop.\n";
        while (m_pgs.isRunning())
        {
            // The console control callback only flips a flag. Shutdown work
            // happens here on the main thread so we avoid doing heavier service
            // teardown directly inside the Win32 console callback.
            if (m_consoleStopRequested.exchange(false))
            {
                m_pgs.stop();
                break;
            }
            Sleep(kConsolePollIntervalMs);
        }

        if (handlerInstalled)
        {
            SetConsoleCtrlHandler(&PGSServiceHost::staticConsoleCtrlHandler, FALSE);
        }
        if (s_consoleInstance == this)
        {
            s_consoleInstance = nullptr;
        }
        return 0;
    }

    int runAsWindowsService()
    {
        s_instance = this;
        SERVICE_TABLE_ENTRYA table[] = {
            {const_cast<char *>(m_serviceName.c_str()), &PGSServiceHost::staticServiceMain},
            {nullptr, nullptr}};

        if (!StartServiceCtrlDispatcherA(table))
        {
            std::cerr << "StartServiceCtrlDispatcher failed: " << GetLastError() << "\n";
            return 1;
        }
        return 0;
    }

    void serviceMain()
    {
        // Windows calls us here after SCM has connected the service entrypoint.
        // From this moment on, every state transition must be reported back to
        // SCM or the service manager will treat startup/shutdown as hung.
        m_statusHandle = RegisterServiceCtrlHandlerExA(
            m_serviceName.c_str(),
            &PGSServiceHost::staticServiceControlHandlerEx,
            nullptr);

        if (!m_statusHandle)
        {
            return;
        }

        updateStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

        if (!m_pgs.initialize(m_logPath, m_bootTokenHash) || !m_pgs.start())
        {
            updateStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
            return;
        }

        m_running = true;
        m_worker = std::thread([this]() {
            // Keep the service thread free for SCM callbacks. The helper thread
            // just waits for a stop signal and performs the blocking shutdown of
            // the PGS core outside the control handler path.
            while (m_running.load())
            {
                Sleep(500);
            }
            m_stopping = true;
            std::thread stopStatusPulse([this]() {
                while (m_stopping.load())
                {
                    updateStatus(SERVICE_STOP_PENDING, NO_ERROR, 10000);
                    Sleep(2000);
                }
            });
            m_pgs.stop();
            m_stopping = false;
            if (stopStatusPulse.joinable())
            {
                stopStatusPulse.join();
            }
        });

        updateStatus(SERVICE_RUNNING, NO_ERROR, 0);

        if (m_worker.joinable())
        {
            m_worker.join();
        }

        updateStatus(SERVICE_STOPPED, NO_ERROR, 0);
    }

    DWORD controlHandlerEx(DWORD control)
    {
        if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN)
        {
            updateStatus(SERVICE_STOP_PENDING, NO_ERROR, 3000);
            m_running = false;
            return NO_ERROR;
        }

        if (control == SERVICE_CONTROL_INTERROGATE)
        {
            SetServiceStatus(m_statusHandle, &m_status);
            return NO_ERROR;
        }

        return NO_ERROR;
    }

    void updateStatus(DWORD state, DWORD win32ExitCode, DWORD waitHint)
    {
        std::lock_guard<std::mutex> lock(m_statusMutex);
        m_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        m_status.dwCurrentState = state;
        m_status.dwWin32ExitCode = win32ExitCode;
        m_status.dwWaitHint = waitHint;
        m_status.dwControlsAccepted =
            (state == SERVICE_RUNNING) ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) : 0;
        m_status.dwCheckPoint =
            (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) ? m_status.dwCheckPoint + 1 : 0;

        SetServiceStatus(m_statusHandle, &m_status);
    }

    static void WINAPI staticServiceMain(DWORD, LPSTR *)
    {
        if (s_instance)
        {
            s_instance->serviceMain();
        }
    }

    static DWORD WINAPI staticServiceControlHandlerEx(DWORD control, DWORD, LPVOID, LPVOID)
    {
        if (!s_instance)
        {
            return ERROR_INVALID_DATA;
        }
        return s_instance->controlHandlerEx(control);
    }

    static BOOL WINAPI staticConsoleCtrlHandler(DWORD controlType)
    {
        if (!s_consoleInstance)
        {
            return FALSE;
        }

        switch (controlType)
        {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            s_consoleInstance->m_consoleStopRequested = true;
            return TRUE;
        default:
            return FALSE;
        }
    }

    static bool parseArguments(int argc, char *argv[], ParsedArgs &out)
    {
        out = ParsedArgs{};
        auto parsePort = [](const std::string &text, int &port) {
            try
            {
                std::size_t consumed = 0;
                const int parsed = std::stoi(text, &consumed, 10);
                if (consumed != text.size() || parsed <= 0 || parsed > 65535)
                    return false;
                port = parsed;
                return true;
            }
            catch (const std::exception &)
            {
                return false;
            }
        };

        for (int i = 1; i < argc; ++i)
        {
            const std::string arg = argv[i];
            if (arg == "--token")
            {
                if (i + 1 >= argc)
                {
                    return false;
                }
                out.hasToken = true;
                out.token = argv[++i];
                if (out.token.empty())
                {
                    return false;
                }
                continue;
            }

            if (arg == "--enable-ppl")
            {
                out.enablePpl = true;
                continue;
            }

            if (arg == "--enable-modules")
            {
                out.enableModules = true;
                continue;
            }

            if (arg == "--enable-kernel-modules")
            {
                out.enableModules = true;
                out.enableKernelModules = true;
                continue;
            }

            if (arg == "--enable-risk")
            {
                if (i + 1 >= argc)
                {
                    return false;
                }
                const std::string level = argv[++i];
                if (level == "critical" || level == "kernel")
                {
                    out.enableModules = true;
                    out.enableKernelModules = true;
                    continue;
                }
                return false;
            }

            // v3 G: explicit listen port (overrides the default / archive).
            if (arg == "--port")
            {
                const std::string next = (i + 1 < argc) ? argv[i + 1] : std::string();
                if (next.empty())
                {
                    return false;
                }
                int p = 0;
                if (!parsePort(next, p))
                {
                    return false;
                }
                out.port = p;
                ++i;
                continue;
            }

            // v3 E: permissive module-loading escape hatch (bypasses the
            // allowlist). Fail-closed by default; opt in for development only.
            if (arg == "--allow-all-modules")
            {
                out.allowAllModules = true;
                continue;
            }
            if (arg == "--no-allow-all-modules")
            {
                out.allowAllModules = false;
                continue;
            }

            // v3 G: optional low-privilege service account for install.
            if (arg == "--service-account")
            {
                if (i + 1 >= argc)
                {
                    return false;
                }
                out.serviceAccount = argv[++i];
                continue;
            }
            if (arg == "--service-password")
            {
                if (i + 1 >= argc)
                {
                    return false;
                }
                out.servicePassword = argv[++i];
                continue;
            }

            if (arg == "install" || arg == "uninstall" || arg == "start" || arg == "stop" ||
                arg == "status" || arg == "run" || arg == "--service")
            {
                if (!out.command.empty())
                {
                    return false;
                }
                out.command = arg;
                continue;
            }

            return false;
        }
        if (!out.hasToken)
        {
            if (const char *envToken = std::getenv("PGS_SERVICE_TOKEN"))
            {
                if (*envToken)
                {
                    out.hasToken = true;
                    out.token = envToken;
                }
            }
        }
        return true;
    }


    bool configureServiceRecovery(SC_HANDLE service)
    {
        SC_ACTION recoveryActions[3]{};
        for (auto &action : recoveryActions)
        {
            action.Type = SC_ACTION_RESTART;
            action.Delay = kServiceRecoveryDelayMs;
        }

        SERVICE_FAILURE_ACTIONSA failureActions{};
        failureActions.dwResetPeriod = kServiceRecoveryResetSeconds;
        failureActions.cActions = static_cast<DWORD>(sizeof(recoveryActions) / sizeof(recoveryActions[0]));
        failureActions.lpsaActions = recoveryActions;

        if (!ChangeServiceConfig2A(service, SERVICE_CONFIG_FAILURE_ACTIONS, &failureActions))
        {
            std::cerr << "ChangeServiceConfig2(failure actions) failed: " << GetLastError() << "\n";
            return false;
        }

#ifdef SERVICE_CONFIG_FAILURE_ACTIONS_FLAG
        SERVICE_FAILURE_ACTIONS_FLAG failureFlag{};
        failureFlag.fFailureActionsOnNonCrashFailures = TRUE;
        if (!ChangeServiceConfig2A(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &failureFlag))
        {
            std::cerr << "ChangeServiceConfig2(failure flag) failed: " << GetLastError() << "\n";
            return false;
        }
#endif

        return true;
    }
};
} // namespace

static std::string defaultServiceLogPath()
{
    const char *programData = std::getenv("ProgramData");
    std::filesystem::path root = (programData && *programData)
                                     ? std::filesystem::path(programData)
                                     : std::filesystem::path("C:\\ProgramData");
    std::filesystem::path logPath = root / "ProcessGuard" / "logs" / "pgs_service.log";
    return logPath.string();
}

int main(int argc, char *argv[])
{
    const std::string logPath = defaultServiceLogPath();
    // Restrict the data root (ProgramData\ProcessGuard and its logs/state) to
    // SYSTEM + Administrators + the runtime identity before any file is written,
    // so persisted secrets are not world-readable.
    {
        std::filesystem::path logP(logPath);
        std::filesystem::path logsDir = logP.parent_path();
        std::filesystem::path root = logsDir.parent_path();
        if (!root.empty())
        {
            ProcessGuard::util::secureCreateDirectory(root.string());
        }
        if (!logsDir.empty())
        {
            ProcessGuard::util::secureCreateDirectory(logsDir.string());
        }
    }
    Logger::initialize(logPath);
    Logger::warning("PGS service host boot, logPath=" + logPath);
    PGSServiceHost host("PGS", logPath);
    return host.run(argc, argv);
}
