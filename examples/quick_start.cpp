#include <conio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "Process_Guard/PGUtil.h"

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

namespace
{
using namespace ProcessGuard::util;

int g_maxRestarts = -1; // -1 means "no"
int g_restartIndex = 0;
std::string g_token;

// Thin UTF-8 wrapper over the shared wide arg-quoting helper in PGUtil.
std::string quoteArgUtf8(const std::string &arg)
{
    return wideToUtf8(quoteArgW(utf8ToWide(arg)));
}

DWORD currentPid()
{
    return GetCurrentProcessId();
}

std::string currentExecutablePath()
{
    std::vector<wchar_t> path(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (length == 0 || length >= path.size())
    {
        return {};
    }
    return wideToUtf8(std::wstring(path.data(), path.data() + length));
}

bool sendToPGS(const std::string &payload)
{
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
    {
        return false;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(12345);
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);

    if (connect(sock, reinterpret_cast<sockaddr *>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR)
    {
        closesocket(sock);
        return false;
    }

    std::string commandLine = payload;
    const std::size_t lineBreak = commandLine.find('\n');
    if (lineBreak != std::string::npos)
    {
        commandLine = commandLine.substr(0, lineBreak);
    }
    const std::string wirePayload = std::string("token ") + base64Encode(g_token) + " " + commandLine + "\n";

    if (send(sock, wirePayload.c_str(), static_cast<int>(wirePayload.size()), 0) == SOCKET_ERROR)
    {
        closesocket(sock);
        return false;
    }

    std::string response;
    char buffer[4096] = {0};
    for (;;)
    {
        const int received = recv(sock, buffer, static_cast<int>(sizeof(buffer) - 1), 0);
        if (received <= 0)
        {
            break;
        }
        response.append(buffer, static_cast<std::size_t>(received));
    }

    closesocket(sock);
    return response.rfind("OK", 0) == 0;
}

std::string maxRestartsArgValue()
{
    return g_maxRestarts < 0 ? "no" : std::to_string(g_maxRestarts);
}

std::string restartArgsValue()
{
    std::string args = std::string("--logic --max-restarts ") + maxRestartsArgValue() +
                       " --restart-index ${PGS_RESTART_INDEX}";
    if (!g_token.empty())
    {
        args += " --token ";
        args += quoteArgUtf8(g_token);
    }
    return args;
}

bool registerGuard()
{
    const std::string path = currentExecutablePath();
    if (path.empty())
    {
        return false;
    }

    std::ostringstream oss;
    oss << "register " << currentPid() << "|" << base64Encode(path) << "|" << maxRestartsArgValue()
        << "|" << base64Encode(restartArgsValue()) << "\n";
    return sendToPGS(oss.str());
}

void notifyIntentionalExit()
{
    std::ostringstream oss;
    oss << "intentional " << currentPid() << "\n";
    sendToPGS(oss.str());
}

bool parseMaxRestarts(const std::string &value, int &outMaxRestarts)
{
    if (value == "no")
    {
        outMaxRestarts = -1;
        return true;
    }
    if (value.empty())
    {
        return false;
    }
    for (char c : value)
    {
        if (c < '0' || c > '9')
        {
            return false;
        }
    }
    try
    {
        outMaxRestarts = std::stoi(value);
        return outMaxRestarts >= 0;
    }
    catch (...)
    {
        return false;
    }
}

void showUsage(const char *exeName)
{
    std::cout
        << "Usage: " << exeName << " [--logic|--exit] [--token <value>] [--max-restarts N|no] [--restart-index N]\n"
        << "  --logic   register to PGS and wait key\n"
        << "  --exit    send intentional-exit to PGS\n"
        << "  --token   auth token (default empty token)\n"
        << "  --max-restarts N|no  submit restart policy to PGS on register\n"
        << "  --restart-index N    internal arg injected by PGS when restarting\n";
}

int runLogicMode()
{
    if (!registerGuard())
    {
        std::cerr << "Failed to register to PGS (is service running / token configured?)\n";
        WSACleanup();
        return -1;
    }

    std::cout << "Guard registered successfully. Press any key to exit intentionally.\n";
    std::cout << "Requested max-restarts: " << maxRestartsArgValue() << "\n";
    std::cout << "Current restart index: " << g_restartIndex << "\n";
    if (g_maxRestarts >= 0)
    {
        int remaining = g_maxRestarts - g_restartIndex;
        if (remaining < 0)
        {
            remaining = 0;
        }
        std::cout << "Remaining restart budget (display): " << remaining << "\n";
    }

    _getch();
    notifyIntentionalExit();
    WSACleanup();
    return 0;
}
} // namespace

int main(int argc, char *argv[])
{
    bool runExitMode = false;
    bool runLogic = false;
    g_maxRestarts = 3;
    g_restartIndex = 0;
    g_token.clear();
    if (const char *envToken = std::getenv("PGS_AUTH_TOKEN"))
    {
        g_token = envToken;
    }

    for (int i = 1; i < argc; ++i)
    {
        const std::string arg = argv[i];
        if (arg == "--exit")
        {
            runExitMode = true;
            continue;
        }
        if (arg == "--logic")
        {
            runLogic = true;
            continue;
        }
        if (arg == "--max-restarts")
        {
            if (i + 1 >= argc || !parseMaxRestarts(argv[++i], g_maxRestarts))
            {
                showUsage(argv[0]);
                return 1;
            }
            continue;
        }
        if (arg == "--token")
        {
            if (i + 1 >= argc)
            {
                showUsage(argv[0]);
                return 1;
            }
            g_token = argv[++i];
            continue;
        }
        if (arg == "--restart-index")
        {
            if (i + 1 >= argc)
            {
                showUsage(argv[0]);
                return 1;
            }
            try
            {
                g_restartIndex = std::stoi(argv[++i]);
                if (g_restartIndex < 0)
                {
                    showUsage(argv[0]);
                    return 1;
                }
            }
            catch (...)
            {
                showUsage(argv[0]);
                return 1;
            }
            continue;
        }

        std::cerr << "Unknown argument: " << arg << "\n";
        showUsage(argv[0]);
        return 1;
    }

    WSADATA wsaData{};
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }

    if (runExitMode)
    {
        notifyIntentionalExit();
        WSACleanup();
        return 0;
    }

    if (runLogic)
    {
        return runLogicMode();
    }

    if (argc <= 1)
    {
        return runLogicMode();
    }

    return runLogicMode();
}
