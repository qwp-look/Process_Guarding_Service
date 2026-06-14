#include <conio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

namespace
{
const std::string kBase64Chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

int g_maxRestarts = -1; // -1 means "no"
bool g_submitRestartPolicy = false;
std::string g_token;

std::string base64Encode(const std::string &input)
{
    std::string output;
    int val = 0;
    int valb = -6;
    for (unsigned char c : input)
    {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0)
        {
            output.push_back(kBase64Chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6)
    {
        output.push_back(kBase64Chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    while (output.size() % 4 != 0)
    {
        output.push_back('=');
    }
    return output;
}

std::string wideToUtf8(const std::wstring &input)
{
    if (input.empty())
    {
        return std::string();
    }
    const int needed = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 0)
    {
        return std::string();
    }
    std::string out(static_cast<std::size_t>(needed), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, &out[0], needed, nullptr, nullptr) <= 0)
    {
        return std::string();
    }
    if (!out.empty() && out.back() == '\0')
    {
        out.pop_back();
    }
    return out;
}

std::string quoteArgUtf8(const std::string &arg)
{
    if (arg.empty())
    {
        return "\"\"";
    }

    bool needQuotes = false;
    for (char ch : arg)
    {
        if (ch == ' ' || ch == '\t' || ch == '"')
        {
            needQuotes = true;
            break;
        }
    }
    if (!needQuotes)
    {
        return arg;
    }

    std::string out = "\"";
    int backslashes = 0;
    for (char ch : arg)
    {
        if (ch == '\\')
        {
            ++backslashes;
            continue;
        }
        if (ch == '"')
        {
            out.append(backslashes * 2 + 1, '\\');
            out.push_back('"');
            backslashes = 0;
            continue;
        }
        if (backslashes > 0)
        {
            out.append(backslashes, '\\');
            backslashes = 0;
        }
        out.push_back(ch);
    }
    if (backslashes > 0)
    {
        out.append(backslashes * 2, '\\');
    }
    out.push_back('"');
    return out;
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

std::string defaultRestartArgs()
{
    std::string args;
    if (g_submitRestartPolicy)
    {
        args = std::string("--max-restarts ") + (g_maxRestarts < 0 ? std::string("no") : std::to_string(g_maxRestarts));
    }
    if (!g_token.empty())
    {
        if (!args.empty())
        {
            args += " ";
        }
        args += "--token ";
        args += quoteArgUtf8(g_token);
    }
    return args;
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
    const std::string wirePayload = std::string("token ") + g_token + " " + commandLine + "\n";

    if (send(sock, wirePayload.c_str(), static_cast<int>(wirePayload.size()), 0) == SOCKET_ERROR)
    {
        closesocket(sock);
        return false;
    }

    std::string response;
    char buffer[512] = {0};
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

bool registerGuard()
{
    const std::string path = currentExecutablePath();
    if (path.empty())
    {
        return false;
    }

    std::ostringstream oss;
    const int effectiveMaxRestarts = g_submitRestartPolicy ? g_maxRestarts : 3;
    oss << "register " << currentPid() << "|" << base64Encode(path)
        << "|" << (effectiveMaxRestarts < 0 ? std::string("no") : std::to_string(effectiveMaxRestarts))
        << "|" << defaultRestartArgs();
    oss << "\n";
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
} // namespace

int main(int argc, char *argv[])
{
    g_submitRestartPolicy = false;
    g_token.clear();
    if (const char *envToken = std::getenv("PGS_AUTH_TOKEN"))
    {
        g_token = envToken;
    }
    for (int i = 1; i < argc; ++i)
    {
        const std::string arg = argv[i];
        if (arg == "--token")
        {
            if (i + 1 >= argc)
            {
                std::cerr << "Usage: " << argv[0] << " [--token <value>] [--max-restarts N|no]\n";
                return 1;
            }
            g_token = argv[++i];
            continue;
        }
        if (arg == "--max-restarts")
        {
            if (i + 1 >= argc || !parseMaxRestarts(argv[++i], g_maxRestarts))
            {
                std::cerr << "Usage: " << argv[0] << " [--token <value>] [--max-restarts N|no]\n";
                return 1;
            }
            g_submitRestartPolicy = true;
            continue;
        }

        std::cerr << "Usage: " << argv[0] << " [--token <value>] [--max-restarts N|no]\n";
        return 1;
    }

    WSADATA wsaData{};
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }

    std::cout << "Guard example started, pid=" << currentPid() << "\n";
    if (g_submitRestartPolicy)
    {
        std::cout << "Requested max-restarts: " << (g_maxRestarts < 0 ? "no" : std::to_string(g_maxRestarts)) << "\n";
    }
    else
    {
        std::cout << "Using PGS default restart policy: 3\n";
    }

    if (!registerGuard())
    {
        std::cerr << "Failed to register to PGS (is service running / token configured?)\n";
        WSACleanup();
        return 1;
    }

    std::cout << "Registered. Press 'q' to intentional exit, 'c' to simulate crash.\n";
    for (;;)
    {
        if (!_kbhit())
        {
            Sleep(100);
            continue;
        }

        const int key = _getch();
        if (key == 'q' || key == 'Q')
        {
            notifyIntentionalExit();
            std::cout << "Intentional exit sent\n";
            WSACleanup();
            return 0;
        }

        if (key == 'c' || key == 'C')
        {
            std::cerr << "Simulating crash\n";
            WSACleanup();
            return 1;
        }
    }
}
