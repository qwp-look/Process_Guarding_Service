/**
 * @file PGSClient.cpp
 * @brief Implementation of the shared PGS management-protocol client.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "Process_Guard/PGSClient.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include "Process_Guard/PGUtil.h"

#include <string>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

namespace ProcessGuard::client
{

    std::string trim(std::string value)
    {
        return ProcessGuard::util::trim(std::move(value));
    }

    std::string base64Encode(const std::string &input)
    {
        return ProcessGuard::util::base64Encode(input);
    }

    std::string base64Decode(const std::string &input)
    {
        return ProcessGuard::util::base64Decode(input);
    }

    std::vector<std::string> split(const std::string &value, char delimiter)
    {
        return ProcessGuard::util::split(value, delimiter);
    }

    std::string jsonEscape(const std::string &value)
    {
        std::string out;
        out.reserve(value.size() + 8);
        for (char c : value)
        {
            switch (c)
            {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out.push_back(c); break;
            }
        }
        return out;
    }

    std::string maxRestartsLabel(int maxRestarts)
    {
        return ProcessGuard::util::maxRestartsLabel(maxRestarts);
    }

    std::string withAuthToken(const std::string &token, const std::string &command)
    {
        if (token.empty())
        {
            return command;
        }
        return "token " + base64Encode(token) + " " + command;
    }

    static bool sendAll(SOCKET socket, const std::string &payload)
    {
        std::size_t totalSent = 0;
        while (totalSent < payload.size())
        {
            const int sent = send(socket, payload.data() + totalSent,
                                  static_cast<int>(payload.size() - totalSent), 0);
            if (sent <= 0)
            {
                return false;
            }
            totalSent += static_cast<std::size_t>(sent);
        }
        return true;
    }

    ClientResponse sendCommand(const ClientOptions &options, const std::string &command, std::uint32_t timeoutMs)
    {
        ClientResponse response;

        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET)
        {
            response.error = "socket failed, error=" + std::to_string(WSAGetLastError());
            return response;
        }

        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(options.port);
        if (inet_pton(AF_INET, options.host.c_str(), &serverAddr.sin_addr) != 1)
        {
            closesocket(sock);
            response.error = "invalid host: " + options.host;
            return response;
        }

        if (connect(sock, reinterpret_cast<sockaddr *>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR)
        {
            response.error = "connect failed, error=" + std::to_string(WSAGetLastError());
            closesocket(sock);
            return response;
        }

        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&timeoutMs), sizeof(timeoutMs));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char *>(&timeoutMs), sizeof(timeoutMs));

        std::string payload = command;
        if (payload.empty() || payload.back() != '\n')
        {
            payload.push_back('\n');
        }
        if (!sendAll(sock, payload))
        {
            response.error = "send failed, error=" + std::to_string(WSAGetLastError());
            closesocket(sock);
            return response;
        }

        char buffer[1024];
        std::string text;
        for (;;)
        {
            const int received = recv(sock, buffer, static_cast<int>(sizeof(buffer)), 0);
            if (received <= 0)
            {
                break;
            }
            text.append(buffer, static_cast<std::size_t>(received));
        }

        closesocket(sock);
        response.ok = true;
        response.payload = trim(text);
        return response;
    }

} // namespace ProcessGuard::client