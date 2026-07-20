/**
 * @file PGSClient.h
 * @brief Shared PGS management-protocol client.
 *
 * Consolidates the line-oriented TCP protocol (auth envelope, send/recv,
 * base64/KV helpers) that was previously duplicated in pgs_bless.cpp and
 * re-implemented via QProcess in the Qt/Web admin frontends. Linking this
 * single implementation into all three clients removes the per-command
 * process spawn and the JSON-over-stdout coupling in the admin surfaces.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef PROCESS_GUARD_PGS_CLIENT_H
#define PROCESS_GUARD_PGS_CLIENT_H

#include <cstdint>
#include <string>
#include <vector>

namespace ProcessGuard::client
{

    struct ClientOptions
    {
        std::string host = "127.0.0.1";
        std::uint16_t port = 12345;
        std::string token;
    };

    struct ClientResponse
    {
        bool ok = false;        // transport succeeded (connected + got a reply)
        std::string payload;    // trimmed reply text (may start with OK / ERR)
        std::string error;      // human-readable transport error when !ok
    };

    // Shared helpers (previously duplicated across CLI / service / admin).
    std::string trim(std::string value);
    std::string base64Encode(const std::string &input);
    std::string base64Decode(const std::string &input);
    std::vector<std::string> split(const std::string &value, char delimiter);
    std::string jsonEscape(const std::string &value);
    std::string maxRestartsLabel(int maxRestarts);

    // Build the "token <base64(token)> <command>" auth envelope. Empty token
    // returns the command unchanged (the service rejects empty tokens, so this
    // only happens when a caller has not configured auth yet).
    std::string withAuthToken(const std::string &token, const std::string &command);

    // Send one line-oriented command to PGS and return the trimmed reply.
    // The client initializes Winsock internally on first use; callers no longer
    // need a process-level WSAStartup precondition. timeoutMs bounds both send
    // and receive so a stuck server cannot pin the caller. One command == one
    // connection; the protocol is request/response.
    ClientResponse sendCommand(const ClientOptions &options, const std::string &command, std::uint32_t timeoutMs = 3000);

} // namespace ProcessGuard::client

#endif // PROCESS_GUARD_PGS_CLIENT_H
