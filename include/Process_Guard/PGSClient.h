#ifndef PROCESS_GUARD_PGS_CLIENT_H
#define PROCESS_GUARD_PGS_CLIENT_H

#include <cstdint>
#include <string>
#include <vector>

namespace ProcessGuard
{

    struct PGSConnectionOptions
    {
        std::string host = "127.0.0.1";
        unsigned short port = 12345;
        std::string token;
        bool useAuth = true;
    };

    struct PGSGuardSummary
    {
        // Keep the parsed representation close to the wire schema so both CLI
        // tools and the web console can render the same data without each
        // having to understand the raw "KEY=VALUE;..." protocol.
        std::uint32_t pid = 0;
        std::string pidText;
        std::string session;
        std::string alive;
        std::string intentional;
        std::string maxRestarts;
        std::string restartCount;
        std::string hashVerified;
        std::string hash;
        std::string path;
        std::string restartArgs;
    };

    struct PGSCommandResult
    {
        bool transportOk = false;
        bool ok = false;
        std::string response;
        std::string statusLine;
        std::string error;
        std::vector<PGSGuardSummary> guards;
    };

    class PGSClient
    {
    public:
        explicit PGSClient(PGSConnectionOptions options = {});

        const PGSConnectionOptions &options() const;

        PGSCommandResult ping() const;
        PGSCommandResult list() const;
        PGSCommandResult get(std::uint32_t pid) const;
        PGSCommandResult registerGuard(std::uint32_t pid,
                                       const std::string &path,
                                       int maxRestarts,
                                       const std::string &restartArgs,
                                       const std::string &fileHash) const;
        PGSCommandResult unregisterPid(std::uint32_t pid) const;
        PGSCommandResult setPolicy(std::uint32_t pid, int maxRestarts, const std::string &restartArgs) const;
        PGSCommandResult intentionalExit(std::uint32_t pid) const;
        PGSCommandResult setToken(const std::string &oldToken, const std::string &newToken) const;
        PGSCommandResult sendRawCommand(const std::string &command, const std::string *tokenOverride = nullptr) const;

        static std::string base64Encode(const std::string &input);
        static std::string base64Decode(const std::string &input);
        static std::string maxRestartsLabel(int maxRestarts);

    private:
        PGSConnectionOptions m_options;
    };

} // namespace ProcessGuard

#endif // PROCESS_GUARD_PGS_CLIENT_H
