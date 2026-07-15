#ifndef WEB_SERVER_H
#define WEB_SERVER_H

#include <QObject>
#include <QStringList>
#include <QHash>
#include <QByteArray>

class QHttpServerResponse;
class QTcpServer;
class QSslCertificate;
class QSslKey;
namespace PgsHttp { class Request; class Server; }

class WebServer : public QObject
{
    Q_OBJECT

public:
    // Web console stays out-of-process from PGS on purpose:
    // - PGS continues to own only guard logic and its local text protocol
    // - WebServer owns HTTP/JSON/HTML concerns
    // - browser clients never talk to the raw management socket directly
    struct Options
    {
        QString bindAddress;
        quint16 httpPort = 18080;
        QString pgsHost;
        quint16 pgsPort = 12345;
        QString pgsToken;
        QString blessToolPath;
        QString serviceToolPath;
        // Remote-gateway mode (Stage C). When `remote` is true the server
        // accepts non-loopback binds, forces TLS, and authenticates every
        // request against an RBAC user store instead of the local-only API
        // token. Default posture stays local + token-only.
        bool remote = false;
        QString tlsCertPath;
        QString tlsKeyPath;
        bool tlsAutocert = false; // reserved; remote mode currently requires explicit PEM files
        QString usersFile;        // RBAC users file; see loadUsers() for supported formats.
        QString auditLogPath;     // append-only audit log for remote API/auth events
    };

    // RBAC roles. viewer = read-only; operator = + guard ops; admin = all.
    enum class Role { Viewer = 0, Operator = 1, Admin = 2 };
    static int roleRequired(const QString &route);

    explicit WebServer(Options options, QObject *parent = nullptr);
    bool start();
    QString listenUrl() const;

private:
    struct CommandResult
    {
        bool started = false;
        bool finished = false;
        int exitCode = -1;
        QString stdOut;
        QString stdErr;
        QString errorText;
    };

    QHttpServerResponse handleHealth() const;
    QHttpServerResponse handleClusterHealth();
    QHttpServerResponse handlePing();
    QHttpServerResponse handleDoctor();
    QHttpServerResponse handleGuards();
    QHttpServerResponse handleGuard(const PgsHttp::Request &request);
    QHttpServerResponse handleBless(const PgsHttp::Request &request);
    QHttpServerResponse handleBlessStart(const PgsHttp::Request &request);
    QHttpServerResponse handlePolicy(const PgsHttp::Request &request);
    QHttpServerResponse handleUnbless(const PgsHttp::Request &request);
    QHttpServerResponse handleIntentional(const PgsHttp::Request &request);
    QHttpServerResponse handleTokenUpdate(const PgsHttp::Request &request);
    QHttpServerResponse handleServiceStatus();
    QHttpServerResponse handleServiceAction(const QString &action);
    QHttpServerResponse handleAudit(const PgsHttp::Request &request) const;
    QHttpServerResponse handleIndex() const;
    QHttpServerResponse handleIndexHtml() const;
    bool isRequestAuthorized(const PgsHttp::Request &request) const;
    bool isLocalPageRequestAllowed(const PgsHttp::Request &request) const;

    // Phase-1 implementation intentionally reuses pgs_bless/pgs_service as the
    // integration boundary. That keeps the browser console thin and lets it
    // inherit mature CLI behavior instead of duplicating protocol logic. A
    // future shared util layer can replace this without changing the UI.
    CommandResult runTool(const QString &program, const QStringList &args, int timeoutMs = 30000) const;
    CommandResult runPgsDirect(const QString &wireCommand) const;
    QString resolvedBlessToolPath() const;
    QString resolvedServiceToolPath() const;
    QStringList blessBaseArguments() const;

    static QHttpServerResponse jsonOk(const QString &message);
    static QHttpServerResponse jsonError(const QString &message, int statusCode = 400);
    static QHttpServerResponse jsonUnauthorized();
    static QHttpServerResponse jsonCommandResult(const CommandResult &result, const QString &message = QString(), bool allowRawStdout = true);

    Options m_options;
    QString m_apiToken;
    PgsHttp::Server *m_server = nullptr;
    QTcpServer *m_tcpServer = nullptr;
    class QSslServer *m_sslServer = nullptr;
    QSslCertificate *m_sslCert = nullptr;
    QSslKey *m_sslKey = nullptr;
    // RBAC: user -> password verifier. Loaded from usersFile.
    struct UserRec
    {
        QString role;
        QString scheme;
        QByteArray salt;
        QByteArray hash;
        int iterations = 0;
    };
    QHash<QString, UserRec> m_users;
    struct LoginFailure { int count = 0; qint64 blockedUntilMs = 0; };
    QHash<QString, LoginFailure> m_loginFailures;
    // Audit log stream (opened lazily).
    class QFile *m_auditFile = nullptr;
    bool loadUsers();
    void audit(const QString &user, const QString &action, const QString &sourceIp);
    void auditUser(const PgsHttp::Request &request, const QString &action);
    bool authenticateAndAuthorize(const PgsHttp::Request &request, int requiredRole, QString &outUser);
    bool setupTls();
    static QByteArray saltHash(const QByteArray &salt, const QByteArray &password);
    static QByteArray pbkdf2Hash(const QByteArray &salt, const QByteArray &password, int iterations, quint64 keyLength);
};

#endif // WEB_SERVER_H
