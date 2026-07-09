#ifndef WEB_SERVER_H
#define WEB_SERVER_H

#include <QObject>
#include <QStringList>
#include <QHash>
#include <QByteArray>

class QHttpServer;
class QHttpServerRequest;
class QHttpServerResponse;
class QTcpServer;
class QSslCertificate;
class QSslKey;

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
        bool tlsAutocert = false; // generate a self-signed cert on first run
        QString usersFile;        // RBAC users file (user;role;salthash)
        QString auditLogPath;     // append-only audit log for mutating ops
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
    QHttpServerResponse handleGuards();
    QHttpServerResponse handleGuard(const QHttpServerRequest &request);
    QHttpServerResponse handleBless(const QHttpServerRequest &request);
    QHttpServerResponse handleBlessStart(const QHttpServerRequest &request);
    QHttpServerResponse handlePolicy(const QHttpServerRequest &request);
    QHttpServerResponse handleUnbless(const QHttpServerRequest &request);
    QHttpServerResponse handleIntentional(const QHttpServerRequest &request);
    QHttpServerResponse handleTokenUpdate(const QHttpServerRequest &request);
    QHttpServerResponse handleServiceStatus();
    QHttpServerResponse handleServiceAction(const QString &action);
    QHttpServerResponse handleIndex() const;
    QHttpServerResponse handleIndexHtml() const;
    bool isRequestAuthorized(const QHttpServerRequest &request) const;

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
    static QHttpServerResponse jsonCommandResult(const CommandResult &result, const QString &message = QString(), bool allowRawStdout = true);

    Options m_options;
    QString m_apiToken;
    QHttpServer *m_server = nullptr;
    QTcpServer *m_tcpServer = nullptr;
    class QSslServer *m_sslServer = nullptr;
    QSslCertificate *m_sslCert = nullptr;
    QSslKey *m_sslKey = nullptr;
    // RBAC: user -> (role, salt-hash). Loaded from usersFile.
    struct UserRec { QString role; QByteArray saltHash; };
    QHash<QString, UserRec> m_users;
    // Audit log stream (opened lazily).
    class QFile *m_auditFile = nullptr;
    bool loadUsers();
    void audit(const QString &user, const QString &action, const QString &sourceIp);
    void auditUser(const QHttpServerRequest &request, const QString &action);
    bool authenticateAndAuthorize(const QHttpServerRequest &request, int requiredRole, QString &outUser);
    bool setupTls();
    static QByteArray saltHash(const QByteArray &salt, const QByteArray &password);
};

#endif // WEB_SERVER_H
