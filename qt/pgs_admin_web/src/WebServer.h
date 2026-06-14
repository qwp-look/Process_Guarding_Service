#ifndef WEB_SERVER_H
#define WEB_SERVER_H

#include <QObject>
#include <QStringList>

class QHttpServer;
class QHttpServerRequest;
class QHttpServerResponse;
class QTcpServer;

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
    };

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

    // Phase-1 implementation intentionally reuses pgs_bless/pgs_service as the
    // integration boundary. That keeps the browser console thin and lets it
    // inherit mature CLI behavior instead of duplicating protocol logic. A
    // future shared PGSClient layer can replace this without changing the UI.
    CommandResult runTool(const QString &program, const QStringList &args, int timeoutMs = 30000) const;
    QString resolvedBlessToolPath() const;
    QString resolvedServiceToolPath() const;
    QStringList blessBaseArguments() const;

    static QHttpServerResponse jsonOk(const QString &message);
    static QHttpServerResponse jsonError(const QString &message, int statusCode = 400);
    static QHttpServerResponse jsonCommandResult(const CommandResult &result, const QString &message = QString(), bool allowRawStdout = true);

    Options m_options;
    QHttpServer *m_server = nullptr;
    QTcpServer *m_tcpServer = nullptr;
};

#endif // WEB_SERVER_H
