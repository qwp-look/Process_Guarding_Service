#ifndef CLUSTER_SERVER_H
#define CLUSTER_SERVER_H

#include <QHash>
#include <QList>
#include <QObject>
#include <QSslCertificate>
#include <QStringList>
#include <QTimer>

class QNetworkAccessManager;
class QSslServer;
class QTcpServer;
namespace PgsHttp { class Request; class Server; }

class ClusterServer : public QObject
{
    Q_OBJECT

public:
    // One registered PGS node. credentials = "user:password" for Basic auth
    // against the node's remote gateway (HTTPS). The registry file persists
    // credentials locally with DPAPI when available, and list/summary APIs
    // intentionally never echo them.
    // generation fences off late replies after delete/re-add of the same name.
    struct Node
    {
        QString name;
        QString baseHttpsUrl; // e.g. https://10.0.0.5:12443
        QString credentials;  // user:pass (Basic auth)
        quint64 generation = 0;
    };

    explicit ClusterServer(QString nodesFile, QString listenAddress, quint16 listenPort,
                           QString apiToken, QString tlsCertPath = QString(),
                           QString tlsKeyPath = QString(), QString nodeCaCertPath = QString(),
                           bool nodeInsecureTls = false, QObject *parent = nullptr);
    bool start();
    QString listenUrl() const;

private:
    void loadNodes();
    void saveNodes();
    void pollAll();
    void pollNode(const Node &node);
    bool isApiAuthorized(const PgsHttp::Request &request) const;
    bool requiresApiToken() const;
    bool setupTls();
    bool loadNodeCaCertificates();

    // HTTP handlers
    class QHttpServerResponse handleDashboard() const;
    class QHttpServerResponse handleNodesList() const;
    class QHttpServerResponse handleNodeAdd(const PgsHttp::Request &request);
    class QHttpServerResponse handleNodeRemove(const PgsHttp::Request &request);
    class QHttpServerResponse handleSummary() const;

    QString m_nodesFile;
    QString m_listenAddress;
    quint16 m_listenPort;
    QString m_apiToken;
    QString m_tlsCertPath;
    QString m_tlsKeyPath;
    QString m_nodeCaCertPath;
    bool m_nodeInsecureTls = false;
    bool m_apiTokenGenerated = false;
    bool m_remoteBind = false;
    bool m_tlsEnabled = false;
    QList<QSslCertificate> m_nodeCaCertificates;
    PgsHttp::Server *m_server = nullptr;
    QNetworkAccessManager *m_nam = nullptr;
    QTcpServer *m_tcpServer = nullptr;
    QSslServer *m_sslServer = nullptr;
    QTimer m_pollTimer;
    QHash<QString, Node> m_nodes;
    quint64 m_nextNodeGeneration = 1;
    quint64 m_nextPollSerial = 1;

    // Cached poll results: node name -> JSON object (health+guards).
    struct NodeCache
    {
        quint64 generation = 0;
        bool healthReachable = false;
        bool guardsReachable = false;
        QString healthError;
        QString guardsError;
        QString healthJson;   // raw /api/cluster/health body
        QString guardsJson;   // raw /api/guards body
        quint64 healthSerial = 0;
        quint64 guardsSerial = 0;
        qint64 lastUpdatedMs = 0;
    };
    QHash<QString, NodeCache> m_cache;
};

#endif // CLUSTER_SERVER_H
