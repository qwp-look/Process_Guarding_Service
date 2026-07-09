#ifndef CLUSTER_SERVER_H
#define CLUSTER_SERVER_H

#include <QHash>
#include <QObject>
#include <QStringList>
#include <QTimer>

class QHttpServer;
class QHttpServerRequest;
class QNetworkAccessManager;

class ClusterServer : public QObject
{
    Q_OBJECT

public:
    // One registered PGS node. credentials = "user:password" for Basic auth
    // against the node's remote gateway (HTTPS). Stored in-memory only; the
    // node registry is loaded from a simple text file on startup and edited
    // via the /api/cluster/nodes CRUD endpoints.
    struct Node
    {
        QString name;
        QString baseHttpsUrl; // e.g. https://10.0.0.5:12443
        QString credentials;  // user:pass (Basic auth)
    };

    explicit ClusterServer(QString nodesFile, quint16 listenPort, QObject *parent = nullptr);
    bool start();
    QString listenUrl() const;

private:
    void loadNodes();
    void saveNodes();
    void pollAll();
    void pollNode(const Node &node);

    // HTTP handlers
    class QHttpServerResponse handleDashboard() const;
    class QHttpServerResponse handleNodesList() const;
    class QHttpServerResponse handleNodeAdd(const QHttpServerRequest &request);
    class QHttpServerResponse handleNodeRemove(const QHttpServerRequest &request);
    class QHttpServerResponse handleSummary() const;

    QString m_nodesFile;
    quint16 m_listenPort;
    QHttpServer *m_server = nullptr;
    QNetworkAccessManager *m_nam = nullptr;
    QTimer m_pollTimer;
    QHash<QString, Node> m_nodes;

    // Cached poll results: node name -> JSON object (health+guards).
    struct NodeCache
    {
        bool reachable = false;
        QString lastError;
        QString healthJson;   // raw /api/cluster/health body
        QString guardsJson;   // raw /api/guards body
        qint64 lastUpdatedMs = 0;
    };
    QHash<QString, NodeCache> m_cache;
};

#endif // CLUSTER_SERVER_H
