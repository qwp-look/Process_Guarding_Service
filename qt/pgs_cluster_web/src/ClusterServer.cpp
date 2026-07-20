/**
 * @file ClusterServer.cpp
 * @brief PGS cluster monitoring dashboard aggregator.
 *
 * Polls each registered node's /api/cluster/health and /api/guards on a timer,
 * caches the results, and serves a browser dashboard + JSON summary. The
 * dashboard is the Stage D deliverable: node cards, status, guard counts, and
 * offline/guard-dead alerts.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "ClusterServer.h"

#include "../../common/SimpleHttp.h"
#include <QAbstractSocket>
#include <QByteArray>
#include <QDateTime>
#include <QFile>
#include <QHostAddress>
#include <QHttpHeaders>
#include <QHttpServerRequest>
#include <QHttpServerResponse>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRandomGenerator>
#include <QEventLoop>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslKey>
#include <QSslServer>
#include <QSslSocket>
#include <QTextStream>
#include <QTimer>
#include <QTcpServer>
#include <QUrl>
#include <QVariant>
#include <utility>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <dpapi.h>
#endif

namespace
{
QHttpServerResponse jsonError(const QString &message, int statusCode)
{
    QJsonObject obj;
    obj.insert("ok", false);
    obj.insert("error", message);
    return QHttpServerResponse(obj, static_cast<QHttpServerResponse::StatusCode>(statusCode));
}

QHttpServerResponse jsonUnauthorized()
{
    QHttpServerResponse response = jsonError(QStringLiteral("unauthorized"), 401);
    QHttpHeaders headers = response.headers();
    headers.replaceOrAppend(QByteArrayLiteral("WWW-Authenticate"), QByteArrayLiteral("Basic realm=\"PGS Cluster\""));
    response.setHeaders(std::move(headers));
    return response;
}

bool isLoopbackBindAddress(const QHostAddress &address)
{
    const QString text = address.toString();
    return address == QHostAddress(QHostAddress::LocalHost) ||
           address == QHostAddress(QHostAddress::LocalHostIPv6) ||
           text == QStringLiteral("127.0.0.1") ||
           text == QStringLiteral("::1");
}

QString hostForUrl(const QString &host)
{
    const QString trimmed = host.trimmed();
    if (trimmed.contains(QLatin1Char(':')) &&
        !trimmed.startsWith(QLatin1Char('[')) &&
        !trimmed.endsWith(QLatin1Char(']')))
    {
        return QStringLiteral("[%1]").arg(trimmed);
    }
    return trimmed;
}

QString hostWithPort(const QString &host, quint16 port)
{
    return QStringLiteral("%1:%2").arg(hostForUrl(host)).arg(port);
}

bool localDashboardRequestAllowed(const PgsHttp::Request &request, const QString &listenAddress, quint16 port, bool tls)
{
    const QString host = request.value("Host").trimmed();
    const QString expectedHost = hostWithPort(listenAddress, port);
    const QString expectedAlt = QStringLiteral("localhost:%1").arg(port);
    if (!host.isEmpty() && host != expectedHost && host != expectedAlt)
        return false;
    const QString scheme = tls ? QStringLiteral("https") : QStringLiteral("http");
    const QString origin = request.value("Origin").trimmed();
    if (!origin.isEmpty())
    {
        const QString selfOrigin = QStringLiteral("%1://%2").arg(scheme, expectedHost);
        const QString selfOriginAlt = QStringLiteral("%1://%2").arg(scheme, expectedAlt);
        if (origin != selfOrigin && origin != selfOriginAlt)
            return false;
    }
    const QString referer = request.value("Referer").trimmed();
    if (!referer.isEmpty())
    {
        const QString selfOrigin = QStringLiteral("%1://%2").arg(scheme, expectedHost);
        const QString selfOriginAlt = QStringLiteral("%1://%2").arg(scheme, expectedAlt);
        if (!referer.startsWith(selfOrigin, Qt::CaseInsensitive) &&
            !referer.startsWith(selfOriginAlt, Qt::CaseInsensitive))
            return false;
    }
    return true;
}

QHttpServerResponse hardenHtmlResponse(QHttpServerResponse response)
{
    QHttpHeaders headers = response.headers();
    headers.replaceOrAppend(QByteArrayLiteral("Cache-Control"), QByteArrayLiteral("no-store"));
    headers.replaceOrAppend(QByteArrayLiteral("X-Content-Type-Options"), QByteArrayLiteral("nosniff"));
    headers.replaceOrAppend(QByteArrayLiteral("Content-Security-Policy"), QByteArrayLiteral("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"));
    response.setHeaders(std::move(headers));
    return response;
}

QHostAddress parseBindAddress(const QString &listenAddress)
{
    const QString normalized = listenAddress.trimmed().toLower();
    if (normalized == QLatin1String("localhost"))
    {
        return QHostAddress(QHostAddress::LocalHost);
    }
    QHostAddress address;
    address.setAddress(listenAddress.trimmed());
    return address;
}

bool constantTimeEquals(const QString &left, const QString &right)
{
    const QByteArray a = left.toUtf8();
    const QByteArray b = right.toUtf8();
    const int maxSize = qMax(a.size(), b.size());
    unsigned char diff = static_cast<unsigned char>(a.size() ^ b.size());
    for (int i = 0; i < maxSize; ++i)
    {
        const unsigned char av = i < a.size() ? static_cast<unsigned char>(a.at(i)) : 0;
        const unsigned char bv = i < b.size() ? static_cast<unsigned char>(b.at(i)) : 0;
        diff |= static_cast<unsigned char>(av ^ bv);
    }
    return diff == 0;
}

QString generateApiToken()
{
    QString token;
    token.reserve(64);
    for (int i = 0; i < 4; ++i)
    {
        token += QString::number(QRandomGenerator::global()->generate64(), 16).rightJustified(16, QLatin1Char('0'));
    }
    return token;
}

bool isUnsafeMethod(QHttpServerRequest::Method method)
{
    using Method = QHttpServerRequest::Method;
    return method == Method::Post || method == Method::Put ||
           method == Method::Patch || method == Method::Delete;
}

bool isJsonRequest(const PgsHttp::Request &request)
{
    const QString contentType = request.value("Content-Type").trimmed().toLower();
    return contentType.startsWith(QLatin1String("application/json"));
}

bool isSafeRegistryField(const QString &value)
{
    for (const QChar ch : value)
    {
        const uint code = static_cast<uint>(ch.unicode());
        if (ch == QLatin1Char(';') || code < 0x20 || code == 0x7f)
        {
            return false;
        }
    }
    return true;
}

QSslKey parsePrivateKey(const QByteArray &keyData)
{
    const QSsl::KeyAlgorithm algorithms[] = {QSsl::Rsa, QSsl::Ec, QSsl::Dsa};
    for (QSsl::KeyAlgorithm algorithm : algorithms)
    {
        QSslKey key(keyData, algorithm, QSsl::Pem);
        if (!key.isNull())
        {
            return key;
        }
    }
    return QSslKey();
}

bool normalizeNodeUrl(const QString &input, QString &outUrl)
{
    QUrl parsed(input.trimmed(), QUrl::StrictMode);
    if (!parsed.isValid() || parsed.scheme() != QLatin1String("https") || parsed.host().isEmpty())
    {
        return false;
    }
    if (!parsed.userInfo().isEmpty() || !parsed.query().isEmpty() || !parsed.fragment().isEmpty())
    {
        return false;
    }
    if (!parsed.path().isEmpty())
    {
        return false;
    }
    parsed.setPath(QString());
    outUrl = parsed.toString(QUrl::RemoveUserInfo | QUrl::RemoveQuery | QUrl::RemoveFragment);
    while (outUrl.endsWith(QLatin1Char('/')))
    {
        outUrl.chop(1);
    }
    return true;
}

int httpStatusCode(const QNetworkReply *reply)
{
    bool ok = false;
    const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt(&ok);
    return ok ? status : 0;
}

bool isHttpSuccess(int status)
{
    return status >= 200 && status < 300;
}

QString pollFailureMessage(const QString &path, const QNetworkReply *reply, int status)
{
    if (status > 0)
    {
        QString message = QStringLiteral("%1: HTTP status %2").arg(path).arg(status);
        const QString reason = reply->attribute(QNetworkRequest::HttpReasonPhraseAttribute).toString().trimmed();
        if (!reason.isEmpty())
        {
            message += QStringLiteral(" ") + reason;
        }
        const QString networkError = reply->errorString().trimmed();
        if (reply->error() != QNetworkReply::NoError && !networkError.isEmpty())
        {
            message += QStringLiteral(" (%1)").arg(networkError);
        }
        return message;
    }
    const QString networkError = reply->errorString().trimmed();
    if (reply->error() != QNetworkReply::NoError && !networkError.isEmpty())
    {
        return QStringLiteral("%1: %2").arg(path, networkError);
    }
    return QStringLiteral("%1: missing HTTP status").arg(path);
}

QString protectNodeCredentials(const QString &plain)
{
#ifdef Q_OS_WIN
    QByteArray utf8 = plain.toUtf8();
    DATA_BLOB in{};
    in.cbData = static_cast<DWORD>(utf8.size());
    in.pbData = reinterpret_cast<BYTE *>(utf8.data());
    DATA_BLOB out{};
    if (CryptProtectData(&in, L"PGS cluster node credentials", nullptr, nullptr, nullptr, 0, &out))
    {
        QByteArray protectedBytes(reinterpret_cast<const char *>(out.pbData), static_cast<int>(out.cbData));
        LocalFree(out.pbData);
        return QStringLiteral("dpapi:") + QString::fromLatin1(protectedBytes.toBase64());
    }
#endif
    return plain;
}

bool unprotectNodeCredentials(const QString &stored, QString &plain)
{
    if (!stored.startsWith(QStringLiteral("dpapi:")))
    {
        plain = stored;
        return true;
    }
#ifdef Q_OS_WIN
    const QByteArray encoded = stored.mid(6).toLatin1();
    const QByteArray protectedBytes = QByteArray::fromBase64(encoded);
    if (protectedBytes.isEmpty())
        return false;
    DATA_BLOB in{};
    in.cbData = static_cast<DWORD>(protectedBytes.size());
    in.pbData = reinterpret_cast<BYTE *>(const_cast<char *>(protectedBytes.constData()));
    DATA_BLOB out{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out))
        return false;
    QByteArray clear(reinterpret_cast<const char *>(out.pbData), static_cast<int>(out.cbData));
    LocalFree(out.pbData);
    plain = QString::fromUtf8(clear);
    return true;
#else
    Q_UNUSED(stored);
    Q_UNUSED(plain);
    return false;
#endif
}
}

ClusterServer::ClusterServer(QString nodesFile, QString listenAddress, quint16 listenPort,
                             QString apiToken, QString tlsCertPath, QString tlsKeyPath,
                             QString nodeCaCertPath, bool nodeInsecureTls, QObject *parent)
    : QObject(parent), m_nodesFile(std::move(nodesFile)), m_listenAddress(std::move(listenAddress)), m_listenPort(listenPort),
      m_apiToken(std::move(apiToken)), m_tlsCertPath(std::move(tlsCertPath)), m_tlsKeyPath(std::move(tlsKeyPath)),
      m_nodeCaCertPath(std::move(nodeCaCertPath)), m_nodeInsecureTls(nodeInsecureTls),
      m_server(new PgsHttp::Server(this)), m_nam(new QNetworkAccessManager(this))
{
    if (m_apiToken.isEmpty())
    {
        m_apiToken = generateApiToken();
        m_apiTokenGenerated = true;
    }
    // Node polling verifies HTTPS peers by default so Basic credentials are not
    // sent to an active MITM. Operators can add a private CA or explicitly opt
    // into insecure polling for lab-only/self-signed deployments.
    connect(&m_pollTimer, &QTimer::timeout, this, &ClusterServer::pollAll);
    m_pollTimer.start(5000); // 5s poll cadence; frontend reads cache at 1s
    loadNodes();
}

bool ClusterServer::start()
{
    using Method = QHttpServerRequest::Method;
    const bool trace = !qgetenv("PGS_WEB_TRACE").isEmpty();
    if (trace)
        QTextStream(stderr) << "PGS cluster start entered\n" << Qt::flush;
    const QHostAddress bindAddress = parseBindAddress(m_listenAddress);
    if (trace)
        QTextStream(stderr) << "PGS cluster parsed bind address " << bindAddress.toString() << "\n" << Qt::flush;
    if (bindAddress.isNull())
        return false;
    const bool remoteBind = !isLoopbackBindAddress(bindAddress);
    m_remoteBind = remoteBind;
    if (remoteBind && m_apiTokenGenerated)
        return false;
    if ((remoteBind || !m_tlsCertPath.trimmed().isEmpty() || !m_tlsKeyPath.trimmed().isEmpty()) && !setupTls())
        return false;
    if (!loadNodeCaCertificates())
        return false;

    // The dashboard uses the local SimpleHttp shim over QTcpServer/QSslServer.
    // This avoids QtHttpServer's Windows/minimal-runtime response stalls while
    // keeping the handler layer in terms of QHttpServerResponse values.
    QTcpServer *listener = nullptr;
    if (m_tlsEnabled)
    {
        listener = m_sslServer;
    }
    else
    {
        m_tcpServer = new QTcpServer(this);
        listener = m_tcpServer;
    }
    if (trace && listener)
    {
        QObject::connect(listener, &QTcpServer::newConnection, this, []() {
            QTextStream(stderr) << "PGS cluster listener newConnection\n" << Qt::flush;
        });
        QObject::connect(listener, &QTcpServer::acceptError, this, [](QAbstractSocket::SocketError error) {
            QTextStream(stderr) << "PGS cluster listener acceptError=" << static_cast<int>(error) << "\n" << Qt::flush;
        });
    }
    if (trace)
        QTextStream(stderr) << "PGS cluster listen begin port=" << m_listenPort << "\n" << Qt::flush;
    if (!listener || !listener->listen(bindAddress, m_listenPort))
        return false;
    if (trace)
        QTextStream(stderr) << "PGS cluster listen ok\n" << Qt::flush;
    if (trace)
        QTextStream(stderr) << "PGS cluster binding routes\n" << Qt::flush;
    if (!m_server->bind(listener, [this](const PgsHttp::Request &req) {
            using Method = QHttpServerRequest::Method;
            const QString path = req.url().path();
            if (path == QStringLiteral("/") && req.method() == Method::Get)
            {
                if (!qgetenv("PGS_WEB_TRACE").isEmpty())
                    QTextStream(stderr) << "PGS cluster route / entered\n";
                if (m_remoteBind)
                {
                    if (!isApiAuthorized(req))
                        return jsonUnauthorized();
                }
                else if (!localDashboardRequestAllowed(req, m_listenAddress, m_listenPort, m_tlsEnabled))
                {
                    return jsonUnauthorized();
                }
                return handleDashboard();
            }
            if (path == QStringLiteral("/api/cluster/summary") && req.method() == Method::Get)
            {
                if (!isApiAuthorized(req))
                    return jsonUnauthorized();
                return handleSummary();
            }
            if (path == QStringLiteral("/api/cluster/nodes") && req.method() == Method::Get)
            {
                if (!isApiAuthorized(req))
                    return jsonUnauthorized();
                return handleNodesList();
            }
            if (path == QStringLiteral("/api/cluster/nodes") && req.method() == Method::Post)
            {
                if (!isApiAuthorized(req))
                    return jsonUnauthorized();
                if (!isJsonRequest(req))
                    return jsonError(QStringLiteral("Content-Type must be application/json"), 415);
                return handleNodeAdd(req);
            }
            if (path == QStringLiteral("/api/cluster/nodes") && req.method() == Method::Put)
            {
                if (!isApiAuthorized(req))
                    return jsonUnauthorized();
                if (!isJsonRequest(req))
                    return jsonError(QStringLiteral("Content-Type must be application/json"), 415);
                return handleNodeUpdate(req);
            }
            if (path == QStringLiteral("/api/cluster/nodes/test") && req.method() == Method::Post)
            {
                if (!isApiAuthorized(req))
                    return jsonUnauthorized();
                if (!isJsonRequest(req))
                    return jsonError(QStringLiteral("Content-Type must be application/json"), 415);
                return handleNodeTest(req);
            }
            if (path == QStringLiteral("/api/cluster/nodes") && req.method() == Method::Delete)
            {
                if (!isApiAuthorized(req))
                    return jsonUnauthorized();
                if (!isJsonRequest(req))
                    return jsonError(QStringLiteral("Content-Type must be application/json"), 415);
                return handleNodeRemove(req);
            }
            return jsonError(QStringLiteral("not found"), 404);
        }))
    {
        listener->close();
        return false;
    }
    if (trace)
        QTextStream(stderr) << "PGS cluster start complete\n" << Qt::flush;
    return true;
}

QString ClusterServer::listenUrl() const
{
    return QStringLiteral("%1://%2:%3")
        .arg(m_tlsEnabled ? QStringLiteral("https") : QStringLiteral("http"),
             hostForUrl(m_listenAddress))
        .arg(m_listenPort);
}

bool ClusterServer::requiresApiToken() const
{
    return !m_apiToken.isEmpty();
}

bool ClusterServer::isApiAuthorized(const PgsHttp::Request &request) const
{
    if (isUnsafeMethod(request.method()) && !isJsonRequest(request))
        return false;
    if (!requiresApiToken())
        return true;

    const QString bearerPrefix = QStringLiteral("Bearer ");
    const QString authorization = request.value("Authorization").trimmed();
    if (authorization.startsWith(bearerPrefix, Qt::CaseInsensitive) && constantTimeEquals(authorization.mid(bearerPrefix.size()), m_apiToken))
        return true;

    const QString basicPrefix = QStringLiteral("Basic ");
    if (authorization.startsWith(basicPrefix, Qt::CaseInsensitive))
    {
        const QByteArray decoded = QByteArray::fromBase64(authorization.mid(basicPrefix.size()).toLatin1());
        const int colon = decoded.indexOf(':');
        if (colon >= 0 && constantTimeEquals(QString::fromUtf8(decoded.mid(colon + 1)), m_apiToken))
            return true;
    }

    const QString token = request.value("X-API-Token").trimmed();
    return !token.isEmpty() && constantTimeEquals(token, m_apiToken);
}

bool ClusterServer::setupTls()
{
    if (m_tlsCertPath.trimmed().isEmpty() || m_tlsKeyPath.trimmed().isEmpty())
        return false;

    QFile certFile(m_tlsCertPath);
    if (!certFile.open(QIODevice::ReadOnly))
        return false;
    const QList<QSslCertificate> certs = QSslCertificate::fromData(certFile.readAll(), QSsl::Pem);
    if (certs.isEmpty() || certs.first().isNull())
        return false;

    QFile keyFile(m_tlsKeyPath);
    if (!keyFile.open(QIODevice::ReadOnly))
        return false;
    const QSslKey key = parsePrivateKey(keyFile.readAll());
    if (key.isNull())
        return false;

    if (!m_sslServer)
        m_sslServer = new QSslServer(this);
    QSslConfiguration cfg = QSslConfiguration::defaultConfiguration();
    cfg.setLocalCertificate(certs.first());
    cfg.setPrivateKey(key);
    cfg.setPeerVerifyMode(QSslSocket::VerifyNone);
    m_sslServer->setSslConfiguration(cfg);
    m_tlsEnabled = true;
    return true;
}

bool ClusterServer::loadNodeCaCertificates()
{
    if (m_nodeInsecureTls && !m_nodeCaCertPath.trimmed().isEmpty())
        return false;
    if (m_nodeCaCertPath.trimmed().isEmpty())
        return true;

    QFile caFile(m_nodeCaCertPath);
    if (!caFile.open(QIODevice::ReadOnly))
        return false;
    const QList<QSslCertificate> certs = QSslCertificate::fromData(caFile.readAll(), QSsl::Pem);
    if (certs.isEmpty())
        return false;
    m_nodeCaCertificates = certs;
    return true;
}

// ---- Node registry persistence ----
// Format: name;baseHttpsUrl;dpapi:<protected user:pass> (legacy user:pass is read)
void ClusterServer::loadNodes()
{
    QFile f(m_nodesFile);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return;
    int lineNo = 0;
    while (!f.atEnd())
    {
        ++lineNo;
        const QByteArray line = f.readLine().trimmed();
        if (line.isEmpty() || line.startsWith('#'))
            continue;
        const QList<QByteArray> parts = line.split(';');
        if (parts.size() != 3)
            continue;
        Node n;
        n.name = QString::fromUtf8(parts[0]);
        QString normalizedUrl;
        if (!normalizeNodeUrl(QString::fromUtf8(parts[1]), normalizedUrl))
        {
            QTextStream(stderr) << "PGS cluster skipped node '" << n.name
                                << "' from " << m_nodesFile << ':' << lineNo
                                << ": url must be https://host[:port] without path, query, fragment, or embedded credentials\n";
            continue;
        }
        n.baseHttpsUrl = normalizedUrl;
        const QString storedCredentials = QString::fromUtf8(parts[2]);
        if (!unprotectNodeCredentials(storedCredentials, n.credentials))
        {
#ifdef Q_OS_WIN
            QTextStream(stderr) << "PGS cluster skipped node '" << n.name
                                << "' from " << m_nodesFile << ':' << lineNo
                                << ": failed to decrypt DPAPI credentials\n";
#else
            if (storedCredentials.startsWith(QStringLiteral("dpapi:")))
            {
                QTextStream(stderr) << "PGS cluster skipped node '" << n.name
                                    << "' from " << m_nodesFile << ':' << lineNo
                                    << ": DPAPI-protected credentials can only be decrypted on Windows; "
                                       "re-add this node on the current platform\n";
            }
            else
            {
                QTextStream(stderr) << "PGS cluster skipped node '" << n.name
                                    << "' from " << m_nodesFile << ':' << lineNo
                                    << ": failed to decode credentials\n";
            }
#endif
            continue;
        }
        if (!isSafeRegistryField(n.name) ||
            !isSafeRegistryField(n.baseHttpsUrl) ||
            !isSafeRegistryField(n.credentials))
        {
            continue;
        }
        n.generation = m_nextNodeGeneration++;
        if (!n.name.isEmpty())
            m_nodes.insert(n.name, n);
    }
}

void ClusterServer::saveNodes()
{
    QFile f(m_nodesFile);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate))
        return;
    QTextStream ts(&f);
    ts << "# PGS cluster node registry: name;baseHttpsUrl;dpapi:<protected user:pass>\n";
    for (const Node &n : m_nodes)
        ts << n.name << ';' << n.baseHttpsUrl << ';' << protectNodeCredentials(n.credentials) << '\n';
}

// ---- Polling ----
void ClusterServer::pollAll()
{
    for (const Node &n : m_nodes)
        pollNode(n);
}

void ClusterServer::pollNode(const Node &node)
{
    // Fire health + guards requests; update cache in the finished lambdas.
    enum class CacheField
    {
        Health,
        Guards
    };

    auto fetch = [this, node](const QString &path, CacheField field) {
        const quint64 serial = m_nextPollSerial++;
        const QUrl url(node.baseHttpsUrl + path);
        QNetworkRequest req(url);
        req.setRawHeader("Authorization", "Basic " + node.credentials.toUtf8().toBase64());
        QSslConfiguration cfg = req.sslConfiguration();
        if (m_nodeInsecureTls)
        {
            cfg.setPeerVerifyMode(QSslSocket::VerifyNone);
        }
        else
        {
            cfg.setPeerVerifyMode(QSslSocket::VerifyPeer);
            if (!m_nodeCaCertificates.isEmpty())
            {
                cfg.addCaCertificates(m_nodeCaCertificates);
            }
        }
        req.setSslConfiguration(cfg);
        QNetworkReply *reply = m_nam->get(req);
        connect(reply, &QNetworkReply::finished, this, [this, node, reply, field, path, serial]() {
            reply->deleteLater();
            auto current = m_nodes.constFind(node.name);
            if (current == m_nodes.constEnd() ||
                current->generation != node.generation ||
                current->baseHttpsUrl != node.baseHttpsUrl)
            {
                return;
            }

            NodeCache &cache = m_cache[node.name];
            if (cache.generation != node.generation)
            {
                cache = NodeCache{};
                cache.generation = node.generation;
            }
            quint64 &fieldSerial = (field == CacheField::Health) ? cache.healthSerial : cache.guardsSerial;
            if (serial < fieldSerial)
            {
                return;
            }
            fieldSerial = serial;
            const int status = httpStatusCode(reply);
            const bool reachable = reply->error() == QNetworkReply::NoError && isHttpSuccess(status);
            if (!reachable)
            {
                const QString error = pollFailureMessage(path, reply, status);
                if (field == CacheField::Health)
                {
                    cache.healthStatus = status;
                    cache.healthReachable = false;
                    cache.healthError = error;
                }
                else
                {
                    cache.guardsStatus = status;
                    cache.guardsReachable = false;
                    cache.guardsError = error;
                }
                cache.lastUpdatedMs = QDateTime::currentMSecsSinceEpoch();
                return;
            }
            const QString body = QString::fromUtf8(reply->readAll());
            if (field == CacheField::Health)
            {
                cache.healthStatus = status;
                cache.healthJson = body;
                cache.healthReachable = true;
                cache.healthError.clear();
            }
            else
            {
                cache.guardsStatus = status;
                cache.guardsJson = body;
                cache.guardsReachable = true;
                cache.guardsError.clear();
            }
            cache.lastUpdatedMs = QDateTime::currentMSecsSinceEpoch();
        });
    };

    fetch(QStringLiteral("/api/cluster/health"), CacheField::Health);
    fetch(QStringLiteral("/api/guards"), CacheField::Guards);
}

// ---- Handlers ----
QHttpServerResponse ClusterServer::handleNodesList() const
{
    QJsonArray arr;
    for (const Node &n : m_nodes)
    {
        QJsonObject o;
        o.insert("name", n.name);
        o.insert("url", n.baseHttpsUrl);
        arr.append(o);
    }
    QJsonObject obj;
    obj.insert("ok", true);
    obj.insert("nodes", arr);
    return QHttpServerResponse(obj);
}

QHttpServerResponse ClusterServer::handleNodeAdd(const PgsHttp::Request &request)
{
    const QJsonDocument doc = QJsonDocument::fromJson(request.body());
    if (!doc.isObject())
        return QHttpServerResponse(QJsonObject{{"ok", false}, {"error", "invalid JSON"}}, QHttpServerResponse::StatusCode::BadRequest);
    const QJsonObject o = doc.object();
    const QString name = o.value("name").toString().trimmed();
    const QString url = o.value("url").toString().trimmed();
    const QString creds = o.value("credentials").toString().trimmed();
    if (name.isEmpty() || url.isEmpty())
        return QHttpServerResponse(QJsonObject{{"ok", false}, {"error", "name and url required"}}, QHttpServerResponse::StatusCode::BadRequest);
    QString normalizedUrl;
    if (!normalizeNodeUrl(url, normalizedUrl))
        return QHttpServerResponse(QJsonObject{{"ok", false}, {"error", "url must be https://host[:port] without path, query, fragment, or embedded credentials"}}, QHttpServerResponse::StatusCode::BadRequest);
    if (!isSafeRegistryField(name) || !isSafeRegistryField(normalizedUrl) || !isSafeRegistryField(creds))
        return QHttpServerResponse(QJsonObject{{"ok", false}, {"error", "name, url, and credentials must not contain control characters or semicolons"}}, QHttpServerResponse::StatusCode::BadRequest);
    Node n;
    n.name = name;
    n.baseHttpsUrl = normalizedUrl;
    n.credentials = creds;
    n.generation = m_nextNodeGeneration++;
    m_nodes.insert(name, n);
    m_cache.remove(name);
    saveNodes();
    return QHttpServerResponse(QJsonObject{{"ok", true}, {"added", name}});
}

QHttpServerResponse ClusterServer::handleNodeUpdate(const PgsHttp::Request &request)
{
    const QJsonDocument doc = QJsonDocument::fromJson(request.body());
    if (!doc.isObject())
        return jsonError(QStringLiteral("invalid JSON"), 400);
    const QJsonObject o = doc.object();
    QString currentName = o.value("current_name").toString().trimmed();
    if (currentName.isEmpty())
        currentName = o.value("old_name").toString().trimmed();
    QString newName = o.value("name").toString().trimmed();
    if (newName.isEmpty())
        newName = currentName;
    const QString url = o.value("url").toString().trimmed();
    const QString creds = o.value("credentials").toString().trimmed();
    const bool replaceCredentials = o.contains("credentials") && !creds.isEmpty();
    const bool clearCredentials = o.value("clear_credentials").toBool(false);
    if (currentName.isEmpty() || newName.isEmpty() || url.isEmpty())
        return jsonError(QStringLiteral("current_name, name, and url required"), 400);
    const auto existing = m_nodes.constFind(currentName);
    if (existing == m_nodes.constEnd())
        return jsonError(QStringLiteral("node not found"), 404);
    QString normalizedUrl;
    if (!normalizeNodeUrl(url, normalizedUrl))
        return jsonError(QStringLiteral("url must be https://host[:port] without path, query, fragment, or embedded credentials"), 400);
    if (!isSafeRegistryField(newName) || !isSafeRegistryField(normalizedUrl) || !isSafeRegistryField(creds))
        return jsonError(QStringLiteral("name, url, and credentials must not contain control characters or semicolons"), 400);
    if (newName != currentName && m_nodes.contains(newName))
        return jsonError(QStringLiteral("node name already exists"), 409);

    Node n = existing.value();
    n.name = newName;
    n.baseHttpsUrl = normalizedUrl;
    if (clearCredentials)
        n.credentials.clear();
    else if (replaceCredentials)
        n.credentials = creds;
    n.generation = m_nextNodeGeneration++;

    m_nodes.remove(currentName);
    m_cache.remove(currentName);
    m_cache.remove(newName);
    m_nodes.insert(newName, n);
    saveNodes();
    pollNode(n);
    return QHttpServerResponse(QJsonObject{{"ok", true}, {"updated", newName}, {"url", normalizedUrl}});
}

QHttpServerResponse ClusterServer::handleNodeTest(const PgsHttp::Request &request)
{
    const QJsonDocument doc = QJsonDocument::fromJson(request.body());
    if (!doc.isObject())
        return jsonError(QStringLiteral("invalid JSON"), 400);
    const QJsonObject o = doc.object();
    const QString name = o.value("name").toString().trimmed();
    const auto existing = name.isEmpty() ? m_nodes.constEnd() : m_nodes.constFind(name);
    QString url = o.value("url").toString().trimmed();
    QString creds = o.value("credentials").toString().trimmed();
    if (url.isEmpty() && existing != m_nodes.constEnd())
        url = existing->baseHttpsUrl;
    if (creds.isEmpty() && existing != m_nodes.constEnd())
        creds = existing->credentials;
    if (url.isEmpty())
        return jsonError(QStringLiteral("url or known node name required"), 400);
    QString normalizedUrl;
    if (!normalizeNodeUrl(url, normalizedUrl))
        return jsonError(QStringLiteral("url must be https://host[:port] without path, query, fragment, or embedded credentials"), 400);
    if (!isSafeRegistryField(normalizedUrl) || !isSafeRegistryField(creds))
        return jsonError(QStringLiteral("url and credentials must not contain control characters or semicolons"), 400);

    QNetworkRequest req(QUrl(normalizedUrl + QStringLiteral("/api/cluster/health")));
    if (!creds.isEmpty())
        req.setRawHeader("Authorization", "Basic " + creds.toUtf8().toBase64());
    QSslConfiguration cfg = req.sslConfiguration();
    if (m_nodeInsecureTls)
    {
        cfg.setPeerVerifyMode(QSslSocket::VerifyNone);
    }
    else
    {
        cfg.setPeerVerifyMode(QSslSocket::VerifyPeer);
        if (!m_nodeCaCertificates.isEmpty())
            cfg.addCaCertificates(m_nodeCaCertificates);
    }
    req.setSslConfiguration(cfg);

    QEventLoop loop;
    QTimer timer;
    timer.setSingleShot(true);
    QNetworkReply *reply = m_nam->get(req);
    connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
    timer.start(5000);
    loop.exec();
    const bool timedOut = !reply->isFinished();
    if (timedOut)
        reply->abort();
    const int status = httpStatusCode(reply);
    const bool reachable = !timedOut && reply->error() == QNetworkReply::NoError && isHttpSuccess(status);
    const QString body = timedOut ? QString() : QString::fromUtf8(reply->readAll());
    QString error = timedOut ? QStringLiteral("request timed out") : pollFailureMessage(QStringLiteral("/api/cluster/health"), reply, status);
    if (reachable)
        error.clear();
    reply->deleteLater();

    QJsonObject obj;
    obj.insert("ok", true);
    obj.insert("reachable", reachable);
    obj.insert("status", status);
    obj.insert("url", normalizedUrl);
    if (!error.isEmpty())
        obj.insert("error", error);
    if (!body.isEmpty())
    {
        QJsonParseError pe;
        const QJsonDocument bodyDoc = QJsonDocument::fromJson(body.toUtf8(), &pe);
        if (pe.error == QJsonParseError::NoError && bodyDoc.isObject())
        {
            const QJsonObject health = bodyDoc.object();
            obj.insert("pgs_ok", health.value("pgs_ok").toBool(false));
            obj.insert("guard_count", health.value("guard_count").toInt(0));
            obj.insert("message", health.value("message").toString());
            obj.insert("listen_url", health.value("listen_url").toString());
        }
    }
    return QHttpServerResponse(obj);
}

QHttpServerResponse ClusterServer::handleNodeRemove(const PgsHttp::Request &request)
{
    const QJsonDocument doc = QJsonDocument::fromJson(request.body());
    if (!doc.isObject())
        return QHttpServerResponse(QJsonObject{{"ok", false}, {"error", "invalid JSON"}}, QHttpServerResponse::StatusCode::BadRequest);
    const QString name = doc.object().value("name").toString().trimmed();
    if (name.isEmpty())
        return QHttpServerResponse(QJsonObject{{"ok", false}, {"error", "name required"}}, QHttpServerResponse::StatusCode::BadRequest);
    if (!isSafeRegistryField(name))
        return QHttpServerResponse(QJsonObject{{"ok", false}, {"error", "invalid node name"}}, QHttpServerResponse::StatusCode::BadRequest);
    m_nodes.remove(name);
    m_cache.remove(name);
    saveNodes();
    return QHttpServerResponse(QJsonObject{{"ok", true}, {"removed", name}});
}

QHttpServerResponse ClusterServer::handleSummary() const
{
    QJsonArray nodes;
    int totalGuards = 0;
    int offlineCount = 0;
    int deadGuards = 0;
    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    for (auto it = m_nodes.constBegin(); it != m_nodes.constEnd(); ++it)
    {
        const NodeCache &c = m_cache.value(it.key());
        const bool reachable = c.generation == it.value().generation && c.healthReachable && c.guardsReachable;
        const bool currentCache = c.generation == it.value().generation;
        const qint64 lastUpdatedMs = currentCache ? c.lastUpdatedMs : 0;
        QString lastError;
        if (!c.healthError.isEmpty())
            lastError = c.healthError;
        if (!c.guardsError.isEmpty())
            lastError = lastError.isEmpty() ? c.guardsError : lastError + QStringLiteral("; ") + c.guardsError;
        QJsonObject o;
        o.insert("name", it.key());
        o.insert("url", it.value().baseHttpsUrl);
        o.insert("reachable", reachable);
        o.insert("health_status", c.healthStatus);
        o.insert("guards_status", c.guardsStatus);
        o.insert("last_error", lastError);
        o.insert("last_updated_ms", static_cast<double>(lastUpdatedMs));
        o.insert("poll_age_ms", static_cast<double>(lastUpdatedMs > 0 ? nowMs - lastUpdatedMs : -1));

        int guardCount = 0;
        if (c.healthReachable && !c.healthJson.isEmpty())
        {
            QJsonParseError pe;
            const QJsonDocument hd = QJsonDocument::fromJson(c.healthJson.toUtf8(), &pe);
            if (pe.error == QJsonParseError::NoError && hd.isObject())
            {
                const QJsonObject health = hd.object();
                guardCount = health.value("guard_count").toInt(0);
                o.insert("pgs_ok", health.value("pgs_ok").toBool(false));
                o.insert("health_message", health.value("message").toString());
                o.insert("node_listen_url", health.value("listen_url").toString());
            }
        }
        if (!reachable)
            ++offlineCount;

        // Count dead guards from the guards JSON.
        QJsonArray guardRows;
        int nodeDeadGuards = 0;
        if (c.guardsReachable && !c.guardsJson.isEmpty())
        {
            QJsonParseError pe;
            const QJsonDocument gd = QJsonDocument::fromJson(c.guardsJson.toUtf8(), &pe);
            if (pe.error == QJsonParseError::NoError && gd.isObject())
            {
                const QJsonArray gs = gd.object().value("guards").toArray();
                for (const QJsonValue &gv : gs)
                {
                    const QJsonObject guard = gv.toObject();
                    const QString alive = guard.value("alive").toString();
                    if (alive != "1" && alive.compare("true", Qt::CaseInsensitive) != 0)
                    {
                        ++deadGuards;
                        ++nodeDeadGuards;
                    }
                    QJsonObject row;
                    row.insert("pid", guard.value("pid").toString());
                    row.insert("path", guard.value("path").toString());
                    row.insert("status", guard.value("status").toString());
                    row.insert("quarantined", guard.value("quarantined").toString());
                    row.insert("health_status", guard.value("health_status").toString());
                    row.insert("last_failure_code", guard.value("last_failure_code").toString());
                    row.insert("restart_count", guard.value("restart_count").toString());
                    row.insert("max_restarts", guard.value("max_restarts").toString());
                    row.insert("alive", alive);
                    row.insert("session", guard.value("session").toString());
                    row.insert("app_kind", guard.value("app_kind").toString());
                    row.insert("aumid", guard.value("aumid").toString());
                    row.insert("restart_window", guard.value("restart_window").toString());
                    row.insert("restart_delay", guard.value("restart_delay").toString());
                    row.insert("backoff", guard.value("backoff").toString());
                    row.insert("hang_timeout", guard.value("hang_timeout").toString());
                    row.insert("kill_on_exit", guard.value("kill_on_exit").toString());
                    guardRows.append(row);
                }
                if (guardCount == 0)
                    guardCount = guardRows.size();
            }
        }
        o.insert("guard_count", guardCount);
        o.insert("dead_guard_count", nodeDeadGuards);
        o.insert("guards", guardRows);
        totalGuards += guardCount;
        nodes.append(o);
    }
    QJsonObject obj;
    obj.insert("ok", true);
    obj.insert("node_count", m_nodes.size());
    obj.insert("offline_count", offlineCount);
    obj.insert("total_guards", totalGuards);
    obj.insert("dead_guards", deadGuards);
    obj.insert("nodes", nodes);
    return QHttpServerResponse(obj);
}

QHttpServerResponse ClusterServer::handleDashboard() const
{
    static const char *html = R"HTML(<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>PGS Cluster Dashboard</title>
<style>
body{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#0f1115;color:#d6dbe2;margin:0;padding:20px}
h1{font-size:20px;margin:0 0 12px}
.summary{display:flex;gap:16px;margin-bottom:16px;flex-wrap:wrap}
.card{background:#1e2024;border:1px solid #3a3f47;border-radius:8px;padding:14px 18px;min-width:120px}
.card .v{font-size:24px;font-weight:700}
.card .l{font-size:12px;color:#9aa3b0;margin-top:4px}
.bad{color:#d43a3a}.ok{color:#3cc66a}.warn{color:#d9a410}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px}
.node{background:#25282e;border:1px solid #3a3f47;border-radius:8px;padding:14px;cursor:pointer}
.node.offline{border-color:#d43a3a}
.node.selected{border-color:#3b6fd8;box-shadow:0 0 0 1px #3b6fd8}
.node h3{margin:0 0 8px;font-size:15px}
.node .meta{font-size:12px;color:#9aa3b0;margin-top:6px}
.tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;margin-right:6px}
.tag.up{background:#1f3d28;color:#3cc66a}.tag.down{background:#3d1f1f;color:#d43a3a}
.node-actions{display:flex;gap:8px;margin-top:12px;flex-wrap:wrap}
button,.button-link{background:#3b6fd8;color:#fff;border:none;border-radius:4px;padding:6px 12px;cursor:pointer;margin-right:8px;text-decoration:none;font:inherit}
button.remove{background:#7f2d2d}
input{background:#2b2f36;border:1px solid #444a54;color:#e6e9ef;border-radius:4px;padding:5px 8px;margin-right:6px}
label{font-size:12px;color:#9aa3b0;margin-right:8px}.edit-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin:12px 0}.edit-grid input{width:100%;box-sizing:border-box;margin:4px 0 0}.edit-actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:10px}.edit-status{font-size:12px;color:#9aa3b0;min-height:18px}
.detail{margin-top:18px;background:#1b1e24;border:1px solid #3a3f47;border-radius:8px;padding:16px}
.detail h2{font-size:16px;margin:0 0 10px}
.detail-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin:10px 0}
.detail-item{background:#25282e;border:1px solid #343944;border-radius:6px;padding:10px}
.detail-item .k{font-size:11px;color:#9aa3b0;text-transform:uppercase}.detail-item .v{margin-top:4px;word-break:break-all}
.guard-table{width:100%;border-collapse:collapse;margin-top:12px;font-size:12px}
.guard-table th,.guard-table td{border-bottom:1px solid #343944;padding:7px 8px;text-align:left;vertical-align:top}
.guard-table th{color:#9aa3b0;font-weight:600}
.empty{color:#9aa3b0}
</style></head><body>
<h1>PGS Cluster Dashboard</h1>
<div class="summary" id="summary"></div>
<div style="margin:16px 0">
<input id="nname" placeholder="node name">
<input id="nurl" placeholder="https://host:12443">
<input id="ncreds" type="password" autocomplete="off" placeholder="user:pass">
<input id="apiToken" type="password" autocomplete="off" placeholder="API token">
<button id="addNode">Add Node</button>
</div>
<div class="grid" id="grid"></div>
<section class="detail" id="detail"></section>
<script>
function fmt(s){return s===0?'0':(s||'--');}
function fmtAge(ms){
  if(ms===undefined||ms===null||Number(ms)<0)return 'never';
  const total=Math.floor(Number(ms)/1000);
  if(total<2)return 'just now';
  if(total<60)return total+'s ago';
  const mins=Math.floor(total/60);
  if(mins<60)return mins+'m ago';
  const hours=Math.floor(mins/60);
  if(hours<24)return hours+'h ago';
  return Math.floor(hours/24)+'d ago';
}
const tokenInput=document.getElementById('apiToken');
const detail=document.getElementById('detail');
const embeddedApiToken='__PGS_CLUSTER_API_TOKEN__';
let latestNodes=[];
let selectedNodeName='';
try{localStorage.removeItem('pgsClusterApiToken')}catch(e){}
tokenInput.value=sessionStorage.getItem('pgsClusterApiToken')||embeddedApiToken;
tokenInput.addEventListener('input',()=>sessionStorage.setItem('pgsClusterApiToken',tokenInput.value));
document.getElementById('addNode').addEventListener('click',addNode);
function apiHeaders(extra){
  const headers=Object.assign({},extra||{});
  const token=tokenInput.value.trim();
  if(token)headers['X-API-Token']=token;
  return headers;
}
function el(tag,cls,text){
  const node=document.createElement(tag);
  if(cls)node.className=cls;
  if(text!==undefined)node.textContent=String(text);
  return node;
}
function metric(value,label,cls){
  const card=el('div','card');
  card.appendChild(el('div','v'+(cls?' '+cls:''),value));
  card.appendChild(el('div','l',label));
  return card;
}
function detailItem(label,value,cls){
  const item=el('div','detail-item');
  item.appendChild(el('div','k',label));
  item.appendChild(el('div','v'+(cls?' '+cls:''),fmt(value)));
  return item;
}
function labeledInput(id,label,value,type){
  const wrap=document.createElement('label');
  wrap.textContent=label;
  const input=document.createElement('input');
  input.id=id;input.type=type||'text';input.value=value||'';input.autocomplete='off';
  wrap.appendChild(input);
  return wrap;
}
function appendCell(row,value,cls){
  const cell=document.createElement('td');
  if(cls)cell.className=cls;
  cell.textContent=fmt(value);
  row.appendChild(cell);
}
function selectNode(name){
  selectedNodeName=name;
  renderCards(latestNodes);
  renderDetail();
}
function selectedNode(){
  return latestNodes.find(n=>n.name===selectedNodeName)||latestNodes[0]||null;
}
async function refresh(){
  const s=document.getElementById('summary');
  const g=document.getElementById('grid');
  const r=await fetch('/api/cluster/summary',{headers:apiHeaders()});
  if(!r.ok){
    s.replaceChildren(metric(r.status,'API Error','bad'));
    g.replaceChildren(el('div','node offline',r.status===401?'unauthorized':'request failed'));
    detail.replaceChildren(el('div','empty','No node details available.'));
    return;
  }
  const j=await r.json();
  s.replaceChildren(
    metric(j.node_count,'Nodes'),
    metric(j.offline_count,'Offline',j.offline_count?'bad':'ok'),
    metric(j.total_guards,'Guards'),
    metric(j.dead_guards,'Dead Guards',j.dead_guards?'bad':'ok'));
  latestNodes=Array.isArray(j.nodes)?j.nodes:[];
  if(selectedNodeName&&!latestNodes.some(n=>n.name===selectedNodeName))selectedNodeName='';
  if(!selectedNodeName&&latestNodes.length)selectedNodeName=latestNodes[0].name;
  renderCards(latestNodes);
  renderDetail();
}
function renderCards(nodes){
  const g=document.getElementById('grid');
  g.replaceChildren();
  nodes.forEach(n=>{
    const d=document.createElement('div');
    d.className='node'+(n.reachable?'':' offline')+(n.name===selectedNodeName?' selected':'');
    d.addEventListener('click',()=>selectNode(n.name));
    const title=el('h3');
    title.appendChild(document.createTextNode(fmt(n.name)+' '));
    title.appendChild(el('span','tag '+(n.reachable?'up':'down'),n.reachable?'UP':'DOWN'));
    d.appendChild(title);
    d.appendChild(el('div','',fmt(n.guard_count)+' guard(s)'));
    if(n.dead_guard_count){
      d.appendChild(el('div','warn',fmt(n.dead_guard_count)+' dead guard(s)'));
    }
    const meta=el('div','meta');
    meta.appendChild(document.createTextNode(fmt(n.url)));
    meta.appendChild(document.createElement('br'));
    meta.appendChild(document.createTextNode('last poll: '+fmtAge(n.poll_age_ms)));
    if(n.health_status||n.guards_status){
      meta.appendChild(document.createElement('br'));
      meta.appendChild(document.createTextNode('status: health '+fmt(n.health_status||'--')+', guards '+fmt(n.guards_status||'--')));
    }
    if(!n.reachable){
      meta.appendChild(document.createElement('br'));
      meta.appendChild(document.createTextNode('error: '+fmt(n.last_error)));
    }
    d.appendChild(meta);
    const actions=el('div','node-actions');
    const open=document.createElement('a');
    open.className='button-link';
    open.href=n.url;
    open.target='_blank';
    open.rel='noopener';
    open.textContent='Open Node';
    open.addEventListener('click',ev=>ev.stopPropagation());
    actions.appendChild(open);
    const remove=el('button','remove','Remove');
    remove.addEventListener('click',ev=>{ev.stopPropagation();removeNode(n.name);});
    actions.appendChild(remove);
    d.appendChild(actions);
    g.appendChild(d);
  });
}
function renderDetail(){
  const n=selectedNode();
  if(!n){
    detail.replaceChildren(el('div','empty','No nodes registered.'));
    return;
  }
  const title=el('h2',null,fmt(n.name));
  const open=document.createElement('a');
  open.className='button-link';
  open.href=n.url;
  open.target='_blank';
  open.rel='noopener';
  open.textContent='Open Node';
  const status=n.reachable?'UP':'DOWN';
  const grid=el('div','detail-grid');
  grid.appendChild(detailItem('URL',n.url));
  grid.appendChild(detailItem('Status',status,n.reachable?'ok':'bad'));
  grid.appendChild(detailItem('Last Poll',fmtAge(n.poll_age_ms)));
  grid.appendChild(detailItem('HTTP',`health ${fmt(n.health_status||'--')} / guards ${fmt(n.guards_status||'--')}`));
  grid.appendChild(detailItem('PGS',n.pgs_ok===true?'ok':(n.pgs_ok===false?'not ok':'unknown'),n.pgs_ok===true?'ok':(n.pgs_ok===false?'bad':'')));
  grid.appendChild(detailItem('Message',n.last_error||n.health_message||'--',n.last_error?'bad':''));
  const edit=el('div','edit-grid');
  edit.appendChild(labeledInput('edit-name','Name',n.name));
  edit.appendChild(labeledInput('edit-url','URL',n.url));
  edit.appendChild(labeledInput('edit-creds','Credentials','', 'password'));
  const clearWrap=document.createElement('label');
  const clearBox=document.createElement('input');
  clearBox.id='edit-clear-creds';clearBox.type='checkbox';
  clearWrap.appendChild(clearBox);clearWrap.appendChild(document.createTextNode(' Clear credentials'));edit.appendChild(clearWrap);
  const editActions=el('div','edit-actions');
  const save=el('button',null,'Save Node');save.addEventListener('click',saveSelectedNode);
  const test=el('button',null,'Test Node');test.addEventListener('click',testSelectedNode);
  const editStatus=el('div','edit-status');editStatus.id='edit-status';
  editActions.append(save,test,editStatus);
  const parts=[title,open,grid,edit,editActions];
  const guards=Array.isArray(n.guards)?n.guards:[];
  if(guards.length){
    const table=document.createElement('table');
    table.className='guard-table';
    const head=document.createElement('thead');
    const hr=document.createElement('tr');
    ['PID','Alive','Status','Health','Failure','Restarts','Max','Session','App','Window','Delay','Backoff','Hang','Kill','Path'].forEach(h=>{const th=document.createElement('th');th.textContent=h;hr.appendChild(th);});
    head.appendChild(hr);
    table.appendChild(head);
    const body=document.createElement('tbody');
    guards.forEach(g=>{
      const row=document.createElement('tr');
      const alive=String(g.alive||'');
      const dead=alive!=='1'&&alive.toLowerCase()!=='true';
      appendCell(row,g.pid);
      appendCell(row,g.alive,dead?'bad':'ok');
      appendCell(row,g.status||g.quarantined);
      appendCell(row,g.health_status);
      appendCell(row,g.last_failure_code,g.last_failure_code?'warn':'');
      appendCell(row,g.restart_count);
      appendCell(row,g.max_restarts);
      appendCell(row,g.session);
      appendCell(row,g.app_kind);
      appendCell(row,g.restart_window);
      appendCell(row,g.restart_delay);
      appendCell(row,g.backoff);
      appendCell(row,g.hang_timeout);
      appendCell(row,g.kill_on_exit);
      appendCell(row,g.path);
      body.appendChild(row);
    });
    table.appendChild(body);
    parts.push(table);
  }else{
    parts.push(el('div','empty','No guard rows in the latest poll.'));
  }
  detail.replaceChildren(...parts);
}
async function addNode(){
  const name=document.getElementById('nname').value.trim();
  const url=document.getElementById('nurl').value.trim();
  const creds=document.getElementById('ncreds').value.trim();
  if(!name||!url)return;
  await fetch('/api/cluster/nodes',{method:'POST',headers:apiHeaders({'Content-Type':'application/json'}),
    body:JSON.stringify({name,url,credentials:creds})});
  document.getElementById('nname').value='';document.getElementById('nurl').value='';document.getElementById('ncreds').value='';
  refresh();
}
function currentEditPayload(){
  const n=selectedNode();
  return {current_name:n?n.name:'',name:document.getElementById('edit-name')?.value.trim()||'',url:document.getElementById('edit-url')?.value.trim()||'',credentials:document.getElementById('edit-creds')?.value.trim()||'',clear_credentials:!!document.getElementById('edit-clear-creds')?.checked};
}
function setEditStatus(text,cls){
  const node=document.getElementById('edit-status');if(!node)return;node.className='edit-status'+(cls?' '+cls:'');node.textContent=text;
}
async function saveSelectedNode(){
  const body=currentEditPayload();
  if(!body.current_name||!body.name||!body.url)return;
  setEditStatus('saving...');
  const r=await fetch('/api/cluster/nodes',{method:'PUT',headers:apiHeaders({'Content-Type':'application/json'}),body:JSON.stringify(body)});
  const j=await r.json().catch(()=>({error:'invalid response'}));
  if(!r.ok||j.ok===false){setEditStatus('save failed: '+(j.error||r.status),'bad');return;}
  selectedNodeName=j.updated||body.name;setEditStatus('saved','ok');refresh();
}
async function testSelectedNode(){
  const body=currentEditPayload();
  setEditStatus('testing...');
  const r=await fetch('/api/cluster/nodes/test',{method:'POST',headers:apiHeaders({'Content-Type':'application/json'}),body:JSON.stringify({name:body.current_name,url:body.url,credentials:body.credentials})});
  const j=await r.json().catch(()=>({error:'invalid response'}));
  if(!r.ok||j.ok===false){setEditStatus('test failed: '+(j.error||r.status),'bad');return;}
  setEditStatus(j.reachable?`reachable: ${j.message||'ok'}`:`unreachable: ${j.error||j.status}`,j.reachable?'ok':'bad');
}
async function removeNode(name){
  if(!confirm(`Remove node "${name}" from this dashboard?`))return;
  const r=await fetch('/api/cluster/nodes',{method:'DELETE',headers:apiHeaders({'Content-Type':'application/json'}),
    body:JSON.stringify({name})});
  if(!r.ok){
    alert('Remove failed: '+r.status);
    return;
  }
  if(selectedNodeName===name)selectedNodeName='';
  refresh();
}
refresh();setInterval(refresh,1000);
</script></body></html>)HTML";
    QByteArray body(html);
    body.replace("__PGS_CLUSTER_API_TOKEN__", m_apiTokenGenerated ? m_apiToken.toUtf8() : QByteArray());
    return hardenHtmlResponse(QHttpServerResponse(QByteArray("text/html; charset=utf-8"), body));
}
