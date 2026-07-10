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

#include <QByteArray>
#include <QDateTime>
#include <QFile>
#include <QHostAddress>
#include <QHttpServer>
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
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslKey>
#include <QSslServer>
#include <QSslSocket>
#include <QTextStream>
#include <QTcpServer>
#include <QUrl>
#include <utility>

namespace
{
QHttpServerResponse jsonError(const QString &message, int statusCode)
{
    QJsonObject obj;
    obj.insert("ok", false);
    obj.insert("error", message);
    return QHttpServerResponse(obj, static_cast<QHttpServerResponse::StatusCode>(statusCode));
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

bool isJsonRequest(const QHttpServerRequest &request)
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
    QString path = parsed.path();
    while (path.endsWith(QLatin1Char('/')) && path.size() > 1)
    {
        path.chop(1);
    }
    if (path == QLatin1String("/"))
    {
        path.clear();
    }
    parsed.setPath(path);
    outUrl = parsed.toString(QUrl::RemoveUserInfo | QUrl::RemoveQuery | QUrl::RemoveFragment);
    while (outUrl.endsWith(QLatin1Char('/')))
    {
        outUrl.chop(1);
    }
    return true;
}
}

ClusterServer::ClusterServer(QString nodesFile, QString listenAddress, quint16 listenPort,
                             QString apiToken, QString tlsCertPath, QString tlsKeyPath,
                             QString nodeCaCertPath, bool nodeInsecureTls, QObject *parent)
    : QObject(parent), m_nodesFile(std::move(nodesFile)), m_listenAddress(std::move(listenAddress)), m_listenPort(listenPort),
      m_apiToken(std::move(apiToken)), m_tlsCertPath(std::move(tlsCertPath)), m_tlsKeyPath(std::move(tlsKeyPath)),
      m_nodeCaCertPath(std::move(nodeCaCertPath)), m_nodeInsecureTls(nodeInsecureTls),
      m_server(new QHttpServer(this)), m_nam(new QNetworkAccessManager(this))
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
    const QHostAddress bindAddress = parseBindAddress(m_listenAddress);
    if (bindAddress.isNull())
        return false;
    const bool remoteBind = !isLoopbackBindAddress(bindAddress);
    if (remoteBind && m_apiTokenGenerated)
        return false;
    if ((remoteBind || !m_tlsCertPath.trimmed().isEmpty() || !m_tlsKeyPath.trimmed().isEmpty()) && !setupTls())
        return false;
    if (!loadNodeCaCertificates())
        return false;

    m_server->route("/", Method::Get, this, [this]() { return handleDashboard(); });
    m_server->route("/api/cluster/summary", Method::Get, this, [this](const QHttpServerRequest &req) {
        if (!isApiAuthorized(req))
            return jsonError(QStringLiteral("unauthorized"), 401);
        return handleSummary();
    });
    m_server->route("/api/cluster/nodes", Method::Get, this, [this](const QHttpServerRequest &req) {
        if (!isApiAuthorized(req))
            return jsonError(QStringLiteral("unauthorized"), 401);
        return handleNodesList();
    });
    m_server->route("/api/cluster/nodes", Method::Post, this, [this](const QHttpServerRequest &req) {
        if (!isApiAuthorized(req))
            return jsonError(QStringLiteral("unauthorized"), 401);
        if (!isJsonRequest(req))
            return jsonError(QStringLiteral("Content-Type must be application/json"), 415);
        return handleNodeAdd(req);
    });
    m_server->route("/api/cluster/nodes", Method::Delete, this, [this](const QHttpServerRequest &req) {
        if (!isApiAuthorized(req))
            return jsonError(QStringLiteral("unauthorized"), 401);
        if (!isJsonRequest(req))
            return jsonError(QStringLiteral("Content-Type must be application/json"), 415);
        return handleNodeRemove(req);
    });
    // QHttpServer uses QTcpServer/QSslServer + bind (same pattern as pgs_admin_web).
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
    if (!listener || !listener->listen(bindAddress, m_listenPort))
        return false;
    if (!m_server->bind(listener))
    {
        listener->close();
        return false;
    }
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

bool ClusterServer::isApiAuthorized(const QHttpServerRequest &request) const
{
    if (isUnsafeMethod(request.method()) && !isJsonRequest(request))
        return false;
    if (!requiresApiToken())
        return true;

    const QString bearerPrefix = QStringLiteral("Bearer ");
    const QString authorization = request.value("Authorization").trimmed();
    if (authorization.startsWith(bearerPrefix) && constantTimeEquals(authorization.mid(bearerPrefix.size()), m_apiToken))
        return true;

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
// Format: name;baseHttpsUrl;user:pass
void ClusterServer::loadNodes()
{
    QFile f(m_nodesFile);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return;
    while (!f.atEnd())
    {
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
            continue;
        n.baseHttpsUrl = normalizedUrl;
        n.credentials = QString::fromUtf8(parts[2]);
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
    ts << "# PGS cluster node registry: name;baseHttpsUrl;user:pass\n";
    for (const Node &n : m_nodes)
        ts << n.name << ';' << n.baseHttpsUrl << ';' << n.credentials << '\n';
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
            if (reply->error() != QNetworkReply::NoError)
            {
                if (field == CacheField::Health)
                {
                    cache.healthReachable = false;
                    cache.healthError = QStringLiteral("%1: %2").arg(path, reply->errorString());
                }
                else
                {
                    cache.guardsReachable = false;
                    cache.guardsError = QStringLiteral("%1: %2").arg(path, reply->errorString());
                }
                cache.lastUpdatedMs = QDateTime::currentMSecsSinceEpoch();
                return;
            }
            const QString body = QString::fromUtf8(reply->readAll());
            if (field == CacheField::Health)
            {
                cache.healthJson = body;
                cache.healthReachable = true;
                cache.healthError.clear();
            }
            else
            {
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

QHttpServerResponse ClusterServer::handleNodeAdd(const QHttpServerRequest &request)
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
        return QHttpServerResponse(QJsonObject{{"ok", false}, {"error", "url must be https://host[:port] without embedded credentials"}}, QHttpServerResponse::StatusCode::BadRequest);
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

QHttpServerResponse ClusterServer::handleNodeRemove(const QHttpServerRequest &request)
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
    for (auto it = m_nodes.constBegin(); it != m_nodes.constEnd(); ++it)
    {
        const NodeCache &c = m_cache.value(it.key());
        const bool reachable = c.generation == it.value().generation && c.healthReachable && c.guardsReachable;
        QString lastError;
        if (!c.healthError.isEmpty())
            lastError = c.healthError;
        if (!c.guardsError.isEmpty())
            lastError = lastError.isEmpty() ? c.guardsError : lastError + QStringLiteral("; ") + c.guardsError;
        QJsonObject o;
        o.insert("name", it.key());
        o.insert("url", it.value().baseHttpsUrl);
        o.insert("reachable", reachable);
        o.insert("last_error", lastError);

        int guardCount = 0;
        if (c.healthReachable && !c.healthJson.isEmpty())
        {
            QJsonParseError pe;
            const QJsonDocument hd = QJsonDocument::fromJson(c.healthJson.toUtf8(), &pe);
            if (pe.error == QJsonParseError::NoError && hd.isObject())
                guardCount = hd.object().value("guard_count").toInt(0);
        }
        if (!reachable)
            ++offlineCount;
        o.insert("guard_count", guardCount);
        totalGuards += guardCount;

        // Count dead guards from the guards JSON.
        if (c.guardsReachable && !c.guardsJson.isEmpty())
        {
            QJsonParseError pe;
            const QJsonDocument gd = QJsonDocument::fromJson(c.guardsJson.toUtf8(), &pe);
            if (pe.error == QJsonParseError::NoError && gd.isObject())
            {
                const QJsonArray gs = gd.object().value("guards").toArray();
                for (const QJsonValue &gv : gs)
                {
                    const QString alive = gv.toObject().value("alive").toString();
                    if (alive != "1" && alive.compare("true", Qt::CaseInsensitive) != 0)
                        ++deadGuards;
                }
            }
        }
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
.summary{display:flex;gap:16px;margin-bottom:16px}
.card{background:#1e2024;border:1px solid #3a3f47;border-radius:8px;padding:14px 18px;min-width:120px}
.card .v{font-size:24px;font-weight:700}
.card .l{font-size:12px;color:#9aa3b0;margin-top:4px}
.bad{color:#d43a3a}.ok{color:#3cc66a}.warn{color#d9a410}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px}
.node{background:#25282e;border:1px solid #3a3f47;border-radius:8px;padding:14px}
.node.offline{border-color:#d43a3a}
.node h3{margin:0 0 8px;font-size:15px}
.node .meta{font-size:12px;color:#9aa3b0;margin-top:6px}
.tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;margin-right:6px}
.tag.up{background:#1f3d28;color:#3cc66a}.tag.down{background:#3d1f1f;color:#d43a3a}
button{background:#3b6fd8;color:#fff;border:none;border-radius:4px;padding:6px 12px;cursor:pointer;margin-right:8px}
input{background:#2b2f36;border:1px solid #444a54;color:#e6e9ef;border-radius:4px;padding:5px 8px;margin-right:6px}
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
<script>
function fmt(s){return s||'--';}
const tokenInput=document.getElementById('apiToken');
const embeddedApiToken='__PGS_CLUSTER_API_TOKEN__';
tokenInput.value=localStorage.getItem('pgsClusterApiToken')||embeddedApiToken;
tokenInput.addEventListener('input',()=>localStorage.setItem('pgsClusterApiToken',tokenInput.value));
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
async function refresh(){
  const s=document.getElementById('summary');
  const g=document.getElementById('grid');
  const r=await fetch('/api/cluster/summary',{headers:apiHeaders()});
  if(!r.ok){
    s.replaceChildren(metric(r.status,'API Error','bad'));
    g.replaceChildren(el('div','node offline',r.status===401?'unauthorized':'request failed'));
    return;
  }
  const j=await r.json();
  s.replaceChildren(
    metric(j.node_count,'Nodes'),
    metric(j.offline_count,'Offline',j.offline_count?'bad':'ok'),
    metric(j.total_guards,'Guards'),
    metric(j.dead_guards,'Dead Guards',j.dead_guards?'bad':'ok'));
  g.replaceChildren();
  (j.nodes||[]).forEach(n=>{
    const d=document.createElement('div');
    d.className='node'+(n.reachable?'':' offline');
    const title=el('h3');
    title.appendChild(document.createTextNode(fmt(n.name)+' '));
    title.appendChild(el('span','tag '+(n.reachable?'up':'down'),n.reachable?'UP':'DOWN'));
    d.appendChild(title);
    d.appendChild(el('div','',fmt(n.guard_count)+' guard(s)'));
    const meta=el('div','meta');
    meta.appendChild(document.createTextNode(fmt(n.url)));
    if(!n.reachable){
      meta.appendChild(document.createElement('br'));
      meta.appendChild(document.createTextNode('error: '+fmt(n.last_error)));
    }
    d.appendChild(meta);
    const remove=el('button','remove','Remove');
    remove.addEventListener('click',()=>removeNode(n.name));
    d.appendChild(remove);
    g.appendChild(d);
  });
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
async function removeNode(name){
  await fetch('/api/cluster/nodes',{method:'DELETE',headers:apiHeaders({'Content-Type':'application/json'}),
    body:JSON.stringify({name})});
  refresh();
}
refresh();setInterval(refresh,1000);
</script></body></html>)HTML";
    QByteArray body(html);
    body.replace("__PGS_CLUSTER_API_TOKEN__", m_apiTokenGenerated ? m_apiToken.toUtf8() : QByteArray());
    return QHttpServerResponse(QByteArray("text/html; charset=utf-8"), body);
}
