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
#include <QSslConfiguration>
#include <QTextStream>
#include <QTcpServer>
#include <QUrl>

ClusterServer::ClusterServer(QString nodesFile, quint16 listenPort, QObject *parent)
    : QObject(parent), m_nodesFile(std::move(nodesFile)), m_listenPort(listenPort),
      m_server(new QHttpServer(this)), m_nam(new QNetworkAccessManager(this))
{
    // The cluster dashboard trusts the operator's nodes (self-signed certs are
    // expected for a first-run PPL gateway). This is acceptable because the
    // dashboard runs on the operator's machine and credentials are per-node.
    connect(&m_pollTimer, &QTimer::timeout, this, &ClusterServer::pollAll);
    m_pollTimer.start(5000); // 5s poll cadence; frontend reads cache at 1s
    loadNodes();
}

bool ClusterServer::start()
{
    using Method = QHttpServerRequest::Method;
    m_server->route("/", Method::Get, this, [this]() { return handleDashboard(); });
    m_server->route("/api/cluster/summary", Method::Get, this, [this]() { return handleSummary(); });
    m_server->route("/api/cluster/nodes", Method::Get, this, [this]() { return handleNodesList(); });
    m_server->route("/api/cluster/nodes", Method::Post, this, [this](const QHttpServerRequest &req) { return handleNodeAdd(req); });
    m_server->route("/api/cluster/nodes", Method::Delete, this, [this](const QHttpServerRequest &req) { return handleNodeRemove(req); });
    // QHttpServer uses QTcpServer + bind (same pattern as pgs_admin_web).
    auto *tcp = new QTcpServer(this);
    if (!tcp->listen(QHostAddress::Any, m_listenPort))
        return false;
    if (!m_server->bind(tcp))
    {
        tcp->close();
        return false;
    }
    return true;
}

QString ClusterServer::listenUrl() const
{
    return QStringLiteral("http://0.0.0.0:%1").arg(m_listenPort);
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
        n.baseHttpsUrl = QString::fromUtf8(parts[1]);
        n.credentials = QString::fromUtf8(parts[2]);
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
    auto fetch = [this, node](const QString &path, QString &outDest, bool &reachableOut, QString &errOut) {
        const QUrl url(node.baseHttpsUrl + path);
        QNetworkRequest req(url);
        req.setRawHeader("Authorization", "Basic " + node.credentials.toUtf8().toBase64());
        // Accept self-signed certs (operator trusts their own nodes).
        QSslConfiguration cfg = req.sslConfiguration();
        cfg.setPeerVerifyMode(QSslSocket::VerifyNone);
        req.setSslConfiguration(cfg);
        QNetworkReply *reply = m_nam->get(req);
        connect(reply, &QNetworkReply::finished, this, [this, node, reply, &outDest, &reachableOut, &errOut]() {
            reply->deleteLater();
            if (reply->error() != QNetworkReply::NoError)
            {
                reachableOut = false;
                errOut = reply->errorString();
                m_cache[node.name].reachable = false;
                m_cache[node.name].lastError = errOut;
                m_cache[node.name].lastUpdatedMs = QDateTime::currentMSecsSinceEpoch();
                return;
            }
            outDest = QString::fromUtf8(reply->readAll());
            reachableOut = true;
            m_cache[node.name].reachable = true;
            m_cache[node.name].lastError.clear();
            m_cache[node.name].lastUpdatedMs = QDateTime::currentMSecsSinceEpoch();
        });
    };

    NodeCache &cache = m_cache[node.name];
    fetch("/api/cluster/health", cache.healthJson, cache.reachable, cache.lastError);
    fetch("/api/guards", cache.guardsJson, cache.reachable, cache.lastError);
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
    Node n;
    n.name = name;
    n.baseHttpsUrl = url;
    n.credentials = creds;
    // mutate via non-const: cast away constness of `this` for the registry
    const_cast<ClusterServer *>(this)->m_nodes.insert(name, n);
    const_cast<ClusterServer *>(this)->saveNodes();
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
    const_cast<ClusterServer *>(this)->m_nodes.remove(name);
    const_cast<ClusterServer *>(this)->m_cache.remove(name);
    const_cast<ClusterServer *>(this)->saveNodes();
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
        QJsonObject o;
        o.insert("name", it.key());
        o.insert("url", it.value().baseHttpsUrl);
        o.insert("reachable", c.reachable);
        o.insert("last_error", c.lastError);

        int guardCount = 0;
        if (c.reachable && !c.healthJson.isEmpty())
        {
            QJsonParseError pe;
            const QJsonDocument hd = QJsonDocument::fromJson(c.healthJson.toUtf8(), &pe);
            if (pe.error == QJsonParseError::NoError && hd.isObject())
                guardCount = hd.object().value("guard_count").toInt(0);
        }
        if (!c.reachable)
            ++offlineCount;
        o.insert("guard_count", guardCount);
        totalGuards += guardCount;

        // Count dead guards from the guards JSON.
        if (c.reachable && !c.guardsJson.isEmpty())
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
<input id="ncreds" placeholder="user:pass">
<button onclick="addNode()">Add Node</button>
</div>
<div class="grid" id="grid"></div>
<script>
function fmt(s){return s||'--';}
async function refresh(){
  const r=await fetch('/api/cluster/summary');const j=await r.json();
  const s=document.getElementById('summary');
  s.innerHTML=`<div class="card"><div class="v">${j.node_count}</div><div class="l">Nodes</div></div>
    <div class="card"><div class="v ${j.offline_count?'bad':'ok'}">${j.offline_count}</div><div class="l">Offline</div></div>
    <div class="card"><div class="v">${j.total_guards}</div><div class="l">Guards</div></div>
    <div class="card"><div class="v ${j.dead_guards?'bad':'ok'}">${j.dead_guards}</div><div class="l">Dead Guards</div></div>`;
  const g=document.getElementById('grid');g.innerHTML='';
  (j.nodes||[]).forEach(n=>{
    const d=document.createElement('div');
    d.className='node'+(n.reachable?'':' offline');
    d.innerHTML=`<h3>${n.name} <span class="tag ${n.reachable?'up':'down'}">${n.reachable?'UP':'DOWN'}</span></h3>
      <div>${n.guard_count} guard(s)</div>
      <div class="meta">${fmt(n.url)}<br>${n.reachable?'':'error: '+fmt(n.last_error)}</div>`;
    g.appendChild(d);
  });
}
async function addNode(){
  const name=document.getElementById('nname').value.trim();
  const url=document.getElementById('nurl').value.trim();
  const creds=document.getElementById('ncreds').value.trim();
  if(!name||!url)return;
  await fetch('/api/cluster/nodes',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({name,url,credentials:creds})});
  document.getElementById('nname').value='';document.getElementById('nurl').value='';document.getElementById('ncreds').value='';
  refresh();
}
refresh();setInterval(refresh,1000);
</script></body></html>)HTML";
    return QHttpServerResponse(QByteArray("text/html; charset=utf-8"), QByteArray(html));
}
