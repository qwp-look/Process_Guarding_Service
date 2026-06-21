#include "WebServer.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QHostAddress>
#include <QHttpServer>
#include <QHttpServerRequest>
#include <QHttpServerResponse>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QProcess>
#include <QProcessEnvironment>
#include <QTcpServer>
#include <QUrlQuery>
#include <QRandomGenerator>
#include <QCryptographicHash>

namespace
{
QString bodyValue(const QJsonObject &obj, const QString &key)
{
    return obj.value(key).toString().trimmed();
}

QString indexHtml()
{
    // Keep the first version self-contained: one executable can serve the page
    // with no asset pipeline, no extra files to deploy, and no mismatch between
    // backend version and frontend bundle.
    return QString::fromUtf8(R"HTML(
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PGS Web Console</title>
<style>
:root{--bg:#f5f0e4;--panel:#fffaf0;--ink:#1e271f;--accent:#22543d;--border:#d7cfbf;--muted:#5d6a5d}
*{box-sizing:border-box}body{margin:0;font-family:"Segoe UI","Microsoft YaHei UI",sans-serif;color:var(--ink);background:linear-gradient(180deg,#f8f4eb,var(--bg))}
header{padding:24px;border-bottom:1px solid #d9cfbf;background:#fff8ee;position:sticky;top:0}h1{margin:0;text-transform:uppercase;letter-spacing:.05em}
.sub{margin-top:8px;color:var(--muted);max-width:900px}.layout{display:grid;grid-template-columns:1.2fr .8fr;gap:16px;padding:20px}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:18px;padding:16px;box-shadow:0 10px 28px rgba(44,53,44,.1)}
.panel h2{margin:0 0 12px;font-size:18px;text-transform:uppercase;letter-spacing:.05em}.grid{display:grid;gap:10px}.grid2{grid-template-columns:repeat(2,minmax(0,1fr))}
label{display:grid;gap:6px;font-size:12px;text-transform:uppercase;color:var(--muted)}input,button{font:inherit}input{width:100%;padding:10px 12px;border:1px solid var(--border);border-radius:12px;background:#fff}
.actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:12px}button{border:0;border-radius:999px;padding:10px 16px;background:var(--accent);color:#f8fff8;cursor:pointer}
button.secondary{background:#dae8dc;color:var(--ink)}button.warn{background:#8b3d1f}.cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}
.card{padding:14px;border-radius:14px;background:#e0ece2}.card b{display:block;font-size:24px}.hint{color:var(--muted);font-size:13px}
table{width:100%;border-collapse:collapse;background:#fff}th,td{padding:10px 12px;border-bottom:1px solid #efe6d8;text-align:left;vertical-align:top}th{background:#f1eadb}
.table-wrap{overflow:auto;border:1px solid var(--border);border-radius:14px}.log{min-height:240px;background:#1c221f;color:#d6f3dd;border-radius:14px;padding:12px;white-space:pre-wrap;overflow:auto;font-family:Consolas,monospace}
@media (max-width:1100px){.layout,.cards,.grid2{grid-template-columns:1fr}}
</style>
</head>
<body>
<header><h1>ProcessGuard Web Console</h1><div class="sub">A real browser-based local control surface. The backend stays outside PGS and reuses the existing toolchain instead of teaching HTTP logic to the guard core.</div></header>
<div class="layout">
<div class="grid" style="gap:16px">
<section class="panel"><h2>Overview</h2><div class="cards"><div class="card"><b id="metric-guards">0</b>Active Guards</div><div class="card"><b id="metric-service">unknown</b>Service</div><div class="card"><b id="metric-ping">unknown</b>PGS Ping</div></div><div class="actions"><button onclick="refreshAll()">Refresh All</button><button class="secondary" onclick="pingPgs()">Ping</button><button class="secondary" onclick="serviceStatus()">Service Status</button></div></section>
<section class="panel"><h2>Guard Table</h2><div class="hint">This table shows currently active guards. It refreshes every 2 seconds.</div><div class="table-wrap" style="margin-top:12px"><table><thead><tr><th>PID</th><th>Path</th><th>Args</th><th>Restarts</th><th>Max</th><th>Alive</th><th>Session</th><th>Hash</th></tr></thead><tbody id="guard-body"></tbody></table></div></section>
<section class="panel"><h2>Launch And Protect</h2><div class="grid grid2"><label>Path<input id="start-path" placeholder="C:/apps/worker.exe"></label><label>Command<input id="start-command" placeholder="&quot;C:/apps/worker.exe&quot; --safe"></label><label>Start Args<input id="start-args" placeholder="--mode worker"></label><label>Restart Args<input id="start-restart-args" placeholder="optional"></label><label>Max Restarts<input id="start-max" value="3"></label></div><div class="actions"><button onclick="blessStart()">Start + Bless</button></div></section>
</div>
<div class="grid" style="gap:16px">
<section class="panel"><h2>Guard Actions</h2><div class="grid grid2"><label>PID<input id="guard-pid" placeholder="1234"></label><label>Path For Unbless-Path<input id="guard-path" placeholder="optional"></label><label>Max Restarts<input id="guard-max" value="3"></label><label>Restart Args<input id="guard-restart-args" placeholder="optional"></label></div><div class="actions"><button onclick="blessPid()">Bless PID</button><button class="secondary" onclick="setPolicy()">Set Policy</button><button class="secondary" onclick="intentionalExit()">Intentional</button><button class="warn" onclick="unblessGuard()">Unbless</button></div></section>
<section class="panel"><h2>Service</h2><div class="actions"><button class="secondary" onclick="serviceAction('install')">Install</button><button class="secondary" onclick="serviceAction('start')">Start</button><button class="secondary" onclick="serviceAction('stop')">Stop</button><button class="secondary" onclick="serviceAction('status')">Status</button><button class="warn" onclick="serviceAction('uninstall')">Uninstall</button></div></section>
<section class="panel"><h2>Token</h2><div class="grid grid2"><label>Old Token<input id="token-old" placeholder="optional"></label><label>New Token<input id="token-new" placeholder="new token"></label></div><div class="actions"><button onclick="updateToken()">Update Token</button></div></section>
<section class="panel"><h2>Activity Log</h2><pre class="log" id="log-box"></pre></section>
</div>
</div>
<script>
window.PGS_API_TOKEN="__PGS_API_TOKEN__";
const logBox=document.getElementById('log-box');const guardBody=document.getElementById('guard-body');
function logLine(m){const t=new Date().toLocaleTimeString();logBox.textContent+=`[${t}] ${m}\n`;logBox.scrollTop=logBox.scrollHeight}
async function api(path,options={}){const hdrs=Object.assign({'Content-Type':'application/json'},options.headers||{});hdrs['X-PGS-Token']=window.PGS_API_TOKEN;const r=await fetch(path,Object.assign({},options,{headers:hdrs}));const text=await r.text();let data={};try{data=text?JSON.parse(text):{}}catch{data={ok:false,message:text}}if(!r.ok||data.ok===false){throw new Error(data.message||text||`request failed: ${r.status}`)}return data}
function guardPayload(){return{pid:document.getElementById('guard-pid').value.trim(),path:document.getElementById('guard-path').value.trim(),max_restarts:document.getElementById('guard-max').value.trim(),restart_args:document.getElementById('guard-restart-args').value.trim()}}
async function refreshAll(){await Promise.allSettled([pingPgs(),serviceStatus(),refreshGuards()])}
async function pingPgs(){try{const d=await api('/api/ping');document.getElementById('metric-ping').textContent='ok';logLine(d.message||'ping ok')}catch(e){document.getElementById('metric-ping').textContent='down';logLine(`ping failed: ${e.message}`)}}
async function serviceStatus(){try{const d=await api('/api/service/status');document.getElementById('metric-service').textContent=d.state||'unknown';logLine(`service status: ${d.state||d.message}`)}catch(e){document.getElementById('metric-service').textContent='error';logLine(`service status failed: ${e.message}`)}}
async function refreshGuards(){try{const d=await api('/api/guards');const items=Array.isArray(d.guards)?d.guards:[];document.getElementById('metric-guards').textContent=String(items.length);guardBody.innerHTML=items.map(i=>`<tr><td>${i.pid||''}</td><td>${i.path||''}</td><td>${i.restart_args||''}</td><td>${i.restart_count||'0'}</td><td>${i.max_restarts||''}</td><td>${i.alive||''}</td><td>${i.session||''}</td><td>${i.hash||''}</td></tr>`).join('')}catch(e){logLine(`guard refresh failed: ${e.message}`)}}
async function blessPid(){try{const d=await api('/api/bless',{method:'POST',body:JSON.stringify(guardPayload())});logLine(d.message||'bless ok');refreshGuards()}catch(e){logLine(`bless failed: ${e.message}`)}}
async function blessStart(){const body={path:document.getElementById('start-path').value.trim(),command:document.getElementById('start-command').value.trim(),start_args:document.getElementById('start-args').value.trim(),restart_args:document.getElementById('start-restart-args').value.trim(),max_restarts:document.getElementById('start-max').value.trim()};try{const d=await api('/api/bless-start',{method:'POST',body:JSON.stringify(body)});logLine(d.message||'bless-start ok');refreshGuards()}catch(e){logLine(`bless-start failed: ${e.message}`)}}
async function setPolicy(){try{const d=await api('/api/policy',{method:'POST',body:JSON.stringify(guardPayload())});logLine(d.message||'policy updated');refreshGuards()}catch(e){logLine(`policy failed: ${e.message}`)}}
async function unblessGuard(){try{const d=await api('/api/unbless',{method:'POST',body:JSON.stringify(guardPayload())});logLine(d.message||'unbless ok');refreshGuards()}catch(e){logLine(`unbless failed: ${e.message}`)}}
async function intentionalExit(){try{const d=await api('/api/intentional',{method:'POST',body:JSON.stringify(guardPayload())});logLine(d.message||'intentional marked');refreshGuards()}catch(e){logLine(`intentional failed: ${e.message}`)}}
async function updateToken(){const body={old_token:document.getElementById('token-old').value.trim(),new_token:document.getElementById('token-new').value.trim()};try{const d=await api('/api/token',{method:'POST',body:JSON.stringify(body)});logLine(d.message||'token updated')}catch(e){logLine(`token update failed: ${e.message}`)}}
async function serviceAction(action){try{const d=await api(`/api/service/${action}`,{method:action==='status'?'GET':'POST'});logLine(d.message||`${action} ok`);serviceStatus()}catch(e){logLine(`service ${action} failed: ${e.message}`)}}
setInterval(refreshGuards,2000);refreshAll();
</script>
</body></html>
)HTML");
}
} // namespace

WebServer::WebServer(Options options, QObject *parent)
    : QObject(parent), m_options(std::move(options)), m_server(new QHttpServer(this))
{
    // Generate a per-process API token that the browser must echo back in the
    // X-PGS-Token header. It is embedded in the served index page (same-origin
    // readable) so a cross-site page cannot read it and therefore cannot forge
    // the custom header on a cross-origin request.
    QByteArray bytes(32, '\0');
    for (int i = 0; i < bytes.size(); ++i)
    {
        bytes[i] = static_cast<char>(QRandomGenerator::global()->generate() & 0xFF);
    }
    m_apiToken = QString::fromLatin1(QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex());
}

// Authorize an /api/* request: require the X-PGS-Token header to match the
// per-process API token, AND verify Host is loopback (DNS-rebinding defense)
// and Origin (when present) is the local listening origin (CSRF defense).
// Because X-PGS-Token is a custom header, a cross-site fetch cannot set it
// without a CORS preflight, which this server never grants.
bool WebServer::isRequestAuthorized(const QHttpServerRequest &request) const
{
    const QString token = request.value("X-PGS-Token").trimmed();
    if (token.isEmpty() || token != m_apiToken)
    {
        return false;
    }

    // Host header must refer to the loopback address we listen on.
    const QString host = request.value("Host").trimmed();
    const QString expectedHost = QStringLiteral("%1:%2").arg(m_options.bindAddress).arg(m_options.httpPort);
    const QString expectedAlt = QStringLiteral("localhost:%1").arg(m_options.httpPort);
    if (!host.isEmpty() && host != expectedHost && host != expectedAlt)
    {
        return false;
    }

    // Origin (sent by browsers on cross-origin/cors requests): when present it
    // must be the local listening origin or empty.
    const QString origin = request.value("Origin").trimmed();
    if (!origin.isEmpty())
    {
        const QString selfOrigin = QStringLiteral("http://%1").arg(expectedHost);
        const QString selfOriginAlt = QStringLiteral("http://%1").arg(expectedAlt);
        if (origin != selfOrigin && origin != selfOriginAlt)
        {
            return false;
        }
    }
    return true;
}

// Served HTML now embeds the API token so the same-origin browser UI can call
// /api/* with the X-PGS-Token header. A cross-site page cannot read this HTML.
QHttpServerResponse WebServer::handleIndexHtml() const
{
    QString html = indexHtml();
    html.replace(QStringLiteral("__PGS_API_TOKEN__"), m_apiToken);
    return QHttpServerResponse(QByteArray("text/html; charset=utf-8"), html.toUtf8());
}
bool WebServer::start()
{
    using Method = QHttpServerRequest::Method;
    // Routes are intentionally coarse-grained and JSON-oriented. The browser UI
    // should consume stable HTTP resources, not the raw OK/ERR line protocol
    // spoken by PGS itself.
    m_server->route("/", Method::Get, this, [this]() { return handleIndexHtml(); });
    m_server->route("/api/health", Method::Get, this, [this]() { return handleHealth(); });
    m_server->route("/api/ping", Method::Get, this, [this](const QHttpServerRequest &request) { if (!isRequestAuthorized(request)) return jsonError("unauthorized", 401); return handlePing(); });
    m_server->route("/api/guards", Method::Get, this, [this](const QHttpServerRequest &request) { if (!isRequestAuthorized(request)) return jsonError("unauthorized", 401); return handleGuards(); });
    m_server->route("/api/guard", Method::Get, this, [this](const QHttpServerRequest &request) { if (!isRequestAuthorized(request)) return jsonError("unauthorized", 401); return handleGuard(request); });
    m_server->route("/api/bless", Method::Post, this, [this](const QHttpServerRequest &request) { if (!isRequestAuthorized(request)) return jsonError("unauthorized", 401); return handleBless(request); });
    m_server->route("/api/bless-start", Method::Post, this, [this](const QHttpServerRequest &request) { if (!isRequestAuthorized(request)) return jsonError("unauthorized", 401); return handleBlessStart(request); });
    m_server->route("/api/policy", Method::Post, this, [this](const QHttpServerRequest &request) { if (!isRequestAuthorized(request)) return jsonError("unauthorized", 401); return handlePolicy(request); });
    m_server->route("/api/unbless", Method::Post, this, [this](const QHttpServerRequest &request) { if (!isRequestAuthorized(request)) return jsonError("unauthorized", 401); return handleUnbless(request); });
    m_server->route("/api/intentional", Method::Post, this, [this](const QHttpServerRequest &request) { if (!isRequestAuthorized(request)) return jsonError("unauthorized", 401); return handleIntentional(request); });
    m_server->route("/api/token", Method::Post, this, [this](const QHttpServerRequest &request) { if (!isRequestAuthorized(request)) return jsonError("unauthorized", 401); return handleTokenUpdate(request); });
    m_server->route("/api/service/status", Method::Get, this, [this](const QHttpServerRequest &request) { if (!isRequestAuthorized(request)) return jsonError("unauthorized", 401); return handleServiceStatus(); });
    m_server->route("/api/service/install", Method::Post, this, [this](const QHttpServerRequest &request) { if (!isRequestAuthorized(request)) return jsonError("unauthorized", 401); return handleServiceAction("install"); });
    m_server->route("/api/service/start", Method::Post, this, [this](const QHttpServerRequest &request) { if (!isRequestAuthorized(request)) return jsonError("unauthorized", 401); return handleServiceAction("start"); });
    m_server->route("/api/service/stop", Method::Post, this, [this](const QHttpServerRequest &request) { if (!isRequestAuthorized(request)) return jsonError("unauthorized", 401); return handleServiceAction("stop"); });
    m_server->route("/api/service/uninstall", Method::Post, this, [this](const QHttpServerRequest &request) { if (!isRequestAuthorized(request)) return jsonError("unauthorized", 401); return handleServiceAction("uninstall"); });

    if (!m_tcpServer)
    {
        m_tcpServer = new QTcpServer(this);
    }
    if (!m_tcpServer->listen(QHostAddress(m_options.bindAddress), m_options.httpPort))
    {
        return false;
    }
    if (!m_server->bind(m_tcpServer))
    {
        m_tcpServer->close();
        return false;
    }
    return true;
}

QString WebServer::listenUrl() const
{
    return QStringLiteral("http://%1:%2").arg(m_options.bindAddress).arg(m_options.httpPort);
}

QHttpServerResponse WebServer::handleHealth() const
{
    QJsonObject obj;
    obj.insert("ok", true);
    obj.insert("listen_url", listenUrl());
    obj.insert("pgs_host", m_options.pgsHost);
    obj.insert("pgs_port", static_cast<int>(m_options.pgsPort));
    obj.insert("bless_tool", resolvedBlessToolPath());
    obj.insert("service_tool", resolvedServiceToolPath());
    return QHttpServerResponse(obj);
}

QHttpServerResponse WebServer::handlePing()
{
    QStringList args{"ping"};
    args << blessBaseArguments();
    return jsonCommandResult(runTool(resolvedBlessToolPath(), args), "PGS ping completed");
}

QHttpServerResponse WebServer::handleGuards()
{
    QStringList args{"list", "--json"};
    args << blessBaseArguments();
    const CommandResult result = runTool(resolvedBlessToolPath(), args);
    if (!result.started || !result.finished || result.exitCode != 0)
    {
        return jsonCommandResult(result, "failed to query guards");
    }
    QJsonParseError parseError;
    const QJsonDocument doc = QJsonDocument::fromJson(result.stdOut.toUtf8(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isArray())
    {
        return jsonError(QStringLiteral("guard list JSON parse failed: %1").arg(parseError.errorString()), 500);
    }
    QJsonObject obj;
    obj.insert("ok", true);
    obj.insert("guards", doc.array());
    return QHttpServerResponse(obj);
}

QHttpServerResponse WebServer::handleGuard(const QHttpServerRequest &request)
{
    const QString pid = request.query().queryItemValue("pid").trimmed();
    if (pid.isEmpty())
    {
        return jsonError("pid is required");
    }
    QStringList args{"get", "--pid", pid, "--json"};
    args << blessBaseArguments();
    const CommandResult result = runTool(resolvedBlessToolPath(), args);
    if (!result.started || !result.finished || result.exitCode != 0)
    {
        return jsonCommandResult(result, "failed to query guard");
    }
    QJsonParseError parseError;
    const QJsonDocument doc = QJsonDocument::fromJson(result.stdOut.toUtf8(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isArray())
    {
        return jsonError(QStringLiteral("guard JSON parse failed: %1").arg(parseError.errorString()), 500);
    }
    QJsonObject obj;
    obj.insert("ok", true);
    obj.insert("guard", doc.array().isEmpty() ? QJsonObject{} : doc.array().first().toObject());
    return QHttpServerResponse(obj);
}

QHttpServerResponse WebServer::handleBless(const QHttpServerRequest &request)
{
    const QJsonObject body = QJsonDocument::fromJson(request.body()).object();
    const QString pid = bodyValue(body, "pid");
    if (pid.isEmpty())
    {
        return jsonError("pid is required");
    }

    QStringList args{"bless", "--pid", pid, "--hash", "auto"};
    const QString maxRestarts = bodyValue(body, "max_restarts");
    const QString restartArgs = bodyValue(body, "restart_args");
    if (!maxRestarts.isEmpty())
    {
        args << "--max-restarts" << maxRestarts;
    }
    if (!restartArgs.isEmpty())
    {
        args << "--restart-args" << restartArgs;
    }
    args << blessBaseArguments();
    return jsonCommandResult(runTool(resolvedBlessToolPath(), args), "bless completed");
}

QHttpServerResponse WebServer::handleBlessStart(const QHttpServerRequest &request)
{
    const QJsonObject body = QJsonDocument::fromJson(request.body()).object();
    const QString path = bodyValue(body, "path");
    const QString command = bodyValue(body, "command");
    if (path.isEmpty() && command.isEmpty())
    {
        return jsonError("path or command is required");
    }

    QStringList args{"bless-start", "--hash", "auto"};
    if (!command.isEmpty())
    {
        args << "--command" << command;
    }
    else
    {
        args << "--path" << path;
    }

    const QString startArgs = bodyValue(body, "start_args");
    const QString maxRestarts = bodyValue(body, "max_restarts");
    const QString restartArgs = bodyValue(body, "restart_args");
    if (!startArgs.isEmpty() && command.isEmpty())
    {
        args << "--start-args" << startArgs;
    }
    if (!maxRestarts.isEmpty())
    {
        args << "--max-restarts" << maxRestarts;
    }
    if (!restartArgs.isEmpty())
    {
        args << "--restart-args" << restartArgs;
    }
    args << blessBaseArguments();
    return jsonCommandResult(runTool(resolvedBlessToolPath(), args), "bless-start completed");
}

QHttpServerResponse WebServer::handlePolicy(const QHttpServerRequest &request)
{
    const QJsonObject body = QJsonDocument::fromJson(request.body()).object();
    const QString pid = bodyValue(body, "pid");
    const QString maxRestarts = bodyValue(body, "max_restarts");
    if (pid.isEmpty() || maxRestarts.isEmpty())
    {
        return jsonError("pid and max_restarts are required");
    }

    QStringList args{"policy", "--pid", pid, "--max-restarts", maxRestarts};
    const QString restartArgs = bodyValue(body, "restart_args");
    if (!restartArgs.isEmpty())
    {
        args << "--restart-args" << restartArgs;
    }
    args << blessBaseArguments();
    return jsonCommandResult(runTool(resolvedBlessToolPath(), args), "policy updated");
}

QHttpServerResponse WebServer::handleUnbless(const QHttpServerRequest &request)
{
    const QJsonObject body = QJsonDocument::fromJson(request.body()).object();
    const QString path = bodyValue(body, "path");
    const QString pid = bodyValue(body, "pid");

    QStringList args;
    if (!path.isEmpty())
    {
        args << "unbless-path" << "--path" << path;
    }
    else if (!pid.isEmpty())
    {
        args << "unbless" << "--pid" << pid;
    }
    else
    {
        return jsonError("pid or path is required");
    }

    args << blessBaseArguments();
    return jsonCommandResult(runTool(resolvedBlessToolPath(), args), "unbless completed");
}

QHttpServerResponse WebServer::handleIntentional(const QHttpServerRequest &request)
{
    const QJsonObject body = QJsonDocument::fromJson(request.body()).object();
    const QString pid = bodyValue(body, "pid");
    if (pid.isEmpty())
    {
        return jsonError("pid is required");
    }
    QStringList args{"intentional", "--pid", pid};
    args << blessBaseArguments();
    return jsonCommandResult(runTool(resolvedBlessToolPath(), args), "intentional exit marked");
}

QHttpServerResponse WebServer::handleTokenUpdate(const QHttpServerRequest &request)
{
    const QJsonObject body = QJsonDocument::fromJson(request.body()).object();
    const QString oldToken = bodyValue(body, "old_token");
    const QString newToken = bodyValue(body, "new_token");
    if (newToken.isEmpty())
    {
        return jsonError("new_token is required");
    }

    QStringList args{"token-set", "--new-token", newToken};
    if (!oldToken.isEmpty())
    {
        args << "--old-token" << oldToken;
    }
    args << blessBaseArguments();
    const CommandResult result = runTool(resolvedBlessToolPath(), args);
    if (!result.started || !result.finished || result.exitCode != 0)
    {
        return jsonCommandResult(result, "token update failed");
    }

    m_options.pgsToken = newToken;
    return jsonCommandResult(result, "token updated");
}

QHttpServerResponse WebServer::handleServiceStatus()
{
    const CommandResult result = runTool(resolvedServiceToolPath(), {"status"});
    if (!result.started || !result.finished || result.exitCode != 0)
    {
        return jsonCommandResult(result, "failed to query service status");
    }

    QString state = result.stdOut.trimmed();
    if (state.startsWith("Status:", Qt::CaseInsensitive))
    {
        state = state.section(':', 1).trimmed();
    }

    QJsonObject obj;
    obj.insert("ok", true);
    obj.insert("state", state);
    obj.insert("message", result.stdOut.trimmed());
    return QHttpServerResponse(obj);
}

QHttpServerResponse WebServer::handleServiceAction(const QString &action)
{
    return jsonCommandResult(runTool(resolvedServiceToolPath(), {action}), "service action completed");
}

QHttpServerResponse WebServer::handleIndex() const
{
    return QHttpServerResponse(QByteArray("text/html; charset=utf-8"), indexHtml().toUtf8());
}

WebServer::CommandResult WebServer::runTool(const QString &program, const QStringList &args, int timeoutMs) const
{
    // Reuse the mature CLI entrypoints as the operational boundary:
    // - blessing semantics stay identical across CLI / Qt / Web
    // - protocol parsing stays centralized in one place for now
    // - failures remain easy to diagnose because stdout/stderr are preserved
    CommandResult result;
    if (!QFileInfo::exists(program))
    {
        result.errorText = QStringLiteral("tool not found: %1").arg(program);
        return result;
    }

    QProcess process;
    process.setProgram(program);
    process.setArguments(args);
    process.setWorkingDirectory(QFileInfo(program).absolutePath());
    // Pass the PGS auth token through the environment instead of the command
    // line so other local users cannot read it via process command-line queries.
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    if (!m_options.pgsToken.isEmpty())
    {
        env.insert(QStringLiteral("PGS_AUTH_TOKEN"), m_options.pgsToken);
    }
    process.setProcessEnvironment(env);
    process.start();
    result.started = process.waitForStarted(5000);
    if (!result.started)
    {
        result.errorText = process.errorString();
        return result;
    }

    result.finished = process.waitForFinished(timeoutMs);
    if (!result.finished)
    {
        process.kill();
        process.waitForFinished(3000);
        result.stdOut = QString::fromUtf8(process.readAllStandardOutput()).trimmed();
        result.stdErr = QString::fromUtf8(process.readAllStandardError()).trimmed();
        result.errorText = "process timeout";
        return result;
    }

    result.exitCode = process.exitCode();
    result.stdOut = QString::fromUtf8(process.readAllStandardOutput()).trimmed();
    result.stdErr = QString::fromUtf8(process.readAllStandardError()).trimmed();
    if (process.exitStatus() != QProcess::NormalExit && result.errorText.isEmpty())
    {
        result.errorText = "process crashed";
    }
    return result;
}

QString WebServer::resolvedBlessToolPath() const
{
    if (!m_options.blessToolPath.trimmed().isEmpty())
    {
        return m_options.blessToolPath;
    }
    const QString appDir = QCoreApplication::applicationDirPath();
    QString candidate = QDir(appDir).filePath("../pgs_bless.exe");
    if (QFileInfo::exists(candidate))
    {
        return QDir::cleanPath(candidate);
    }
    candidate = QDir(appDir).filePath("pgs_bless.exe");
    if (QFileInfo::exists(candidate))
    {
        return QDir::cleanPath(candidate);
    }
    return "pgs_bless.exe";
}

QString WebServer::resolvedServiceToolPath() const
{
    if (!m_options.serviceToolPath.trimmed().isEmpty())
    {
        return m_options.serviceToolPath;
    }
    const QString appDir = QCoreApplication::applicationDirPath();
    QString candidate = QDir(appDir).filePath("../pgs_service.exe");
    if (QFileInfo::exists(candidate))
    {
        return QDir::cleanPath(candidate);
    }
    candidate = QDir(appDir).filePath("pgs_service.exe");
    if (QFileInfo::exists(candidate))
    {
        return QDir::cleanPath(candidate);
    }
    return "pgs_service.exe";
}

QStringList WebServer::blessBaseArguments() const
{
    // The browser never needs to understand the raw token protocol. The web
    // backend holds the current PGS token and injects it into every CLI call
    // via the PGS_AUTH_TOKEN environment variable (see runTool), never on the
    // command line where other local users could read it.
    QStringList args{"--host", m_options.pgsHost, "--port", QString::number(m_options.pgsPort)};
    return args;
}

QHttpServerResponse WebServer::jsonOk(const QString &message)
{
    QJsonObject obj;
    obj.insert("ok", true);
    obj.insert("message", message);
    return QHttpServerResponse(obj);
}

QHttpServerResponse WebServer::jsonError(const QString &message, int statusCode)
{
    QJsonObject obj;
    obj.insert("ok", false);
    obj.insert("message", message);
    return QHttpServerResponse(obj, static_cast<QHttpServerResponse::StatusCode>(statusCode));
}

QHttpServerResponse WebServer::jsonCommandResult(const CommandResult &result, const QString &message, bool allowRawStdout)
{
    if (!result.started)
    {
        return jsonError(result.errorText.isEmpty() ? "failed to start tool process" : result.errorText, 500);
    }
    if (!result.finished)
    {
        return jsonError(result.errorText.isEmpty() ? "tool process timeout" : result.errorText, 504);
    }
    if (result.exitCode != 0)
    {
        QString failure = result.stdErr;
        if (failure.isEmpty())
        {
            failure = result.stdOut;
        }
        if (failure.isEmpty())
        {
            failure = result.errorText;
        }
        if (failure.isEmpty())
        {
            failure = QStringLiteral("command failed with exit code %1").arg(result.exitCode);
        }
        return jsonError(failure, 500);
    }

    QJsonObject obj;
    obj.insert("ok", true);
    obj.insert("message", message.isEmpty() ? result.stdOut : message);
    if (allowRawStdout)
    {
        obj.insert("stdout", result.stdOut);
        obj.insert("stderr", result.stdErr);
    }
    return QHttpServerResponse(obj);
}
