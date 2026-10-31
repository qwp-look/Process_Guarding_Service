#include "WebServer.h"

#include "../../common/SimpleHttp.h"
#include <QCoreApplication>
#include <QAbstractSocket>
#include <QDir>
#include <QFileInfo>
#include <QHostAddress>
#include <QHttpHeaders>
#include <QHttpServerRequest>
#include <QHttpServerResponse>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QProcess>
#include <QProcessEnvironment>
#include <QTcpServer>
#include <QUrl>
#include <QUrlQuery>
#include <QRandomGenerator>
#include <QCryptographicHash>
#include <QSslServer>
#include <QSslKey>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslSocket>
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <QHash>
#include <QMessageAuthenticationCode>
#include <QPasswordDigestor>
#include <algorithm>
#include <cstring>
#include "Process_Guard/PGSClient.h"

namespace
{
QString bodyValue(const QJsonObject &obj, const QString &key)
{
    return obj.value(key).toString().trimmed();
}

bool bodyFlag(const QJsonObject &obj, const QString &key)
{
    const QString value = bodyValue(obj, key).toLower();
    return value == QLatin1String("1") || value == QLatin1String("true") ||
           value == QLatin1String("yes") || value == QLatin1String("on");
}

void appendAdvancedGuardArgs(QStringList &args, const QJsonObject &body)
{
    const QString restartWindow = bodyValue(body, QStringLiteral("restart_window"));
    if (!restartWindow.isEmpty())
    {
        args << QStringLiteral("--restart-window") << restartWindow;
    }
    const QString restartDelay = bodyValue(body, QStringLiteral("restart_delay"));
    if (!restartDelay.isEmpty())
    {
        args << QStringLiteral("--restart-delay") << restartDelay;
    }
    if (bodyFlag(body, QStringLiteral("restart_backoff")))
    {
        args << QStringLiteral("--restart-backoff");
    }
    const QString hangTimeout = bodyValue(body, QStringLiteral("hang_timeout"));
    if (!hangTimeout.isEmpty())
    {
        args << QStringLiteral("--hang-timeout") << hangTimeout;
    }
    if (bodyFlag(body, QStringLiteral("kill_on_exit")))
    {
        args << QStringLiteral("--kill-on-exit");
    }
    if (bodyFlag(body, QStringLiteral("winapp")))
    {
        args << QStringLiteral("--winapp");
    }
    const QString aumid = bodyValue(body, QStringLiteral("aumid"));
    if (!aumid.isEmpty())
    {
        args << QStringLiteral("--aumid") << aumid;
    }
}

QString optionalPolicyField(const QJsonObject &body, const QString &key)
{
    return body.contains(key) ? bodyValue(body, key) : QString();
}

bool isUnsignedText(const QString &value)
{
    if (value.isEmpty())
    {
        return false;
    }
    for (const QChar ch : value)
    {
        if (!ch.isDigit())
        {
            return false;
        }
    }
    return true;
}

bool isOpaqueIdText(const QString &value, const QString &prefix)
{
    if (!value.startsWith(prefix) || value.size() <= prefix.size())
    {
        return false;
    }
    for (const QChar ch : value)
    {
        if (!(ch.isLetterOrNumber() || ch == QLatin1Char('_') || ch == QLatin1Char('-')))
        {
            return false;
        }
    }
    return true;
}

bool isSafeKvValueText(const QString &value)
{
    if (value.size() > 128)
    {
        return false;
    }
    for (const QChar ch : value)
    {
        if (ch == QLatin1Char(';') || ch == QLatin1Char('\r') || ch == QLatin1Char('\n') || ch == QLatin1Char('\0'))
        {
            return false;
        }
        if (ch.unicode() < 0x20 && ch != QLatin1Char('\t'))
        {
            return false;
        }
    }
    return true;
}

QJsonObject jsonObjectFromToolStdout(const QString &stdoutText)
{
    QJsonParseError parseError{};
    const QJsonDocument doc = QJsonDocument::fromJson(stdoutText.trimmed().toUtf8(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject())
    {
        return QJsonObject{};
    }
    return doc.object();
}

QString summaryField(const QString &summaryText, const QString &key)
{
    QString line = summaryText.section(QLatin1Char('\n'), 0, 0).trimmed();
    if (line.startsWith(QLatin1String("OK ")))
    {
        line = line.mid(3).trimmed();
    }
    const QStringList fields = line.split(QLatin1Char(';'));
    for (const QString &field : fields)
    {
        const int eq = field.indexOf(QLatin1Char('='));
        if (eq < 0)
        {
            continue;
        }
        const QString name = field.left(eq).trimmed();
        if (name.compare(key, Qt::CaseInsensitive) == 0)
        {
            return field.mid(eq + 1).trimmed();
        }
    }
    return QString();
}

QString decodedSummaryField(const QString &summaryText, const QString &key)
{
    const QString encoded = summaryField(summaryText, key);
    if (encoded.isEmpty())
    {
        return QString();
    }
    return QString::fromStdString(ProcessGuard::client::base64Decode(encoded.toStdString()));
}

// Parse one "PID=1;SESSION=0;ALIVE=1;...;PATH_B64=...;RESTART_ARGS_B64=..." line
// into the same JSON shape pgs_bless --json produces, so the browser frontend
// does not change when the web backend switches from QProcess to direct TCP.
QJsonObject parseGuardKvLine(const QString &line)
{
    QJsonObject obj;
    std::string pathB64;
    std::string argsB64;
    std::string aumidB64;
    std::string lastFailureB64;
    const QStringList parts = line.split(QLatin1Char(';'));
    for (const QString &part : parts)
    {
        const int eq = part.indexOf(QLatin1Char('='));
        if (eq < 0)
        {
            continue;
        }
        const QString key = part.left(eq).trimmed().toLower();
        const QString val = part.mid(eq + 1).trimmed();
        if (key == QLatin1String("path_b64"))
        {
            pathB64 = val.toStdString();
        }
        else if (key == QLatin1String("restart_args_b64"))
        {
            argsB64 = val.toStdString();
        }
        else if (key == QLatin1String("aumid_b64"))
        {
            aumidB64 = val.toStdString();
            obj.insert(key, val);
        }
        else if (key == QLatin1String("last_failure_b64"))
        {
            lastFailureB64 = val.toStdString();
            obj.insert(key, val);
        }
        else
        {
            obj.insert(key, val);
        }
    }
    obj.insert(QStringLiteral("path"), QString::fromStdString(ProcessGuard::client::base64Decode(pathB64)));
    obj.insert(QStringLiteral("restart_args"), QString::fromStdString(ProcessGuard::client::base64Decode(argsB64)));
    obj.insert(QStringLiteral("aumid"), QString::fromStdString(ProcessGuard::client::base64Decode(aumidB64)));
    obj.insert(QStringLiteral("last_failure"), QString::fromStdString(ProcessGuard::client::base64Decode(lastFailureB64)));
    if (obj.contains(QStringLiteral("last_failure_code")) && obj.value(QStringLiteral("last_failure_code")).toString() == QLatin1String("-"))
    {
        obj.insert(QStringLiteral("last_failure_code"), QString());
    }
    return obj;
}

// Split a raw PGS "list"/"get" reply into guard JSON objects. The reply shape is
// "OK [count=N]\nPID=...;...\nPID=...;...". ERR replies are rejected before
// callers parse them.
QJsonArray parseGuardReply(const QString &reply)
{
    QJsonArray out;
    const QStringList lines = reply.split(QLatin1Char('\n'));
    for (const QString &line : lines)
    {
        const QString trimmed = line.trimmed();
        if (trimmed.startsWith(QLatin1String("PID=")))
        {
            out.append(parseGuardKvLine(trimmed));
        }
    }
    return out;
}

bool isLoopbackBind(const QString &bindAddress)
{
    const QString normalized = bindAddress.trimmed().toLower();
    return normalized == QLatin1String("127.0.0.1") ||
           normalized == QLatin1String("localhost") ||
           normalized == QLatin1String("::1");
}

QHostAddress parseBindAddress(const QString &bindAddress)
{
    const QString normalized = bindAddress.trimmed().toLower();
    if (normalized == QLatin1String("localhost"))
    {
        return QHostAddress(QHostAddress::LocalHost);
    }
    QHostAddress address;
    address.setAddress(bindAddress.trimmed());
    return address;
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

bool constantTimeEquals(const QByteArray &left, const QByteArray &right)
{
    const int maxSize = qMax(left.size(), right.size());
    unsigned char diff = static_cast<unsigned char>(left.size() ^ right.size());
    for (int i = 0; i < maxSize; ++i)
    {
        const unsigned char av = i < left.size() ? static_cast<unsigned char>(left.at(i)) : 0;
        const unsigned char bv = i < right.size() ? static_cast<unsigned char>(right.at(i)) : 0;
        diff |= static_cast<unsigned char>(av ^ bv);
    }
    return diff == 0;
}

QString cookieValue(const PgsHttp::Request &request, const QString &name)
{
    const QString cookieHeader = QString::fromLatin1(request.value("Cookie"));
    const QStringList cookies = cookieHeader.split(QLatin1Char(';'), Qt::SkipEmptyParts);
    for (const QString &cookie : cookies)
    {
        const QString trimmed = cookie.trimmed();
        const int eq = trimmed.indexOf(QLatin1Char('='));
        if (eq <= 0)
        {
            continue;
        }
        const QString cookieName = trimmed.left(eq).trimmed();
        if (cookieName == name)
        {
            return trimmed.mid(eq + 1).trimmed();
        }
    }
    return QString();
}

QString makeLocalSessionCookie(const QString &sessionToken)
{
    return QStringLiteral("pgs_local_session=%1; Path=/; HttpOnly; SameSite=Strict").arg(sessionToken);
}

bool isUnsafeMethod(QHttpServerRequest::Method method)
{
    using Method = QHttpServerRequest::Method;
    return method == Method::Post || method == Method::Put ||
           method == Method::Patch || method == Method::Delete;
}

constexpr int kPbkdf2MinIterations = 100000;
constexpr int kPbkdf2KeyLength = 32;

bool isJsonRequest(const PgsHttp::Request &request)
{
    const QString contentType = request.value("Content-Type").trimmed().toLower();
    return contentType.startsWith(QLatin1String("application/json"));
}

QString auditField(QString value)
{
    QString out;
    out.reserve(value.size());
    for (const QChar ch : value)
    {
        const uint code = static_cast<uint>(ch.unicode());
        switch (code)
        {
        case '\\':
            out += QStringLiteral("\\\\");
            break;
        case '"':
            out += QStringLiteral("\\\"");
            break;
        case '\r':
            out += QStringLiteral("\\r");
            break;
        case '\n':
            out += QStringLiteral("\\n");
            break;
        case '\t':
            out += QStringLiteral("\\t");
            break;
        default:
            if (code < 0x20 || code == 0x7f)
            {
                out += QStringLiteral("\\u%1").arg(code, 4, 16, QLatin1Char('0'));
            }
            else
            {
                out += ch;
            }
            break;
        }
    }
    return out;
}

int auditHexValue(QChar ch)
{
    const ushort u = ch.unicode();
    if (u >= '0' && u <= '9')
        return static_cast<int>(u - '0');
    if (u >= 'a' && u <= 'f')
        return static_cast<int>(u - 'a' + 10);
    if (u >= 'A' && u <= 'F')
        return static_cast<int>(u - 'A' + 10);
    return -1;
}

QString auditQuotedValue(const QString &line, const QString &key)
{
    const QString prefix = key + QStringLiteral("=\"");
    const int start = line.indexOf(prefix);
    if (start < 0)
        return QString();

    QString out;
    bool escaped = false;
    for (int i = start + prefix.size(); i < line.size(); ++i)
    {
        const QChar ch = line.at(i);
        if (escaped)
        {
            switch (ch.unicode())
            {
            case '\\':
            case '"':
                out += ch;
                break;
            case 'r':
                out += QLatin1Char('\r');
                break;
            case 'n':
                out += QLatin1Char('\n');
                break;
            case 't':
                out += QLatin1Char('\t');
                break;
            case 'u':
                if (i + 4 < line.size())
                {
                    int code = 0;
                    bool ok = true;
                    for (int j = 1; j <= 4; ++j)
                    {
                        const int v = auditHexValue(line.at(i + j));
                        if (v < 0)
                        {
                            ok = false;
                            break;
                        }
                        code = (code << 4) | v;
                    }
                    if (ok)
                    {
                        out += QChar(static_cast<ushort>(code));
                        i += 4;
                        break;
                    }
                }
                out += ch;
                break;
            default:
                out += ch;
                break;
            }
            escaped = false;
            continue;
        }
        if (ch == QLatin1Char('\\'))
        {
            escaped = true;
            continue;
        }
        if (ch == QLatin1Char('"'))
        {
            break;
        }
        out += ch;
    }
    return out;
}

QJsonObject parseAuditLine(const QString &line)
{
    QJsonObject obj;
    const int space = line.indexOf(QLatin1Char(' '));
    obj.insert(QStringLiteral("time"), space > 0 ? line.left(space) : QString());
    obj.insert(QStringLiteral("user"), auditQuotedValue(line, QStringLiteral("user")));
    obj.insert(QStringLiteral("action"), auditQuotedValue(line, QStringLiteral("action")));
    obj.insert(QStringLiteral("from"), auditQuotedValue(line, QStringLiteral("from")));
    obj.insert(QStringLiteral("raw"), line);
    return obj;
}

QString expectedOriginFromHost(const PgsHttp::Request &request, bool https)
{
    const QString host = request.value("Host").trimmed();
    if (host.isEmpty())
    {
        return QString();
    }
    return QStringLiteral("%1://%2").arg(https ? QStringLiteral("https") : QStringLiteral("http"), host);
}

bool sameOriginBrowserHeaders(const PgsHttp::Request &request, bool https)
{
    const QString expectedOrigin = expectedOriginFromHost(request, https);
    if (expectedOrigin.isEmpty())
    {
        return false;
    }

    const QString secFetchSite = request.value("Sec-Fetch-Site").trimmed().toLower();
    if (!secFetchSite.isEmpty() &&
        secFetchSite != QLatin1String("same-origin") &&
        secFetchSite != QLatin1String("none"))
    {
        return false;
    }

    const QString origin = request.value("Origin").trimmed();
    if (!origin.isEmpty())
    {
        return origin.compare(expectedOrigin, Qt::CaseInsensitive) == 0;
    }

    const QString referer = request.value("Referer").trimmed();
    if (!referer.isEmpty())
    {
        return referer.compare(expectedOrigin, Qt::CaseInsensitive) == 0 ||
               referer.startsWith(expectedOrigin + QLatin1Char('/'), Qt::CaseInsensitive);
    }

    return false;
}

bool authorizeRemoteCsrf(const PgsHttp::Request &request, const QString &csrfToken)
{
    if (!isUnsafeMethod(request.method()))
    {
        return true;
    }
    if (!isJsonRequest(request))
    {
        return false;
    }
    if (!constantTimeEquals(request.value("X-PGS-CSRF").trimmed(), csrfToken))
    {
        return false;
    }
    return sameOriginBrowserHeaders(request, true);
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

QString sourceAddress(const PgsHttp::Request &request)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 4, 0)
    return request.remoteAddress().toString();
#else
    Q_UNUSED(request);
    return QStringLiteral("unknown");
#endif
}

QString methodName(QHttpServerRequest::Method method)
{
    using Method = QHttpServerRequest::Method;
    switch (method)
    {
    case Method::Get:
        return QStringLiteral("GET");
    case Method::Put:
        return QStringLiteral("PUT");
    case Method::Delete:
        return QStringLiteral("DELETE");
    case Method::Post:
        return QStringLiteral("POST");
    case Method::Patch:
        return QStringLiteral("PATCH");
    default:
        return QStringLiteral("HTTP");
    }
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
:root{--bg:#f4f6f8;--panel:#ffffff;--ink:#16202a;--accent:#1f6f64;--border:#cfd7df;--muted:#5f6c78}
*{box-sizing:border-box}body{margin:0;font-family:"Segoe UI","Microsoft YaHei UI",sans-serif;color:var(--ink);background:var(--bg)}
header{padding:18px 20px;border-bottom:1px solid var(--border);background:#ffffff;position:sticky;top:0}h1{margin:0;text-transform:uppercase;letter-spacing:0}
.sub{margin-top:8px;color:var(--muted);max-width:900px}.layout{display:grid;grid-template-columns:1.2fr .8fr;gap:16px;padding:20px}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:14px}
.panel h2{margin:0 0 12px;font-size:16px;text-transform:uppercase;letter-spacing:0}.grid{display:grid;gap:10px}.grid2{grid-template-columns:repeat(2,minmax(0,1fr))}
label{display:grid;gap:6px;font-size:12px;text-transform:uppercase;color:var(--muted)}input,button{font:inherit}input{width:100%;padding:8px 10px;border:1px solid var(--border);border-radius:4px;background:#fff}
.actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}button{border:0;border-radius:4px;padding:8px 12px;background:var(--accent);color:#f8fff8;cursor:pointer}
button.secondary{background:#dde6ec;color:var(--ink)}button.warn{background:#a13f34}.cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}
.card{padding:12px;border-radius:6px;background:#edf5f2}.card b{display:block;font-size:24px}.hint{color:var(--muted);font-size:13px}
table{width:100%;border-collapse:collapse;background:#fff}th,td{padding:8px 10px;border-bottom:1px solid #e5eaef;text-align:left;vertical-align:top;white-space:nowrap}td.path{white-space:normal;min-width:260px}th{background:#edf1f5}
.table-wrap{overflow:auto;border:1px solid var(--border);border-radius:6px}.log{min-height:240px;background:#111820;color:#d7f4e6;border-radius:6px;padding:12px;white-space:pre-wrap;overflow:auto;font-family:Consolas,monospace}
.result{min-height:120px;max-height:320px;overflow:auto;border:1px solid var(--border);border-radius:6px;background:#fff;padding:10px}.result table{font-size:13px}.result pre{margin:0;white-space:pre-wrap;font-family:Consolas,monospace}.kv{display:grid;grid-template-columns:minmax(120px,180px) 1fr;gap:6px 10px}.kv div:nth-child(odd){color:var(--muted);font-size:12px;text-transform:uppercase}.pill{display:inline-block;border-radius:4px;background:#edf5f2;padding:2px 6px;margin:1px 4px 1px 0}
.timeline{display:grid;gap:8px;max-height:300px;overflow:auto}.event{border:1px solid var(--border);border-radius:6px;background:#fff;padding:10px}.event .time{font-size:12px;color:var(--muted)}.event .action{font-weight:700;margin-top:4px}.event .meta{font-size:12px;color:var(--muted);margin-top:4px}
.check-list{display:grid;gap:8px;max-height:320px;overflow:auto}.check{display:grid;grid-template-columns:76px 1fr;gap:8px;align-items:start;border:1px solid var(--border);border-radius:6px;background:#fff;padding:10px}.status{border-radius:4px;padding:4px 8px;text-align:center;font-size:12px;text-transform:uppercase;background:#eef2f4;color:var(--muted)}.status.ok{background:#d9f0e4;color:#1f6b35}.status.warn,.status.info{background:#f6e6b8;color:#7a5514}.status.fail{background:#f3d1cc;color:#8b2d1f}
@media (max-width:1100px){.layout,.cards,.grid2{grid-template-columns:1fr}}
</style>
</head>
<body>
<header><h1>ProcessGuard Web Console</h1><div class="sub">A real browser-based local control surface. The backend stays outside PGS and reuses the existing toolchain instead of teaching HTTP logic to the guard core.</div></header>
<div class="layout">
<div class="grid" style="gap:16px">
<section class="panel"><h2>Overview</h2><div class="cards"><div class="card"><b id="metric-guards">0</b>Active Guards</div><div class="card"><b id="metric-service">unknown</b>Service</div><div class="card"><b id="metric-ping">unknown</b>PGS Ping</div><div class="card"><b id="metric-doctor">unknown</b>Doctor</div></div><div class="actions"><button onclick="refreshAll()">Refresh All</button><button class="secondary" onclick="pingPgs()">Ping</button><button class="secondary" onclick="serviceStatus()">Service Status</button><button class="secondary" onclick="refreshDoctor()">Doctor</button></div></section>
<section class="panel"><h2>Doctor</h2><div class="hint">Read-only diagnostics for service reachability, trust files, runtime DLLs, and module loader state.</div><div class="check-list" id="doctor-list" style="margin-top:12px"></div></section>
<section class="panel"><h2>Guard Table</h2><div class="hint">This table shows active guards, quarantine state, health checks, and v3 policy fields. It refreshes every 2 seconds.</div><div class="table-wrap" style="margin-top:12px"><table><thead><tr><th>PID</th><th>Guard</th><th>Status</th><th>Path</th><th>Args</th><th>Restarts</th><th>Max</th><th>Health</th><th>Failure</th><th>Alive</th><th>Session</th><th>Hash</th><th>App</th><th>AUMID</th><th>Job</th><th>Window</th><th>Delay</th><th>Backoff</th><th>Hang</th><th>Kill</th></tr></thead><tbody id="guard-body"></tbody></table></div></section>
<section class="panel"><h2>Launch And Protect</h2><div class="grid grid2"><label>Path<input id="start-path" placeholder="C:/apps/worker.exe"></label><label>Command<input id="start-command" placeholder="&quot;C:/apps/worker.exe&quot; --safe"></label><label>Start Args<input id="start-args" placeholder="--mode worker"></label><label>Restart Args<input id="start-restart-args" placeholder="optional"></label><label>Max Restarts<input id="start-max" value="3"></label><label>Restart Window<input id="start-window" placeholder="0"></label><label>Restart Delay<input id="start-delay" placeholder="0"></label><label>Hang Timeout<input id="start-hang" placeholder="0"></label><label>AUMID<input id="start-aumid" placeholder="PackageFamilyName!App"></label><label><input id="start-backoff" type="checkbox"> Restart Backoff</label><label><input id="start-kill" type="checkbox"> Kill On Exit</label><label><input id="start-winapp" type="checkbox"> WindowsApps</label></div><div class="actions"><button onclick="blessStart()">Start + Bless</button></div></section>
</div>
<div class="grid" style="gap:16px">
<section class="panel"><h2>Guard Actions</h2><div class="grid grid2"><label>PID<input id="guard-pid" placeholder="1234"></label><label>Path For Unbless-Path<input id="guard-path" placeholder="optional"></label><label>Max Restarts<input id="guard-max" value="3"></label><label>Restart Args<input id="guard-restart-args" placeholder="optional"></label><label>Restart Window<input id="guard-window" placeholder="0"></label><label>Restart Delay<input id="guard-delay" placeholder="0"></label><label>Hang Timeout<input id="guard-hang" placeholder="0"></label><label>AUMID<input id="guard-aumid" placeholder="PackageFamilyName!App"></label><label><input id="guard-backoff" type="checkbox"> Restart Backoff</label><label><input id="guard-kill" type="checkbox"> Kill On Exit</label><label><input id="guard-winapp" type="checkbox"> WindowsApps</label></div><div class="actions"><button onclick="blessPid()">Bless PID</button><button class="secondary" onclick="setPolicy()">Set Policy</button><button class="secondary" onclick="intentionalExit()">Intentional</button><button class="warn" onclick="unblessGuard()">Unbless</button></div></section>
<section class="panel"><h2>Recovery</h2><div class="grid grid2"><label>Guard ID<input id="guard-id" placeholder="guard id"></label><label>Health JSON<input id="health-json" placeholder='{ "type":"process", "interval_ms":5000, "action":"event" }'></label></div><div class="actions"><button class="secondary" onclick="guardRetry()">Retry Guard</button><button class="warn" onclick="guardClearQuarantine()">Clear Quarantine</button><button onclick="healthSet()">Set Health</button><button class="secondary" onclick="healthGet()">Get Health</button><button class="warn" onclick="healthClear()">Clear Health</button></div></section>
<section class="panel"><h2>Scheduler</h2><div class="grid grid2"><label>Type<input id="sched-type" value="interval"></label><label>Expression<input id="sched-expr" placeholder="300"></label><label>Count<input id="sched-count" placeholder="optional"></label><label>Action<input id="sched-action" placeholder="set-policy 1234|no"></label><label>ID<input id="sched-id" placeholder="schedule id"></label></div><div class="actions"><button onclick="scheduleAdd()">Add</button><button class="secondary" onclick="scheduleList()">List</button><button class="secondary" onclick="scheduleToggle('enable')">Enable</button><button class="secondary" onclick="scheduleToggle('disable')">Disable</button><button class="warn" onclick="scheduleRemove()">Remove</button></div></section>
<section class="panel"><h2>Modules</h2><div class="grid grid2"><label>Name<input id="module-name" placeholder="health"></label><label>Request<input id="module-request" placeholder="op=summary"></label></div><div class="actions"><button class="secondary" onclick="moduleList()">List</button><button onclick="moduleCall()">Call</button></div></section>
<section class="panel"><h2>Metrics</h2><div class="actions"><button class="secondary" onclick="metricsFetch('summary')">Summary</button><button onclick="metricsFetch('json')">JSON</button><button class="secondary" onclick="metricsFetch('prometheus')">Prometheus</button></div></section>
<section class="panel"><h2>State Backup</h2><div class="grid grid2"><label>Max Bytes<input id="backup-max-bytes" placeholder="1048576"></label><label><input id="backup-artifact" type="checkbox" checked> Artifact</label></div><div class="actions"><button class="secondary" onclick="backupStatus()">Status</button><button onclick="backupSnapshot()">Snapshot</button></div></section>
<section class="panel"><h2>Event Log</h2><div class="grid grid2"><label>Limit<input id="eventlog-limit" placeholder="20"></label><label>Source<input id="eventlog-source" placeholder="ProcessGuardService"></label></div><div class="actions"><button class="secondary" onclick="eventlogStatus()">Status</button><button onclick="eventlogRecent()">Recent</button></div></section>
<section class="panel"><h2>Report And Artifacts</h2><div class="grid grid2"><label>Limit<input id="report-limit" placeholder="50"></label><label>Operation ID<input id="operation-id" placeholder="op_..."></label><label>Artifact ID<input id="artifact-id" placeholder="art_..."></label><label>Output Path<input id="artifact-out" placeholder="C:/temp/report.json"></label><label>Artifact TTL Ms<input id="artifact-ttl" placeholder="86400000"></label><label>Max Artifact Bytes<input id="artifact-max-bytes" placeholder="16777216"></label><label>Max Total Bytes<input id="artifact-max-total-bytes" placeholder="268435456"></label><label><input id="artifact-auto-cleanup" type="checkbox" checked> Auto Cleanup</label><label><input id="artifact-verify-status" type="checkbox"> Verify On Status</label></div><div class="actions"><button onclick="reportSnapshot(false)">Snapshot</button><button onclick="reportSnapshot(true)">Snapshot Artifact</button><button class="secondary" onclick="reportBackup(true)">Backup Artifact</button><button class="secondary" onclick="operationStatus()">Operation</button><button class="secondary" onclick="artifactMeta()">Artifact Meta</button><button class="secondary" onclick="artifactStatus(false)">Artifact Status</button><button class="secondary" onclick="artifactStatus(true)">Verify Status</button><button class="secondary" onclick="artifactPolicy()">Policy</button><button onclick="artifactDownload()">Download</button></div></section>
<section class="panel"><h2>Notifications</h2><div class="grid grid2"><label><input id="notify-eventlog" type="checkbox" checked> Event Log</label><label><input id="notify-popup" type="checkbox"> Local Popup</label></div><div class="actions"><button class="secondary" onclick="notifyStatus()">Status</button><button onclick="notifyConfig()">Apply</button></div></section>
<section class="panel"><h2>Service</h2><div class="actions"><button class="secondary" onclick="serviceAction('install')">Install</button><button class="secondary" onclick="serviceAction('start')">Start</button><button class="secondary" onclick="serviceAction('stop')">Stop</button><button class="secondary" onclick="serviceAction('status')">Status</button><button class="warn" onclick="serviceAction('uninstall')">Uninstall</button></div></section>
<section class="panel"><h2>Token</h2><div class="grid grid2"><label>Old Token<input id="token-old" type="password" autocomplete="off" placeholder="optional"></label><label>New Token<input id="token-new" type="password" autocomplete="off" placeholder="new token"></label></div><div class="actions"><button onclick="updateToken()">Update Token</button></div></section>
<section class="panel"><h2>Audit Timeline</h2><div class="actions"><button class="secondary" onclick="refreshAudit()">Refresh Audit</button></div><div class="timeline" id="audit-list"></div></section>
<section class="panel"><h2>Structured Result</h2><div class="hint" id="result-title">Run a module, schedule, report, or artifact action.</div><div class="result" id="result-body"></div></section>
<section class="panel"><h2>Activity Log</h2><pre class="log" id="log-box"></pre></section>
</div>
</div>
<script>
window.PGS_CSRF_TOKEN="__PGS_CSRF_TOKEN__";
const logBox=document.getElementById('log-box');const guardBody=document.getElementById('guard-body');const auditList=document.getElementById('audit-list');const doctorList=document.getElementById('doctor-list');const resultTitle=document.getElementById('result-title');const resultBody=document.getElementById('result-body');
function logLine(m){const t=new Date().toLocaleTimeString();logBox.textContent+=`[${t}] ${m}\n`;logBox.scrollTop=logBox.scrollHeight}
async function api(path,options={}){const hdrs=Object.assign({'Content-Type':'application/json'},options.headers||{});if(window.PGS_CSRF_TOKEN){hdrs['X-PGS-CSRF']=window.PGS_CSRF_TOKEN}const r=await fetch(path,Object.assign({},options,{headers:hdrs,credentials:'same-origin'}));const text=await r.text();let data={};try{data=text?JSON.parse(text):{}}catch{data={ok:false,message:text}}if(!r.ok||data.ok===false){throw new Error(data.message||text||`request failed: ${r.status}`)}return data}
function guardPayload(){const p={pid:document.getElementById('guard-pid').value.trim(),path:document.getElementById('guard-path').value.trim(),max_restarts:document.getElementById('guard-max').value.trim(),restart_args:document.getElementById('guard-restart-args').value.trim(),restart_window:document.getElementById('guard-window').value.trim(),restart_delay:document.getElementById('guard-delay').value.trim(),hang_timeout:document.getElementById('guard-hang').value.trim()};if(document.getElementById('guard-backoff').checked)p.restart_backoff='1';if(document.getElementById('guard-kill').checked)p.kill_on_exit='1';if(document.getElementById('guard-winapp').checked)p.winapp='1';const a=document.getElementById('guard-aumid').value.trim();if(a)p.aumid=a;return p}
function appendCell(row,value,cls=''){const cell=document.createElement('td');if(cls){cell.className=cls}cell.textContent=value==null?'':String(value);row.appendChild(cell)}
function renderResultTitle(title){resultTitle.textContent=title||'Result'}
function renderTextResult(title,text){renderResultTitle(title);const pre=document.createElement('pre');pre.textContent=text||'';resultBody.replaceChildren(pre)}
function valueText(v){if(v==null)return'';if(typeof v==='object')return JSON.stringify(v);return String(v)}
function renderKvResult(title,obj){renderResultTitle(title);const box=document.createElement('div');box.className='kv';for(const [k,v] of Object.entries(obj||{})){const key=document.createElement('div');key.textContent=k;const val=document.createElement('div');val.textContent=valueText(v);box.append(key,val)}resultBody.replaceChildren(box)}
function renderRowsResult(title,rows){renderResultTitle(title);if(!rows||!rows.length){resultBody.replaceChildren(Object.assign(document.createElement('div'),{className:'hint',textContent:'No rows.'}));return}const table=document.createElement('table');const keys=[...new Set(rows.flatMap(r=>Object.keys(r)))];const thead=document.createElement('thead');const hr=document.createElement('tr');for(const k of keys){const th=document.createElement('th');th.textContent=k;hr.appendChild(th)}thead.appendChild(hr);const tbody=document.createElement('tbody');for(const r of rows){const tr=document.createElement('tr');for(const k of keys){appendCell(tr,valueText(r[k]))}tbody.appendChild(tr)}table.append(thead,tbody);resultBody.replaceChildren(table)}
function parseKvLine(line){let text=String(line||'').trim();if(!text)return null;text=text.replace(/^OK\s+/,'');const obj={};for(const part of text.split(/[;\t ]+/)){const i=part.indexOf('=');if(i>0){obj[part.slice(0,i)]=part.slice(i+1)}}return Object.keys(obj).length?obj:null}
function parseStdoutRows(stdout){return String(stdout||'').split(/\r?\n/).map(parseKvLine).filter(Boolean)}
function renderStdoutResult(title,stdout){const rows=parseStdoutRows(stdout);if(rows.length){fillOperationArtifactIds(rows[0]);renderRowsResult(title,rows)}else{renderTextResult(title,stdout||'')}}
function fillOperationArtifactIds(d){if(d.operation_id){document.getElementById('operation-id').value=d.operation_id}if(d.artifact_id){document.getElementById('artifact-id').value=d.artifact_id}}
function renderGuards(items){const rows=[];for(const i of items){const row=document.createElement('tr');const failure=[i.last_failure_code,i.last_failure].filter(v=>v&&v!=='-').join(' ');appendCell(row,i.pid);appendCell(row,i.guard_id);appendCell(row,i.status);appendCell(row,i.path,'path');appendCell(row,i.restart_args);appendCell(row,i.restart_count||'0');appendCell(row,i.max_restarts);appendCell(row,i.health_status||'disabled');appendCell(row,failure);appendCell(row,i.alive);appendCell(row,i.session);appendCell(row,i.hash);appendCell(row,i.app_kind||'win32');appendCell(row,i.aumid);appendCell(row,i.job_attached);appendCell(row,i.restart_window);appendCell(row,i.restart_delay);appendCell(row,i.backoff);appendCell(row,i.hang_timeout);appendCell(row,i.kill_on_exit);rows.push(row)}guardBody.replaceChildren(...rows)}
function renderDoctor(checks){if(!Array.isArray(checks)||!checks.length){doctorList.replaceChildren(Object.assign(document.createElement('div'),{className:'hint',textContent:'Doctor has not run yet.'}));return}let worst='ok';const nodes=[];for(const c of checks){const item=document.createElement('div');item.className='check';const badge=document.createElement('div');const status=String(c.status||'info').toLowerCase();badge.className=`status ${status}`;badge.textContent=status;const body=document.createElement('div');const title=document.createElement('div');title.textContent=c.id||'check';title.style.fontWeight='700';const msg=document.createElement('div');msg.className='hint';msg.textContent=c.message||'';body.append(title,msg);item.append(badge,body);nodes.push(item);if(status==='fail'){worst='fail'}else if(status==='warn'&&worst==='ok'){worst='warn'}}doctorList.replaceChildren(...nodes);document.getElementById('metric-doctor').textContent=worst}
function renderAudit(events,enabled){if(!enabled){auditList.replaceChildren(Object.assign(document.createElement('div'),{className:'hint',textContent:'Audit log is not configured for this server.'}));return}if(!events.length){auditList.replaceChildren(Object.assign(document.createElement('div'),{className:'hint',textContent:'No audit events yet.'}));return}const nodes=[];for(const e of events.slice().reverse()){const item=document.createElement('div');item.className='event';const time=document.createElement('div');time.className='time';time.textContent=e.time||'';const action=document.createElement('div');action.className='action';action.textContent=e.action||e.raw||'';const meta=document.createElement('div');meta.className='meta';meta.textContent=`user ${e.user||'-'} from ${e.from||'-'}`;item.append(time,action,meta);nodes.push(item)}auditList.replaceChildren(...nodes)}
async function refreshAudit(){try{const d=await api('/api/audit?limit=80',{headers:{'Content-Type':'application/json'}});renderAudit(Array.isArray(d.events)?d.events:[],d.enabled!==false)}catch(e){auditList.replaceChildren(Object.assign(document.createElement('div'),{className:'hint',textContent:`audit unavailable: ${e.message}`}))}}
async function refreshDoctor(){try{const d=await api('/api/doctor');renderDoctor(d.checks);logLine('doctor completed')}catch(e){document.getElementById('metric-doctor').textContent='error';doctorList.replaceChildren(Object.assign(document.createElement('div'),{className:'hint',textContent:`doctor unavailable: ${e.message}`}));logLine(`doctor failed: ${e.message}`)}}
async function refreshAll(){await Promise.allSettled([pingPgs(),serviceStatus(),refreshGuards(),refreshAudit(),refreshDoctor()])}
async function pingPgs(){try{const d=await api('/api/ping');document.getElementById('metric-ping').textContent='ok';logLine(d.message||'ping ok')}catch(e){document.getElementById('metric-ping').textContent='down';logLine(`ping failed: ${e.message}`)}}
async function serviceStatus(){try{const d=await api('/api/service/status');document.getElementById('metric-service').textContent=d.state||'unknown';logLine(`service status: ${d.state||d.message}`)}catch(e){document.getElementById('metric-service').textContent='error';logLine(`service status failed: ${e.message}`)}}
async function refreshGuards(){try{const d=await api('/api/guards');const items=Array.isArray(d.guards)?d.guards:[];document.getElementById('metric-guards').textContent=String(items.length);renderGuards(items)}catch(e){logLine(`guard refresh failed: ${e.message}`)}}
async function blessPid(){try{const d=await api('/api/bless',{method:'POST',body:JSON.stringify(guardPayload())});logLine(d.message||'bless ok');refreshGuards()}catch(e){logLine(`bless failed: ${e.message}`)}}
async function blessStart(){const body={path:document.getElementById('start-path').value.trim(),command:document.getElementById('start-command').value.trim(),start_args:document.getElementById('start-args').value.trim(),restart_args:document.getElementById('start-restart-args').value.trim(),max_restarts:document.getElementById('start-max').value.trim(),restart_window:document.getElementById('start-window').value.trim(),restart_delay:document.getElementById('start-delay').value.trim(),hang_timeout:document.getElementById('start-hang').value.trim()};if(document.getElementById('start-backoff').checked)body.restart_backoff='1';if(document.getElementById('start-kill').checked)body.kill_on_exit='1';if(document.getElementById('start-winapp').checked)body.winapp='1';const a=document.getElementById('start-aumid').value.trim();if(a)body.aumid=a;try{const d=await api('/api/bless-start',{method:'POST',body:JSON.stringify(body)});logLine(d.message||'bless-start ok');refreshGuards()}catch(e){logLine(`bless-start failed: ${e.message}`)}}
async function setPolicy(){try{const d=await api('/api/policy',{method:'POST',body:JSON.stringify(guardPayload())});logLine(d.message||'policy updated');refreshGuards()}catch(e){logLine(`policy failed: ${e.message}`)}}
async function unblessGuard(){try{const d=await api('/api/unbless',{method:'POST',body:JSON.stringify(guardPayload())});logLine(d.message||'unbless ok');refreshGuards()}catch(e){logLine(`unbless failed: ${e.message}`)}}
async function intentionalExit(){try{const d=await api('/api/intentional',{method:'POST',body:JSON.stringify(guardPayload())});logLine(d.message||'intentional marked');refreshGuards()}catch(e){logLine(`intentional failed: ${e.message}`)}}
async function guardRetry(){const id=document.getElementById('guard-id').value.trim();try{const d=await api('/api/guard/retry',{method:'POST',body:JSON.stringify({id})});logLine(d.stdout||d.message||'guard retry ok');refreshGuards()}catch(e){logLine(`guard retry failed: ${e.message}`)}}
async function guardClearQuarantine(){const id=document.getElementById('guard-id').value.trim();try{const d=await api('/api/guard/clear-quarantine',{method:'POST',body:JSON.stringify({id})});logLine(d.stdout||d.message||'quarantine cleared');refreshGuards()}catch(e){logLine(`clear quarantine failed: ${e.message}`)}}
async function healthSet(){const body={pid:document.getElementById('guard-pid').value.trim(),config_json:document.getElementById('health-json').value.trim()};try{const d=await api('/api/health-check/set',{method:'POST',body:JSON.stringify(body)});logLine(d.stdout||d.message||'health set');refreshGuards()}catch(e){logLine(`health set failed: ${e.message}`)}}
async function healthGet(){const pid=document.getElementById('guard-pid').value.trim();try{const d=await api(`/api/health-check/get?pid=${encodeURIComponent(pid)}`);logLine(d.stdout||d.message||'health get ok')}catch(e){logLine(`health get failed: ${e.message}`)}}
async function healthClear(){const body={pid:document.getElementById('guard-pid').value.trim()};try{const d=await api('/api/health-check/clear',{method:'POST',body:JSON.stringify(body)});logLine(d.stdout||d.message||'health cleared');refreshGuards()}catch(e){logLine(`health clear failed: ${e.message}`)}}
async function updateToken(){const body={old_token:document.getElementById('token-old').value.trim(),new_token:document.getElementById('token-new').value.trim()};try{const d=await api('/api/token',{method:'POST',body:JSON.stringify(body)});logLine(d.message||'token updated')}catch(e){logLine(`token update failed: ${e.message}`)}}
async function serviceAction(action){try{const d=await api(`/api/service/${action}`,{method:action==='status'?'GET':'POST'});logLine(d.message||`${action} ok`);serviceStatus()}catch(e){logLine(`service ${action} failed: ${e.message}`)}}
async function moduleList(){try{const d=await api('/api/modules');renderStdoutResult('Modules',d.stdout||d.message||'');logLine(d.stdout||d.message||'modules listed')}catch(e){logLine(`module list failed: ${e.message}`)}}
async function moduleCall(){const body={name:document.getElementById('module-name').value.trim(),request:document.getElementById('module-request').value.trim()};try{const d=await api('/api/module/call',{method:'POST',body:JSON.stringify(body)});renderStdoutResult(`Module ${body.name}`,d.stdout||d.message||'');logLine(d.stdout||d.message||'module call ok')}catch(e){logLine(`module call failed: ${e.message}`)}}
async function metricsFetch(format){try{const d=await api(`/api/metrics?format=${encodeURIComponent(format)}`);if(d.metrics&&Object.keys(d.metrics).length){renderKvResult('Metrics',d.metrics)}else if(d.text){renderTextResult(`Metrics ${format}`,d.text)}else{renderStdoutResult(`Metrics ${format}`,d.summary||d.stdout||'')}logLine(d.text||d.summary||d.stdout||'metrics ok')}catch(e){logLine(`metrics ${format} failed: ${e.message}`)}}
async function backupStatus(){try{const d=await api('/api/backup/status');renderKvResult('Backup Status',{data_dir:d.data_dir,stdout:d.stdout});logLine(d.data_dir?`backup data_dir=${d.data_dir}`:(d.stdout||'backup status ok'))}catch(e){logLine(`backup status failed: ${e.message}`)}}
async function backupSnapshot(){const body={artifact:document.getElementById('backup-artifact').checked?'1':'0',max_bytes:document.getElementById('backup-max-bytes').value.trim()};try{const d=await api('/api/backup/snapshot',{method:'POST',body:JSON.stringify(body)});fillOperationArtifactIds(d);renderKvResult('Backup Snapshot',{operation_id:d.operation_id,artifact_id:d.artifact_id,stdout:d.stdout});let msg=d.stdout||'backup snapshot ok';if(d.operation_id||d.artifact_id){msg+=`\noperation_id=${d.operation_id||''}; artifact_id=${d.artifact_id||''}`}logLine(msg)}catch(e){logLine(`backup snapshot failed: ${e.message}`)}}
async function eventlogStatus(){try{const d=await api('/api/eventlog/status');renderStdoutResult('Event Log Status',d.stdout||d.message||'');logLine(d.stdout||d.message||'eventlog status ok')}catch(e){logLine(`eventlog status failed: ${e.message}`)}}
async function eventlogRecent(){const limit=document.getElementById('eventlog-limit').value.trim();const source=document.getElementById('eventlog-source').value.trim();try{const d=await api(`/api/eventlog/recent?limit=${encodeURIComponent(limit)}&source=${encodeURIComponent(source)}`);renderStdoutResult('Event Log Recent',d.stdout||d.message||'');logLine(d.stdout||d.message||'eventlog recent ok')}catch(e){logLine(`eventlog recent failed: ${e.message}`)}}
async function notifyStatus(){try{const d=await api('/api/notify/status');renderStdoutResult('Notify Status',d.stdout||d.message||'');logLine(d.stdout||d.message||'notify status ok')}catch(e){logLine(`notify status failed: ${e.message}`)}}
async function notifyConfig(){const body={eventlog:document.getElementById('notify-eventlog').checked?'1':'0',popup:document.getElementById('notify-popup').checked?'1':'0'};try{const d=await api('/api/notify/config',{method:'POST',body:JSON.stringify(body)});renderStdoutResult('Notify Config',d.stdout||d.message||'');logLine(d.stdout||d.message||'notify config ok')}catch(e){logLine(`notify config failed: ${e.message}`)}}
async function reportSnapshot(artifact){const body={kind:'snapshot',artifact:artifact?'1':'0',limit:document.getElementById('report-limit').value.trim()};try{const d=await api('/api/report',{method:'POST',body:JSON.stringify(body)});renderStdoutResult('Report Snapshot',d.stdout||d.message||'');logLine(d.stdout||d.message||'report snapshot ok')}catch(e){logLine(`report snapshot failed: ${e.message}`)}}
async function reportBackup(artifact){const body={kind:'backup',artifact:artifact?'1':'0',limit:document.getElementById('report-limit').value.trim()};try{const d=await api('/api/report',{method:'POST',body:JSON.stringify(body)});renderStdoutResult('Report Backup',d.stdout||d.message||'');logLine(d.stdout||d.message||'report backup ok')}catch(e){logLine(`report backup failed: ${e.message}`)}}
async function operationStatus(){const id=document.getElementById('operation-id').value.trim();try{const d=await api(`/api/operation/status?id=${encodeURIComponent(id)}`);if(d.operation&&Object.keys(d.operation).length){renderKvResult('Operation Status',d.operation)}else{renderStdoutResult('Operation Status',d.stdout||d.message||'')}logLine(d.stdout||JSON.stringify(d.operation)||d.message||'operation ok')}catch(e){logLine(`operation status failed: ${e.message}`)}}
async function artifactMeta(){const id=document.getElementById('artifact-id').value.trim();try{const d=await api(`/api/artifact/meta?id=${encodeURIComponent(id)}`);if(d.artifact&&Object.keys(d.artifact).length){renderKvResult('Artifact Meta',d.artifact)}else{renderStdoutResult('Artifact Meta',d.stdout||d.message||'')}logLine(d.stdout||JSON.stringify(d.artifact)||d.message||'artifact meta ok')}catch(e){logLine(`artifact meta failed: ${e.message}`)}}
async function artifactStatus(verify){try{const d=await api(`/api/artifact/status?verify=${verify?'1':'0'}`);if(d.status&&Object.keys(d.status).length){renderKvResult('Artifact Status',d.status)}else{renderStdoutResult('Artifact Status',d.stdout||d.message||'')}logLine(d.stdout||JSON.stringify(d.status)||d.message||'artifact status ok')}catch(e){logLine(`artifact status failed: ${e.message}`)}}
async function artifactPolicy(){const body={ttl_ms:document.getElementById('artifact-ttl').value.trim(),max_artifact_bytes:document.getElementById('artifact-max-bytes').value.trim(),max_total_bytes:document.getElementById('artifact-max-total-bytes').value.trim(),auto_cleanup:document.getElementById('artifact-auto-cleanup').checked?'1':'0',verify_on_status:document.getElementById('artifact-verify-status').checked?'1':'0'};try{const d=await api('/api/artifact/policy',{method:'POST',body:JSON.stringify(body)});if(d.policy&&Object.keys(d.policy).length){renderKvResult('Artifact Policy',d.policy)}else{renderStdoutResult('Artifact Policy',d.stdout||d.message||'')}logLine(d.stdout||JSON.stringify(d.policy)||d.message||'artifact policy ok')}catch(e){logLine(`artifact policy failed: ${e.message}`)}}
async function artifactDownload(){const body={id:document.getElementById('artifact-id').value.trim(),out:document.getElementById('artifact-out').value.trim()};try{const d=await api('/api/artifact/download',{method:'POST',body:JSON.stringify(body)});renderStdoutResult('Artifact Download',d.stdout||d.message||'');logLine(d.stdout||d.message||'artifact downloaded')}catch(e){logLine(`artifact download failed: ${e.message}`)}}
async function scheduleList(){try{const d=await api('/api/schedule');renderStdoutResult('Schedules',d.stdout||d.message||'');logLine(d.stdout||d.message||'schedule listed')}catch(e){logLine(`schedule list failed: ${e.message}`)}}
async function scheduleAdd(){const body={type:document.getElementById('sched-type').value.trim(),expr:document.getElementById('sched-expr').value.trim(),count:document.getElementById('sched-count').value.trim(),action:document.getElementById('sched-action').value.trim()};try{const d=await api('/api/schedule',{method:'POST',body:JSON.stringify(body)});renderStdoutResult('Schedule Add',d.stdout||d.message||'');logLine(d.stdout||d.message||'schedule added')}catch(e){logLine(`schedule add failed: ${e.message}`)}}
async function scheduleToggle(action){const id=document.getElementById('sched-id').value.trim();try{const d=await api(`/api/schedule/${action}`,{method:'POST',body:JSON.stringify({id})});renderStdoutResult(`Schedule ${action}`,d.stdout||d.message||'');logLine(d.stdout||d.message||`schedule ${action} ok`)}catch(e){logLine(`schedule ${action} failed: ${e.message}`)}}
async function scheduleRemove(){const id=document.getElementById('sched-id').value.trim();try{const d=await api('/api/schedule/remove',{method:'POST',body:JSON.stringify({id})});renderStdoutResult('Schedule Remove',d.stdout||d.message||'');logLine(d.stdout||d.message||'schedule removed')}catch(e){logLine(`schedule remove failed: ${e.message}`)}}
setInterval(refreshGuards,2000);setInterval(refreshAudit,5000);setInterval(refreshDoctor,10000);refreshAll();
</script>
</body></html>
)HTML");
}
} // namespace


// Minimum RBAC role required for a route path.
int WebServer::roleRequired(const QString &route)
{
    // admin-only: token rotation + service lifecycle
    if (route == "/api/audit" ||
        route == "/api/token" || route.startsWith("/api/service/install") ||
        route.startsWith("/api/service/uninstall") ||
        route.startsWith("/api/service/start") ||
        route.startsWith("/api/service/stop"))
        return static_cast<int>(Role::Admin);
    // operator: guard mutations
    if (route.startsWith("/api/bless") || route == "/api/policy" ||
        route == "/api/unbless" || route == "/api/intentional" ||
        route.startsWith("/api/guard/") || route.startsWith("/api/health-check") ||
        route == "/api/notify/config" || route.startsWith("/api/report") ||
        route.startsWith("/api/operation") || route.startsWith("/api/artifact") ||
        route.startsWith("/api/backup") || route.startsWith("/api/eventlog") ||
        route.startsWith("/api/module") || route.startsWith("/api/schedule"))
        return static_cast<int>(Role::Operator);
    // everything else (health/ping/guards/guard/service/status/cluster/metrics) = viewer
    return static_cast<int>(Role::Viewer);
}

WebServer::WebServer(Options options, QObject *parent)
    : QObject(parent), m_options(std::move(options)), m_server(new PgsHttp::Server(this))
{
    // Generate per-process browser secrets. Local mode keeps the capability
    // token in an HttpOnly SameSite cookie and exposes only a CSRF nonce to
    // page JavaScript. Remote mode uses Basic/RBAC plus the same CSRF nonce.
    QByteArray bytes(32, '\0');
    for (int i = 0; i < bytes.size(); ++i)
    {
        bytes[i] = static_cast<char>(QRandomGenerator::global()->generate() & 0xFF);
    }
    m_apiToken = QString::fromLatin1(QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex());
    for (int i = 0; i < bytes.size(); ++i)
    {
        bytes[i] = static_cast<char>(QRandomGenerator::global()->generate() & 0xFF);
    }
    m_csrfToken = QString::fromLatin1(QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex());
}

bool WebServer::isLocalPageRequestAllowed(const PgsHttp::Request &request) const
{
    if (m_options.remote)
    {
        return true;
    }
    const QString host = request.value("Host").trimmed();
    const QString expectedHost = hostWithPort(m_options.bindAddress, m_options.httpPort);
    const QString expectedAlt = QStringLiteral("localhost:%1").arg(m_options.httpPort);
    if (!host.isEmpty() && host != expectedHost && host != expectedAlt)
    {
        return false;
    }
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
    const QString referer = request.value("Referer").trimmed();
    if (!referer.isEmpty())
    {
        const QString selfOrigin = QStringLiteral("http://%1").arg(expectedHost);
        const QString selfOriginAlt = QStringLiteral("http://%1").arg(expectedAlt);
        if (!referer.startsWith(selfOrigin, Qt::CaseInsensitive) &&
            !referer.startsWith(selfOriginAlt, Qt::CaseInsensitive))
        {
            return false;
        }
    }
    return true;
}

// Authorize a local /api/* request with an HttpOnly SameSite session cookie.
// Unsafe methods additionally require the page-readable CSRF nonce and
// same-origin browser headers. The Web API bearer is never exposed to JS.
bool WebServer::isRequestAuthorized(const PgsHttp::Request &request) const
{
    const QString session = cookieValue(request, QStringLiteral("pgs_local_session"));
    if (session.isEmpty() || !constantTimeEquals(session, m_apiToken))
    {
        return false;
    }

    // Host header must refer to the loopback address we listen on.
    const QString host = request.value("Host").trimmed();
    const QString expectedHost = hostWithPort(m_options.bindAddress, m_options.httpPort);
    const QString expectedAlt = QStringLiteral("localhost:%1").arg(m_options.httpPort);
    if (!host.isEmpty() && host != expectedHost && host != expectedAlt)
    {
        return false;
    }

    if (!isUnsafeMethod(request.method()))
    {
        return true;
    }
    if (!isJsonRequest(request))
    {
        return false;
    }
    if (!constantTimeEquals(request.value("X-PGS-CSRF").trimmed(), m_csrfToken))
    {
        return false;
    }

    const QString origin = request.value("Origin").trimmed();
    const QString referer = request.value("Referer").trimmed();
    const QString selfOrigin = QStringLiteral("http://%1").arg(expectedHost);
    const QString selfOriginAlt = QStringLiteral("http://%1").arg(expectedAlt);
    const QString secFetchSite = request.value("Sec-Fetch-Site").trimmed().toLower();
    if (!secFetchSite.isEmpty() &&
        secFetchSite != QLatin1String("same-origin") &&
        secFetchSite != QLatin1String("none"))
    {
        return false;
    }
    if (!origin.isEmpty())
    {
        return origin == selfOrigin || origin == selfOriginAlt;
    }
    if (!referer.isEmpty())
    {
        return referer.startsWith(selfOrigin, Qt::CaseInsensitive) ||
               referer.startsWith(selfOriginAlt, Qt::CaseInsensitive);
    }
    return true;
}

// Served HTML sets the local HttpOnly session cookie and embeds only the CSRF
// nonce. PGS auth stays server-side in WebServer.
QHttpServerResponse WebServer::handleIndexHtml() const
{
    QString html = indexHtml();
    html.replace(QStringLiteral("__PGS_CSRF_TOKEN__"), m_csrfToken);
    QHttpServerResponse response(QByteArray("text/html; charset=utf-8"), html.toUtf8());
    QHttpHeaders headers = response.headers();
    if (!m_options.remote)
    {
        headers.replaceOrAppend(QByteArrayLiteral("Set-Cookie"), makeLocalSessionCookie(m_apiToken).toLatin1());
    }
    headers.replaceOrAppend(QByteArrayLiteral("Cache-Control"), QByteArrayLiteral("no-store"));
    headers.replaceOrAppend(QByteArrayLiteral("X-Content-Type-Options"), QByteArrayLiteral("nosniff"));
    headers.replaceOrAppend(QByteArrayLiteral("Content-Security-Policy"), QByteArrayLiteral("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"));
    response.setHeaders(std::move(headers));
    return response;
}
bool WebServer::start()
{
    using Method = QHttpServerRequest::Method;
    const bool trace = !qgetenv("PGS_WEB_TRACE").isEmpty();
    if (trace)
        QTextStream(stderr) << "PGS web start entered\n" << Qt::flush;
    if (m_options.remote)
    {
        if (!loadUsers() || !setupTls())
        {
            return false;
        }
        if (m_options.auditLogPath.trimmed().isEmpty())
        {
            return false;
        }
        m_auditFile = new QFile(m_options.auditLogPath, this);
        if (!m_auditFile->open(QIODevice::Append | QIODevice::Text))
        {
            return false;
        }
    }
    else if (!isLoopbackBind(m_options.bindAddress))
    {
        return false;
    }

    auto authorizeApi = [this](const PgsHttp::Request &request, const QString &route, QString *outUser = nullptr) {
        QString user;
        const bool authorized = m_options.remote
            ? (authenticateAndAuthorize(request, roleRequired(route), user) &&
               authorizeRemoteCsrf(request, m_csrfToken))
            : isRequestAuthorized(request);
        if (!authorized)
        {
            return false;
        }
        if (m_options.remote)
        {
            audit(user, QStringLiteral("%1 %2").arg(methodName(request.method()), route), sourceAddress(request));
        }
        if (outUser)
        {
            *outUser = user;
        }
        return true;
    };

    QTcpServer *listener = nullptr;
    if (m_options.remote)
    {
        listener = m_sslServer;
    }
    else
    {
        if (!m_tcpServer)
        {
            m_tcpServer = new QTcpServer(this);
        }
        listener = m_tcpServer;
    }
    const QHostAddress bindAddress = parseBindAddress(m_options.bindAddress);
    if (trace)
        QTextStream(stderr) << "PGS web parsed bind address " << bindAddress.toString() << "\n" << Qt::flush;
    if (bindAddress.isNull())
    {
        return false;
    }
    if (trace && listener)
    {
        QObject::connect(listener, &QTcpServer::newConnection, this, []() {
            QTextStream(stderr) << "PGS web listener newConnection\n" << Qt::flush;
        });
        QObject::connect(listener, &QTcpServer::acceptError, this, [](QAbstractSocket::SocketError error) {
            QTextStream(stderr) << "PGS web listener acceptError=" << static_cast<int>(error) << "\n" << Qt::flush;
        });
    }
    if (trace)
        QTextStream(stderr) << "PGS web listen begin port=" << m_options.httpPort << "\n" << Qt::flush;
    if (!listener || !listener->listen(bindAddress, m_options.httpPort))
    {
        return false;
    }
    if (trace)
        QTextStream(stderr) << "PGS web listen ok\n" << Qt::flush;
    if (trace)
        QTextStream(stderr) << "PGS web binding routes\n" << Qt::flush;
    if (!m_server->bind(listener, [this, authorizeApi](const PgsHttp::Request &request) {
            using Method = QHttpServerRequest::Method;
            const QString path = request.url().path();
            if (path == QStringLiteral("/") && request.method() == Method::Get)
            {
                if (!qgetenv("PGS_WEB_TRACE").isEmpty())
                    QTextStream(stderr) << "PGS web route / entered\n";
                if (m_options.remote)
                {
                    if (!authorizeApi(request, "/"))
                        return jsonUnauthorized();
                }
                else if (!isLocalPageRequestAllowed(request))
                {
                    return jsonUnauthorized();
                }
                return handleIndexHtml();
            }
            if (path == QStringLiteral("/api/health") && request.method() == Method::Get)
            {
                if (!authorizeApi(request, "/api/health")) return jsonUnauthorized();
                return handleHealth();
            }
            if (path == QStringLiteral("/api/doctor") && request.method() == Method::Get)
            {
                if (!authorizeApi(request, "/api/doctor")) return jsonUnauthorized();
                return handleDoctor();
            }
            if (path == QStringLiteral("/api/cluster/health") && request.method() == Method::Get)
            {
                if (!authorizeApi(request, "/api/cluster/health")) return jsonUnauthorized();
                return handleClusterHealth();
            }
            if (path == QStringLiteral("/api/ping") && request.method() == Method::Get)
            {
                if (!authorizeApi(request, "/api/ping")) return jsonUnauthorized();
                return handlePing();
            }
            if (path == QStringLiteral("/api/guards") && request.method() == Method::Get)
            {
                if (!authorizeApi(request, "/api/guards")) return jsonUnauthorized();
                return handleGuards();
            }
            if (path == QStringLiteral("/api/guard") && request.method() == Method::Get)
            {
                if (!authorizeApi(request, "/api/guard")) return jsonUnauthorized();
                return handleGuard(request);
            }
            if (path == QStringLiteral("/api/bless") && request.method() == Method::Post)
            {
                if (!authorizeApi(request, "/api/bless")) return jsonUnauthorized();
                return handleBless(request);
            }
            if (path == QStringLiteral("/api/bless-start") && request.method() == Method::Post)
            {
                if (!authorizeApi(request, "/api/bless-start")) return jsonUnauthorized();
                return handleBlessStart(request);
            }
            if (path == QStringLiteral("/api/policy") && request.method() == Method::Post)
            {
                if (!authorizeApi(request, "/api/policy")) return jsonUnauthorized();
                return handlePolicy(request);
            }
            if (path == QStringLiteral("/api/unbless") && request.method() == Method::Post)
            {
                if (!authorizeApi(request, "/api/unbless")) return jsonUnauthorized();
                return handleUnbless(request);
            }
            if (path == QStringLiteral("/api/intentional") && request.method() == Method::Post)
            {
                if (!authorizeApi(request, "/api/intentional")) return jsonUnauthorized();
                return handleIntentional(request);
            }
            if (path == QStringLiteral("/api/guard/retry") && request.method() == Method::Post)
            {
                if (!authorizeApi(request, "/api/guard/retry")) return jsonUnauthorized();
                return handleGuardControl(request, QStringLiteral("retry"));
            }
            if (path == QStringLiteral("/api/guard/clear-quarantine") && request.method() == Method::Post)
            {
                if (!authorizeApi(request, "/api/guard/clear-quarantine")) return jsonUnauthorized();
                return handleGuardControl(request, QStringLiteral("clear-quarantine"));
            }
            if (path == QStringLiteral("/api/health-check/get") && request.method() == Method::Get)
            {
                if (!authorizeApi(request, "/api/health-check/get")) return jsonUnauthorized();
                return handleHealthCheck(request, QStringLiteral("get"));
            }
            if (path == QStringLiteral("/api/health-check/set") && request.method() == Method::Post)
            {
                if (!authorizeApi(request, "/api/health-check/set")) return jsonUnauthorized();
                return handleHealthCheck(request, QStringLiteral("set"));
            }
            if (path == QStringLiteral("/api/health-check/clear") && request.method() == Method::Post)
            {
                if (!authorizeApi(request, "/api/health-check/clear")) return jsonUnauthorized();
                return handleHealthCheck(request, QStringLiteral("clear"));
            }
            if (path == QStringLiteral("/api/token") && request.method() == Method::Post)
            {
                if (!authorizeApi(request, "/api/token")) return jsonUnauthorized();
                return handleTokenUpdate(request);
            }
            if (path == QStringLiteral("/api/audit") && request.method() == Method::Get)
            {
                if (!authorizeApi(request, "/api/audit")) return jsonUnauthorized();
                return handleAudit(request);
            }
            if (path == QStringLiteral("/api/modules") && request.method() == Method::Get)
            {
                if (!authorizeApi(request, "/api/modules")) return jsonUnauthorized();
                return handleModules();
            }
            if (path == QStringLiteral("/api/module/call") && request.method() == Method::Post)
            {
                if (!authorizeApi(request, "/api/module/call")) return jsonUnauthorized();
                return handleModuleCall(request);
            }
            if (path == QStringLiteral("/api/metrics") && request.method() == Method::Get)
            {
                if (!authorizeApi(request, "/api/metrics")) return jsonUnauthorized();
                return handleMetrics(request);
            }
            if (path == QStringLiteral("/api/backup/status") && request.method() == Method::Get)
            {
                if (!authorizeApi(request, "/api/backup/status")) return jsonUnauthorized();
                return handleBackupStatus();
            }
            if (path == QStringLiteral("/api/backup/snapshot") && request.method() == Method::Post)
            {
                if (!authorizeApi(request, "/api/backup/snapshot")) return jsonUnauthorized();
                return handleBackupSnapshot(request);
            }
            if (path == QStringLiteral("/api/eventlog/status") && request.method() == Method::Get)
            {
                if (!authorizeApi(request, "/api/eventlog/status")) return jsonUnauthorized();
                return handleEventlogStatus();
            }
            if (path == QStringLiteral("/api/eventlog/recent") && request.method() == Method::Get)
            {
                if (!authorizeApi(request, "/api/eventlog/recent")) return jsonUnauthorized();
                return handleEventlogRecent(request);
            }
            if (path == QStringLiteral("/api/notify/status") && request.method() == Method::Get)
            {
                if (!authorizeApi(request, "/api/notify/status")) return jsonUnauthorized();
                return handleNotifyStatus();
            }
            if (path == QStringLiteral("/api/notify/config") && request.method() == Method::Post)
            {
                if (!authorizeApi(request, "/api/notify/config")) return jsonUnauthorized();
                return handleNotifyConfig(request);
            }
            if (path == QStringLiteral("/api/report") && request.method() == Method::Post)
            {
                if (!authorizeApi(request, "/api/report")) return jsonUnauthorized();
                return handleReport(request);
            }
            if (path == QStringLiteral("/api/operation/status") && request.method() == Method::Get)
            {
                if (!authorizeApi(request, "/api/operation/status")) return jsonUnauthorized();
                return handleOperationStatus(request);
            }
            if (path == QStringLiteral("/api/artifact/meta") && request.method() == Method::Get)
            {
                if (!authorizeApi(request, "/api/artifact/meta")) return jsonUnauthorized();
                return handleArtifactMeta(request);
            }
            if (path == QStringLiteral("/api/artifact/status") && request.method() == Method::Get)
            {
                if (!authorizeApi(request, "/api/artifact/status")) return jsonUnauthorized();
                return handleArtifactStatus(request);
            }
            if (path == QStringLiteral("/api/artifact/policy") && request.method() == Method::Post)
            {
                if (!authorizeApi(request, "/api/artifact/policy")) return jsonUnauthorized();
                return handleArtifactPolicy(request);
            }
            if (path == QStringLiteral("/api/artifact/download") && request.method() == Method::Post)
            {
                if (!authorizeApi(request, "/api/artifact/download")) return jsonUnauthorized();
                return handleArtifactDownload(request);
            }
            if (path == QStringLiteral("/api/schedule") && request.method() == Method::Get)
            {
                if (!authorizeApi(request, "/api/schedule")) return jsonUnauthorized();
                return handleScheduleList();
            }
            if (path == QStringLiteral("/api/schedule") && request.method() == Method::Post)
            {
                if (!authorizeApi(request, "/api/schedule")) return jsonUnauthorized();
                return handleScheduleAdd(request);
            }
            if (path == QStringLiteral("/api/schedule/remove") && request.method() == Method::Post)
            {
                if (!authorizeApi(request, "/api/schedule/remove")) return jsonUnauthorized();
                return handleScheduleControl(request, QStringLiteral("remove"));
            }
            if (path == QStringLiteral("/api/schedule/enable") && request.method() == Method::Post)
            {
                if (!authorizeApi(request, "/api/schedule/enable")) return jsonUnauthorized();
                return handleScheduleControl(request, QStringLiteral("enable"));
            }
            if (path == QStringLiteral("/api/schedule/disable") && request.method() == Method::Post)
            {
                if (!authorizeApi(request, "/api/schedule/disable")) return jsonUnauthorized();
                return handleScheduleControl(request, QStringLiteral("disable"));
            }
            if (path == QStringLiteral("/api/service/status") && request.method() == Method::Get)
            {
                if (!authorizeApi(request, "/api/service/status")) return jsonUnauthorized();
                return handleServiceStatus();
            }
            if (path == QStringLiteral("/api/service/install") && request.method() == Method::Post)
            {
                if (!authorizeApi(request, "/api/service/install")) return jsonUnauthorized();
                return handleServiceAction("install");
            }
            if (path == QStringLiteral("/api/service/start") && request.method() == Method::Post)
            {
                if (!authorizeApi(request, "/api/service/start")) return jsonUnauthorized();
                return handleServiceAction("start");
            }
            if (path == QStringLiteral("/api/service/stop") && request.method() == Method::Post)
            {
                if (!authorizeApi(request, "/api/service/stop")) return jsonUnauthorized();
                return handleServiceAction("stop");
            }
            if (path == QStringLiteral("/api/service/uninstall") && request.method() == Method::Post)
            {
                if (!authorizeApi(request, "/api/service/uninstall")) return jsonUnauthorized();
                return handleServiceAction("uninstall");
            }
            return jsonError(QStringLiteral("not found"), 404);
        }))
    {
        listener->close();
        return false;
    }
    if (trace)
        QTextStream(stderr) << "PGS web start complete\n" << Qt::flush;
    return true;
}

QString WebServer::listenUrl() const
{
    return QStringLiteral("%1://%2")
        .arg(m_options.remote ? QStringLiteral("https") : QStringLiteral("http"),
             hostWithPort(m_options.bindAddress, m_options.httpPort));
}

// Legacy HMAC-SHA256 over the password using a per-user salt. New user files
// should prefer PBKDF2-SHA256; legacy records remain readable for upgrades.
QByteArray WebServer::saltHash(const QByteArray &salt, const QByteArray &password)
{
    return QMessageAuthenticationCode::hash(password, salt, QCryptographicHash::Sha256).toHex();
}

QByteArray WebServer::pbkdf2Hash(const QByteArray &salt, const QByteArray &password, int iterations, quint64 keyLength)
{
    return QPasswordDigestor::deriveKeyPbkdf2(QCryptographicHash::Sha256, password, salt, iterations, keyLength);
}

// Load the RBAC user store. File formats, one user per line:
//   user;role;pbkdf2-sha256;iterations;saltHex;hashHex   (preferred)
//   user;role;saltHex;hashHex                             (legacy HMAC)
// role in {viewer, operator, admin}. Blank lines and # comments are skipped.
bool WebServer::loadUsers()
{
    if (m_options.usersFile.trimmed().isEmpty())
    {
        return false;
    }
    QFile f(m_options.usersFile);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        return false;
    }
    m_users.clear();
    while (!f.atEnd())
    {
        const QByteArray line = f.readLine().trimmed();
        if (line.isEmpty() || line.startsWith('#'))
            continue;
        const QList<QByteArray> parts = line.split(';');
        if (parts.size() != 4 && parts.size() != 6)
            continue;
        const QString user = QString::fromUtf8(parts[0]);
        const QString role = QString::fromUtf8(parts[1]).toLower();
        if (role != "viewer" && role != "operator" && role != "admin")
            continue;
        UserRec rec;
        rec.role = role;
        if (parts.size() == 4)
        {
            rec.scheme = QStringLiteral("hmac-sha256-legacy");
            rec.salt = QByteArray::fromHex(parts[2]);
            rec.hash = parts[3].trimmed().toLower();
        }
        else
        {
            rec.scheme = QString::fromUtf8(parts[2]).toLower();
            if (rec.scheme != QLatin1String("pbkdf2-sha256"))
                continue;
            bool ok = false;
            rec.iterations = QString::fromUtf8(parts[3]).toInt(&ok);
            if (!ok || rec.iterations < kPbkdf2MinIterations)
                continue;
            rec.salt = QByteArray::fromHex(parts[4]);
            rec.hash = QByteArray::fromHex(parts[5]);
            if (rec.hash.size() != kPbkdf2KeyLength)
                continue;
        }
        if (rec.salt.isEmpty() || rec.hash.isEmpty())
            continue;
        m_users.insert(user, rec);
    }
    return !m_users.isEmpty();
}

// HTTP Basic auth: validate user+password and check the role meets the minimum.
bool WebServer::authenticateAndAuthorize(const PgsHttp::Request &request, int requiredRole, QString &outUser)
{
    const QString source = sourceAddress(request);
    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    auto failureIt = m_loginFailures.find(source);
    if (failureIt != m_loginFailures.end() && failureIt->blockedUntilMs > nowMs)
    {
        audit(QStringLiteral("-"), QStringLiteral("login-throttled"), source);
        return false;
    }
    auto reject = [&](const QString &user, const QString &reason) {
        LoginFailure &failure = m_loginFailures[source];
        failure.count = std::min(failure.count + 1, 10);
        int delayMs = 250;
        for (int i = 1; i < failure.count; ++i)
        {
            delayMs = std::min(delayMs * 2, 60000);
        }
        failure.blockedUntilMs = QDateTime::currentMSecsSinceEpoch() + delayMs;
        audit(user.isEmpty() ? QStringLiteral("-") : user, QStringLiteral("login-failed:") + reason, source);
        return false;
    };

    // Expect "Authorization: Basic <base64(user:pass)>".
    const QByteArray auth = request.value("Authorization");
    const QByteArray prefix = "Basic ";
    if (!auth.startsWith(prefix))
        return reject(QString(), QStringLiteral("missing-basic"));
    const QByteArray decoded = QByteArray::fromBase64(auth.mid(prefix.size()));
    const int colon = decoded.indexOf(':');
    if (colon < 0)
        return reject(QString(), QStringLiteral("bad-basic"));
    const QString user = QString::fromUtf8(decoded.left(colon));
    const QByteArray password = decoded.mid(colon + 1);
    auto it = m_users.constFind(user);
    if (it == m_users.constEnd())
        return reject(user, QStringLiteral("unknown-user"));
    const UserRec &rec = it.value();
    QByteArray computed;
    QByteArray storedHash = rec.hash;
    if (rec.scheme == QLatin1String("pbkdf2-sha256"))
    {
        computed = pbkdf2Hash(rec.salt, password, rec.iterations, static_cast<quint64>(storedHash.size()));
    }
    else if (rec.scheme == QLatin1String("hmac-sha256-legacy"))
    {
        computed = saltHash(rec.salt, password);
    }
    else
    {
        return reject(user, QStringLiteral("bad-user-record"));
    }
    if (!constantTimeEquals(computed, storedHash))
        return reject(user, QStringLiteral("bad-password"));
    int roleVal = (rec.role == "admin") ? static_cast<int>(Role::Admin)
                 : (rec.role == "operator") ? static_cast<int>(Role::Operator)
                 : static_cast<int>(Role::Viewer);
    if (roleVal < requiredRole)
        return reject(user, QStringLiteral("insufficient-role"));
    m_loginFailures.remove(source);
    outUser = user;
    return true;
}

void WebServer::audit(const QString &user, const QString &action, const QString &sourceIp)
{
    if (m_options.auditLogPath.isEmpty())
        return;
    if (!m_auditFile)
    {
        m_auditFile = new QFile(m_options.auditLogPath, this);
        // Best-effort open; if it fails we silently skip audit records.
        m_auditFile->open(QIODevice::Append | QIODevice::Text);
    }
    if (m_auditFile && m_auditFile->isOpen())
    {
        QTextStream ts(m_auditFile);
        ts << QDateTime::currentDateTime().toString(Qt::ISODate)
           << " user=\"" << auditField(user) << '"'
           << " action=\"" << auditField(action) << '"'
           << " from=\"" << auditField(sourceIp) << '"'
           << "\n";
        ts.flush();
    }
}

void WebServer::auditUser(const PgsHttp::Request &request, const QString &action)
{
    QString user;
    if (m_options.remote && authenticateAndAuthorize(request, roleRequired(action), user))
    {
        audit(user, action, sourceAddress(request));
    }
}

bool WebServer::setupTls()
{
    if (m_options.tlsCertPath.trimmed().isEmpty() || m_options.tlsKeyPath.trimmed().isEmpty())
    {
        return false;
    }

    QFile certFile(m_options.tlsCertPath);
    if (!certFile.open(QIODevice::ReadOnly))
    {
        return false;
    }
    const QList<QSslCertificate> certs = QSslCertificate::fromData(certFile.readAll(), QSsl::Pem);
    if (certs.isEmpty() || certs.first().isNull())
    {
        return false;
    }

    QFile keyFile(m_options.tlsKeyPath);
    if (!keyFile.open(QIODevice::ReadOnly))
    {
        return false;
    }
    const QSslKey key = parsePrivateKey(keyFile.readAll());
    if (key.isNull())
    {
        return false;
    }

    if (!m_sslServer)
    {
        m_sslServer = new QSslServer(this);
    }

    delete m_sslCert;
    delete m_sslKey;
    m_sslCert = new QSslCertificate(certs.first());
    m_sslKey = new QSslKey(key);

    QSslConfiguration cfg = QSslConfiguration::defaultConfiguration();
    cfg.setLocalCertificate(*m_sslCert);
    cfg.setPrivateKey(*m_sslKey);
    cfg.setPeerVerifyMode(QSslSocket::VerifyNone);
    m_sslServer->setSslConfiguration(cfg);
    return true;
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
    obj.insert("remote", m_options.remote);
    return QHttpServerResponse(obj);
}

QHttpServerResponse WebServer::handleClusterHealth()
{
    const CommandResult ping = runPgsDirect(QStringLiteral("ping"));
    const CommandResult guardsResult = runPgsDirect(QStringLiteral("list"));
    const bool pgsOk = ping.started && ping.finished && ping.exitCode == 0;
    const bool guardsOk = guardsResult.started && guardsResult.finished && guardsResult.exitCode == 0;
    const QJsonArray guards = guardsOk ? parseGuardReply(guardsResult.stdOut) : QJsonArray{};

    QJsonObject obj;
    obj.insert("ok", true);
    obj.insert("pgs_ok", pgsOk);
    obj.insert("guard_count", guards.size());
    obj.insert("listen_url", listenUrl());
    obj.insert("pgs_host", m_options.pgsHost);
    obj.insert("pgs_port", static_cast<int>(m_options.pgsPort));
    obj.insert("message", pgsOk ? QStringLiteral("PGS reachable") : (ping.errorText.isEmpty() ? ping.stdErr : ping.errorText));
    return QHttpServerResponse(obj);
}

QHttpServerResponse WebServer::handlePing()
{
    return jsonCommandResult(runPgsDirect(QStringLiteral("ping")), QStringLiteral("PGS ping completed"));
}

QHttpServerResponse WebServer::handleDoctor()
{
    QJsonArray checks;
    auto add = [&](const QString &id, const QString &status, const QString &message) {
        QJsonObject check;
        check.insert(QStringLiteral("id"), id);
        check.insert(QStringLiteral("status"), status);
        check.insert(QStringLiteral("message"), message);
        checks.append(check);
    };

    const CommandResult ping = runPgsDirect(QStringLiteral("ping"));
    add(QStringLiteral("pgs_connect"),
        (ping.started && ping.finished && ping.exitCode == 0) ? QStringLiteral("ok") : QStringLiteral("fail"),
        ping.stdOut.trimmed().isEmpty() ? ping.errorText : ping.stdOut.trimmed());

    const CommandResult stats = runPgsDirect(QStringLiteral("stats"));
    add(QStringLiteral("stats"),
        (stats.started && stats.finished && stats.exitCode == 0) ? QStringLiteral("ok") : QStringLiteral("warn"),
        stats.stdOut.trimmed().isEmpty() ? stats.errorText : stats.stdOut.trimmed());

    const CommandResult moduleVerify = runPgsDirect(QStringLiteral("module verify"));
    add(QStringLiteral("module_loader"),
        (moduleVerify.started && moduleVerify.finished && moduleVerify.exitCode == 0) ? QStringLiteral("ok") : QStringLiteral("warn"),
        moduleVerify.stdOut.trimmed().isEmpty() ? moduleVerify.errorText : moduleVerify.stdOut.trimmed());

    const CommandResult service = runTool(resolvedServiceToolPath(), {QStringLiteral("status")});
    add(QStringLiteral("service"),
        (service.started && service.finished && service.exitCode == 0) ? QStringLiteral("ok") : QStringLiteral("warn"),
        service.stdOut.trimmed().isEmpty() ? service.errorText : service.stdOut.trimmed());

    const QFileInfo blessTool(resolvedBlessToolPath());
    add(QStringLiteral("bless_tool"), blessTool.exists() ? QStringLiteral("ok") : QStringLiteral("warn"), blessTool.absoluteFilePath());
    const QFileInfo modulesDir(QCoreApplication::applicationDirPath() + QStringLiteral("/modules"));
    add(QStringLiteral("modules_dir"), modulesDir.exists() ? QStringLiteral("ok") : QStringLiteral("warn"), modulesDir.absoluteFilePath());
    add(QStringLiteral("modules_allow"), QFileInfo(modulesDir.absoluteFilePath() + QStringLiteral("/modules.allow")).exists() ? QStringLiteral("ok") : QStringLiteral("warn"), modulesDir.absoluteFilePath() + QStringLiteral("/modules.allow"));
    add(QStringLiteral("modules_lock"), QFileInfo(modulesDir.absoluteFilePath() + QStringLiteral("/modules.lock")).exists() ? QStringLiteral("ok") : QStringLiteral("warn"), modulesDir.absoluteFilePath() + QStringLiteral("/modules.lock"));
    add(QStringLiteral("qt_runtime"), (QFileInfo(QCoreApplication::applicationDirPath() + QStringLiteral("/Qt6Core.dll")).exists() || QFileInfo(QCoreApplication::applicationDirPath() + QStringLiteral("/Qt5Core.dll")).exists()) ? QStringLiteral("ok") : QStringLiteral("info"), QStringLiteral("Qt runtime beside web executable"));
    add(QStringLiteral("openssl_runtime"), (QFileInfo(QCoreApplication::applicationDirPath() + QStringLiteral("/libssl-3-x64.dll")).exists() || QFileInfo(QCoreApplication::applicationDirPath() + QStringLiteral("/libssl-3.dll")).exists()) ? QStringLiteral("ok") : QStringLiteral("info"), QStringLiteral("OpenSSL runtime beside web executable"));

    QJsonObject obj;
    obj.insert(QStringLiteral("ok"), true);
    obj.insert(QStringLiteral("checks"), checks);
    return QHttpServerResponse(obj);
}

QHttpServerResponse WebServer::handleGuards()
{
    const CommandResult result = runPgsDirect(QStringLiteral("list"));
    if (!result.started || result.exitCode != 0)
    {
        return jsonCommandResult(result, QStringLiteral("failed to query guards"));
    }
    QJsonObject obj;
    obj.insert("ok", true);
    obj.insert("guards", parseGuardReply(result.stdOut));
    return QHttpServerResponse(obj);
}

QHttpServerResponse WebServer::handleGuard(const PgsHttp::Request &request)
{
    const QString pid = request.query().queryItemValue("pid").trimmed();
    if (pid.isEmpty())
    {
        return jsonError("pid is required");
    }
    const CommandResult result = runPgsDirect(QStringLiteral("get ") + pid);
    if (!result.started || result.exitCode != 0)
    {
        return jsonCommandResult(result, QStringLiteral("failed to query guard"));
    }
    const QJsonArray guards = parseGuardReply(result.stdOut);
    QJsonObject obj;
    obj.insert("ok", true);
    obj.insert("guard", guards.isEmpty() ? QJsonObject{} : guards.first().toObject());
    return QHttpServerResponse(obj);
}

QHttpServerResponse WebServer::handleBless(const PgsHttp::Request &request)
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
    appendAdvancedGuardArgs(args, body);
    args << blessBaseArguments();
    return jsonCommandResult(runTool(resolvedBlessToolPath(), args), "bless completed");
}

QHttpServerResponse WebServer::handleBlessStart(const PgsHttp::Request &request)
{
    const QJsonObject body = QJsonDocument::fromJson(request.body()).object();
    const QString path = bodyValue(body, "path");
    const QString command = bodyValue(body, "command");
    const bool winapp = bodyFlag(body, QStringLiteral("winapp"));
    const QString aumid = bodyValue(body, QStringLiteral("aumid"));
    if (path.isEmpty() && command.isEmpty() && !(winapp && !aumid.isEmpty()))
    {
        return jsonError("path or command is required; WindowsApps may use aumid only");
    }

    QStringList args{"bless-start", "--hash", winapp ? QStringLiteral("none") : QStringLiteral("auto")};
    if (winapp && !command.isEmpty())
    {
        return jsonError("WindowsApps bless-start does not support command mode");
    }
    if (!command.isEmpty())
    {
        args << "--command" << command;
    }
    else if (!path.isEmpty())
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
    appendAdvancedGuardArgs(args, body);
    args << blessBaseArguments();
    return jsonCommandResult(runTool(resolvedBlessToolPath(), args), "bless-start completed");
}

QHttpServerResponse WebServer::handlePolicy(const PgsHttp::Request &request)
{
    const QJsonObject body = QJsonDocument::fromJson(request.body()).object();
    const QString pid = bodyValue(body, "pid");
    const QString maxRestarts = bodyValue(body, "max_restarts");
    if (pid.isEmpty() || maxRestarts.isEmpty())
    {
        return jsonError("pid and max_restarts are required");
    }
    // Wire format:
    //   set-policy <pid>|<max>|<argsB64>[|restartWindow|restartDelay|backoff|hang|kill|appKind|aumidB64]
    const QString restartArgs = bodyValue(body, "restart_args");
    const std::string argsB64 = ProcessGuard::client::base64Encode(restartArgs.toStdString());
    QString wire = QStringLiteral("set-policy %1|%2|%3").arg(pid, maxRestarts, QString::fromStdString(argsB64));
    const QString restartWindow = optionalPolicyField(body, QStringLiteral("restart_window"));
    const QString restartDelay = optionalPolicyField(body, QStringLiteral("restart_delay"));
    const QString backoff = body.contains(QStringLiteral("restart_backoff")) ? (bodyFlag(body, QStringLiteral("restart_backoff")) ? QStringLiteral("1") : QStringLiteral("0")) : QString();
    const QString hangTimeout = optionalPolicyField(body, QStringLiteral("hang_timeout"));
    const QString killOnExit = body.contains(QStringLiteral("kill_on_exit")) ? (bodyFlag(body, QStringLiteral("kill_on_exit")) ? QStringLiteral("1") : QStringLiteral("0")) : QString();
    const QString appKind = bodyFlag(body, QStringLiteral("winapp")) ? QStringLiteral("winapp") : QString();
    const QString aumid = bodyValue(body, QStringLiteral("aumid"));
    if (!restartWindow.isEmpty() || !restartDelay.isEmpty() || !backoff.isEmpty() ||
        !hangTimeout.isEmpty() || !killOnExit.isEmpty() || !appKind.isEmpty() || !aumid.isEmpty())
    {
        wire += QStringLiteral("|%1|%2|%3|%4|%5|%6|%7")
                    .arg(restartWindow,
                         restartDelay,
                         backoff,
                         hangTimeout,
                         killOnExit,
                         appKind,
                         QString::fromStdString(ProcessGuard::client::base64Encode(aumid.toStdString())));
    }
    return jsonCommandResult(runPgsDirect(wire), QStringLiteral("policy updated"));
}

QHttpServerResponse WebServer::handleUnbless(const PgsHttp::Request &request)
{
    const QJsonObject body = QJsonDocument::fromJson(request.body()).object();
    const QString path = bodyValue(body, "path");
    const QString pid = bodyValue(body, "pid");

    // By-pid unregister is a pure protocol round-trip, so go direct. By-path
    // still needs client-side list+match (pgs_bless unbless-path), so keep QProcess.
    if (!pid.isEmpty())
    {
        return jsonCommandResult(runPgsDirect(QStringLiteral("unregister ") + pid), QStringLiteral("unbless completed"));
    }
    if (!path.isEmpty())
    {
        QStringList args{"unbless-path", "--path", path};
        args << blessBaseArguments();
        return jsonCommandResult(runTool(resolvedBlessToolPath(), args), QStringLiteral("unbless completed"));
    }
    return jsonError("pid or path is required");
}

QHttpServerResponse WebServer::handleIntentional(const PgsHttp::Request &request)
{
    const QJsonObject body = QJsonDocument::fromJson(request.body()).object();
    const QString pid = bodyValue(body, "pid");
    if (pid.isEmpty())
    {
        return jsonError("pid is required");
    }
    return jsonCommandResult(runPgsDirect(QStringLiteral("intentional ") + pid), QStringLiteral("intentional exit marked"));
}

QHttpServerResponse WebServer::handleGuardControl(const PgsHttp::Request &request, const QString &action)
{
    const QJsonObject body = QJsonDocument::fromJson(request.body()).object();
    const QString id = bodyValue(body, QStringLiteral("id"));
    if (!isUnsignedText(id))
    {
        return jsonError(QStringLiteral("valid guard id is required"));
    }
    return jsonCommandResult(runPgsDirect(QStringLiteral("guard %1 %2").arg(action, id)),
                             QStringLiteral("guard control completed"));
}

QHttpServerResponse WebServer::handleHealthCheck(const PgsHttp::Request &request, const QString &action)
{
    QString pid;
    QString configJson;
    if (request.method() == QHttpServerRequest::Method::Get)
    {
        pid = request.query().queryItemValue(QStringLiteral("pid")).trimmed();
    }
    else
    {
        const QJsonObject body = QJsonDocument::fromJson(request.body()).object();
        pid = bodyValue(body, QStringLiteral("pid"));
        configJson = bodyValue(body, QStringLiteral("config_json"));
    }
    if (!isUnsignedText(pid))
    {
        return jsonError(QStringLiteral("valid pid is required"));
    }
    QString wire = QStringLiteral("health-check %1 %2").arg(action, pid);
    if (action == QLatin1String("set"))
    {
        if (configJson.isEmpty())
        {
            return jsonError(QStringLiteral("config_json is required"));
        }
        QJsonParseError parseError{};
        QJsonDocument::fromJson(configJson.toUtf8(), &parseError);
        if (parseError.error != QJsonParseError::NoError)
        {
            return jsonError(QStringLiteral("config_json must be valid JSON"));
        }
        wire += QLatin1Char(' ') + QString::fromStdString(ProcessGuard::client::base64Encode(configJson.toStdString()));
    }
    return jsonCommandResult(runPgsDirect(wire), QStringLiteral("health-check completed"));
}

QHttpServerResponse WebServer::handleTokenUpdate(const PgsHttp::Request &request)
{
    const QJsonObject body = QJsonDocument::fromJson(request.body()).object();
    const QString oldToken = bodyValue(body, "old_token");
    const QString newToken = bodyValue(body, "new_token");
    if (newToken.isEmpty())
    {
        return jsonError("new_token is required");
    }

    // Wire format: "set-token <base64(oldToken)>|<base64(newToken)>".
    // The service verifies oldToken against the current hash before rotating.
    const std::string oldB64 = ProcessGuard::client::base64Encode((oldToken.isEmpty() ? m_options.pgsToken : oldToken).toStdString());
    const std::string newB64 = ProcessGuard::client::base64Encode(newToken.toStdString());
    const QString wire = QStringLiteral("set-token %1|%2").arg(QString::fromStdString(oldB64), QString::fromStdString(newB64));
    const CommandResult result = runPgsDirect(wire);
    if (!result.started || result.exitCode != 0)
    {
        return jsonCommandResult(result, QStringLiteral("token update failed"));
    }

    m_options.pgsToken = newToken;
    return jsonCommandResult(result, QStringLiteral("token updated"));
}

QHttpServerResponse WebServer::handleModules()
{
    return jsonCommandResult(runPgsDirect(QStringLiteral("module list")), QStringLiteral("modules listed"));
}

QHttpServerResponse WebServer::handleModuleCall(const PgsHttp::Request &request)
{
    const QJsonObject body = QJsonDocument::fromJson(request.body()).object();
    const QString name = bodyValue(body, QStringLiteral("name"));
    const QString moduleRequest = bodyValue(body, QStringLiteral("request"));
    if (name.isEmpty() || moduleRequest.isEmpty())
    {
        return jsonError(QStringLiteral("name and request are required"));
    }
    if (name.contains(QLatin1Char(' ')) || name.contains(QLatin1Char('\t')))
    {
        return jsonError(QStringLiteral("module name must not contain whitespace"));
    }
    return jsonCommandResult(runPgsDirect(QStringLiteral("module call %1 %2").arg(name, moduleRequest)),
                             QStringLiteral("module call completed"));
}

QHttpServerResponse WebServer::handleMetrics(const PgsHttp::Request &request)
{
    const QString format = request.query().queryItemValue(QStringLiteral("format")).trimmed().isEmpty()
        ? QStringLiteral("summary")
        : request.query().queryItemValue(QStringLiteral("format")).trimmed().toLower();
    if (format != QLatin1String("summary") && format != QLatin1String("json") && format != QLatin1String("prometheus"))
    {
        return jsonError(QStringLiteral("format must be summary, json, or prometheus"));
    }
    const CommandResult result = runPgsDirect(QStringLiteral("module call metrics op=%1").arg(format));
    if (!result.started || !result.finished || result.exitCode != 0)
    {
        return jsonCommandResult(result, QStringLiteral("metrics query failed"));
    }
    QJsonObject obj;
    obj.insert(QStringLiteral("ok"), true);
    obj.insert(QStringLiteral("format"), format);
    obj.insert(QStringLiteral("stdout"), result.stdOut);
    if (format == QLatin1String("json"))
    {
        const QString text = decodedSummaryField(result.stdOut, QStringLiteral("json_b64"));
        obj.insert(QStringLiteral("text"), text);
        obj.insert(QStringLiteral("metrics"), jsonObjectFromToolStdout(text));
    }
    else if (format == QLatin1String("prometheus"))
    {
        obj.insert(QStringLiteral("text"), decodedSummaryField(result.stdOut, QStringLiteral("prometheus_b64")));
    }
    else
    {
        obj.insert(QStringLiteral("summary"), result.stdOut);
    }
    return QHttpServerResponse(obj);
}

QHttpServerResponse WebServer::handleBackupStatus()
{
    const CommandResult result = runPgsDirect(QStringLiteral("module call backup op=status"));
    if (!result.started || !result.finished || result.exitCode != 0)
    {
        return jsonCommandResult(result, QStringLiteral("backup status failed"));
    }
    QJsonObject obj;
    obj.insert(QStringLiteral("ok"), true);
    obj.insert(QStringLiteral("stdout"), result.stdOut);
    obj.insert(QStringLiteral("data_dir"), decodedSummaryField(result.stdOut, QStringLiteral("data_dir_b64")));
    return QHttpServerResponse(obj);
}

QHttpServerResponse WebServer::handleBackupSnapshot(const PgsHttp::Request &request)
{
    const QJsonObject body = QJsonDocument::fromJson(request.body()).object();
    QStringList args{QStringLiteral("backup"), QStringLiteral("snapshot")};
    if (bodyFlag(body, QStringLiteral("artifact")))
    {
        args << QStringLiteral("--artifact");
    }
    const QString maxBytes = bodyValue(body, QStringLiteral("max_bytes"));
    if (!maxBytes.isEmpty())
    {
        if (!isUnsignedText(maxBytes))
        {
            return jsonError(QStringLiteral("max_bytes must be a positive integer"));
        }
        args << QStringLiteral("--max-bytes") << maxBytes;
    }
    args << blessBaseArguments();
    const CommandResult result = runTool(resolvedBlessToolPath(), args, 120000);
    if (!result.started || !result.finished || result.exitCode != 0)
    {
        return jsonCommandResult(result, QStringLiteral("backup snapshot failed"));
    }
    QJsonObject obj;
    obj.insert(QStringLiteral("ok"), true);
    obj.insert(QStringLiteral("stdout"), result.stdOut);
    obj.insert(QStringLiteral("operation_id"), summaryField(result.stdOut, QStringLiteral("operation_id")));
    obj.insert(QStringLiteral("artifact_id"), summaryField(result.stdOut, QStringLiteral("artifact_id")));
    return QHttpServerResponse(obj);
}

QHttpServerResponse WebServer::handleEventlogStatus()
{
    return jsonCommandResult(runPgsDirect(QStringLiteral("module call eventlog op=status")),
                             QStringLiteral("eventlog status completed"));
}

QHttpServerResponse WebServer::handleEventlogRecent(const PgsHttp::Request &request)
{
    QString wire = QStringLiteral("module call eventlog op=recent");
    const QString limit = request.query().queryItemValue(QStringLiteral("limit")).trimmed();
    if (!limit.isEmpty())
    {
        if (!isUnsignedText(limit))
        {
            return jsonError(QStringLiteral("limit must be a positive integer"));
        }
        wire += QStringLiteral(";limit=") + limit;
    }
    const QString source = request.query().queryItemValue(QStringLiteral("source")).trimmed();
    if (!source.isEmpty())
    {
        if (!isSafeKvValueText(source))
        {
            return jsonError(QStringLiteral("source must not contain semicolon, control characters, or exceed 128 characters"));
        }
        wire += QStringLiteral(";source=") + source;
    }
    return jsonCommandResult(runPgsDirect(wire), QStringLiteral("eventlog recent completed"));
}

QHttpServerResponse WebServer::handleNotifyStatus()
{
    return jsonCommandResult(runPgsDirect(QStringLiteral("module call notify op=status")),
                             QStringLiteral("notify status completed"));
}

QHttpServerResponse WebServer::handleNotifyConfig(const PgsHttp::Request &request)
{
    const QJsonObject body = QJsonDocument::fromJson(request.body()).object();
    QString wire = QStringLiteral("module call notify op=config");
    if (body.contains(QStringLiteral("eventlog")))
    {
        wire += QStringLiteral(";eventlog=") + (bodyFlag(body, QStringLiteral("eventlog")) ? QStringLiteral("1") : QStringLiteral("0"));
    }
    if (body.contains(QStringLiteral("popup")))
    {
        wire += QStringLiteral(";popup=") + (bodyFlag(body, QStringLiteral("popup")) ? QStringLiteral("1") : QStringLiteral("0"));
    }
    return jsonCommandResult(runPgsDirect(wire), QStringLiteral("notify config completed"));
}

QHttpServerResponse WebServer::handleReport(const PgsHttp::Request &request)
{
    const QJsonObject body = QJsonDocument::fromJson(request.body()).object();
    const QString kind = bodyValue(body, QStringLiteral("kind")).isEmpty() ? QStringLiteral("snapshot") : bodyValue(body, QStringLiteral("kind"));
    if (kind != QLatin1String("snapshot") && kind != QLatin1String("backup"))
    {
        return jsonError(QStringLiteral("kind must be snapshot or backup"));
    }
    QStringList args{QStringLiteral("report"), kind};
    if (bodyFlag(body, QStringLiteral("artifact")))
    {
        args << QStringLiteral("--artifact");
    }
    const QString limit = bodyValue(body, QStringLiteral("limit"));
    if (!limit.isEmpty())
    {
        if (!isUnsignedText(limit))
        {
            return jsonError(QStringLiteral("limit must be a positive integer"));
        }
        args << QStringLiteral("--limit") << limit;
    }
    args << blessBaseArguments();
    return jsonCommandResult(runTool(resolvedBlessToolPath(), args), QStringLiteral("report completed"));
}

QHttpServerResponse WebServer::handleOperationStatus(const PgsHttp::Request &request)
{
    const QString id = request.query().queryItemValue(QStringLiteral("id")).trimmed();
    if (!isOpaqueIdText(id, QStringLiteral("op_")))
    {
        return jsonError(QStringLiteral("valid operation id is required"));
    }
    QStringList args{QStringLiteral("module"), QStringLiteral("op-status"), id, QStringLiteral("--json")};
    args << blessBaseArguments();
    const CommandResult result = runTool(resolvedBlessToolPath(), args);
    if (!result.started || !result.finished || result.exitCode != 0)
    {
        return jsonCommandResult(result, QStringLiteral("operation query failed"));
    }
    QJsonObject obj;
    obj.insert(QStringLiteral("ok"), true);
    obj.insert(QStringLiteral("operation"), jsonObjectFromToolStdout(result.stdOut));
    obj.insert(QStringLiteral("stdout"), result.stdOut);
    return QHttpServerResponse(obj);
}

QHttpServerResponse WebServer::handleArtifactMeta(const PgsHttp::Request &request)
{
    const QString id = request.query().queryItemValue(QStringLiteral("id")).trimmed();
    if (!isOpaqueIdText(id, QStringLiteral("art_")))
    {
        return jsonError(QStringLiteral("valid artifact id is required"));
    }
    QStringList args{QStringLiteral("module"), QStringLiteral("artifact"), QStringLiteral("get"), id, QStringLiteral("--json")};
    args << blessBaseArguments();
    const CommandResult result = runTool(resolvedBlessToolPath(), args);
    if (!result.started || !result.finished || result.exitCode != 0)
    {
        return jsonCommandResult(result, QStringLiteral("artifact query failed"));
    }
    QJsonObject obj;
    obj.insert(QStringLiteral("ok"), true);
    obj.insert(QStringLiteral("artifact"), jsonObjectFromToolStdout(result.stdOut));
    obj.insert(QStringLiteral("stdout"), result.stdOut);
    return QHttpServerResponse(obj);
}

QHttpServerResponse WebServer::handleArtifactStatus(const PgsHttp::Request &request)
{
    QStringList args{QStringLiteral("module"), QStringLiteral("artifact"), QStringLiteral("status"), QStringLiteral("--json")};
    const QString verify = request.query().queryItemValue(QStringLiteral("verify")).trimmed().toLower();
    if (verify == QLatin1String("1") || verify == QLatin1String("true") || verify == QLatin1String("yes"))
    {
        args << QStringLiteral("--verify");
    }
    args << blessBaseArguments();
    const CommandResult result = runTool(resolvedBlessToolPath(), args, 120000);
    if (!result.started || !result.finished || result.exitCode != 0)
    {
        return jsonCommandResult(result, QStringLiteral("artifact status failed"));
    }
    QJsonObject obj;
    obj.insert(QStringLiteral("ok"), true);
    obj.insert(QStringLiteral("status"), jsonObjectFromToolStdout(result.stdOut));
    obj.insert(QStringLiteral("stdout"), result.stdOut);
    return QHttpServerResponse(obj);
}

QHttpServerResponse WebServer::handleArtifactPolicy(const PgsHttp::Request &request)
{
    const QJsonObject body = QJsonDocument::fromJson(request.body()).object();
    QStringList args{QStringLiteral("module"), QStringLiteral("artifact"), QStringLiteral("policy"), QStringLiteral("--json")};
    const QString ttlMs = bodyValue(body, QStringLiteral("ttl_ms"));
    if (!ttlMs.isEmpty())
    {
        if (!isUnsignedText(ttlMs))
        {
            return jsonError(QStringLiteral("ttl_ms must be an integer"));
        }
        args << QStringLiteral("--ttl-ms") << ttlMs;
    }
    const QString maxArtifactBytes = bodyValue(body, QStringLiteral("max_artifact_bytes"));
    if (!maxArtifactBytes.isEmpty())
    {
        if (!isUnsignedText(maxArtifactBytes))
        {
            return jsonError(QStringLiteral("max_artifact_bytes must be an integer"));
        }
        args << QStringLiteral("--max-artifact-bytes") << maxArtifactBytes;
    }
    const QString maxTotalBytes = bodyValue(body, QStringLiteral("max_total_bytes"));
    if (!maxTotalBytes.isEmpty())
    {
        if (!isUnsignedText(maxTotalBytes))
        {
            return jsonError(QStringLiteral("max_total_bytes must be an integer"));
        }
        args << QStringLiteral("--max-total-bytes") << maxTotalBytes;
    }
    if (body.contains(QStringLiteral("auto_cleanup")))
    {
        args << (bodyFlag(body, QStringLiteral("auto_cleanup")) ? QStringLiteral("--auto-cleanup") : QStringLiteral("--no-auto-cleanup"));
    }
    if (body.contains(QStringLiteral("verify_on_status")))
    {
        args << (bodyFlag(body, QStringLiteral("verify_on_status")) ? QStringLiteral("--verify-on-status") : QStringLiteral("--no-verify-on-status"));
    }
    args << blessBaseArguments();
    const CommandResult result = runTool(resolvedBlessToolPath(), args, 120000);
    if (!result.started || !result.finished || result.exitCode != 0)
    {
        return jsonCommandResult(result, QStringLiteral("artifact policy failed"));
    }
    QJsonObject obj;
    obj.insert(QStringLiteral("ok"), true);
    obj.insert(QStringLiteral("policy"), jsonObjectFromToolStdout(result.stdOut));
    obj.insert(QStringLiteral("stdout"), result.stdOut);
    return QHttpServerResponse(obj);
}

QHttpServerResponse WebServer::handleArtifactDownload(const PgsHttp::Request &request)
{
    const QJsonObject body = QJsonDocument::fromJson(request.body()).object();
    const QString id = bodyValue(body, QStringLiteral("id"));
    const QString outPath = bodyValue(body, QStringLiteral("out"));
    if (!isOpaqueIdText(id, QStringLiteral("art_")))
    {
        return jsonError(QStringLiteral("valid artifact id is required"));
    }
    if (outPath.isEmpty())
    {
        return jsonError(QStringLiteral("out path is required"));
    }
    QStringList args{QStringLiteral("module"), QStringLiteral("artifact"), QStringLiteral("get"), id, QStringLiteral("--out"), outPath};
    args << blessBaseArguments();
    return jsonCommandResult(runTool(resolvedBlessToolPath(), args, 120000), QStringLiteral("artifact downloaded"));
}

QHttpServerResponse WebServer::handleScheduleList()
{
    return jsonCommandResult(runPgsDirect(QStringLiteral("module call sched op=list")),
                             QStringLiteral("schedule listed"));
}

QHttpServerResponse WebServer::handleScheduleAdd(const PgsHttp::Request &request)
{
    const QJsonObject body = QJsonDocument::fromJson(request.body()).object();
    const QString type = bodyValue(body, QStringLiteral("type"));
    const QString expr = bodyValue(body, QStringLiteral("expr"));
    const QString action = bodyValue(body, QStringLiteral("action"));
    const QString count = bodyValue(body, QStringLiteral("count"));
    if (type.isEmpty() || expr.isEmpty() || action.isEmpty())
    {
        return jsonError(QStringLiteral("type, expr, and action are required"));
    }
    if (type != QLatin1String("cron") && type != QLatin1String("once") && type != QLatin1String("interval"))
    {
        return jsonError(QStringLiteral("type must be cron, once, or interval"));
    }
    QString wire = QStringLiteral("module call sched op=add;type=%1;expr=%2;action=%3")
                       .arg(type, expr, action);
    if (!count.isEmpty())
    {
        wire += QStringLiteral(";count=") + count;
    }
    return jsonCommandResult(runPgsDirect(wire), QStringLiteral("schedule added"));
}

QHttpServerResponse WebServer::handleScheduleControl(const PgsHttp::Request &request, const QString &action)
{
    const QJsonObject body = QJsonDocument::fromJson(request.body()).object();
    const QString id = bodyValue(body, QStringLiteral("id"));
    if (id.isEmpty())
    {
        return jsonError(QStringLiteral("id is required"));
    }
    return jsonCommandResult(runPgsDirect(QStringLiteral("module call sched op=%1;id=%2").arg(action, id)),
                             QStringLiteral("schedule updated"));
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

QHttpServerResponse WebServer::handleAudit(const PgsHttp::Request &request) const
{
    bool ok = false;
    int limit = request.query().queryItemValue(QStringLiteral("limit")).toInt(&ok);
    if (!ok)
    {
        limit = 100;
    }
    if (limit < 1)
    {
        limit = 1;
    }
    if (limit > 500)
    {
        limit = 500;
    }

    QJsonObject obj;
    obj.insert("ok", true);
    obj.insert("limit", limit);
    obj.insert("enabled", !m_options.auditLogPath.trimmed().isEmpty());

    QJsonArray events;
    if (m_options.auditLogPath.trimmed().isEmpty())
    {
        obj.insert("events", events);
        obj.insert("message", QStringLiteral("audit log is not configured"));
        return QHttpServerResponse(obj);
    }

    QFile file(m_options.auditLogPath);
    if (!file.exists())
    {
        obj.insert("events", events);
        obj.insert("message", QStringLiteral("audit log has no events yet"));
        return QHttpServerResponse(obj);
    }
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        return jsonError(QStringLiteral("failed to read audit log"), 500);
    }

    QStringList tail;
    while (!file.atEnd())
    {
        const QString line = QString::fromUtf8(file.readLine()).trimmed();
        if (line.isEmpty())
        {
            continue;
        }
        tail.append(line);
        while (tail.size() > limit)
        {
            tail.removeFirst();
        }
    }
    for (const QString &line : tail)
    {
        events.append(parseAuditLine(line));
    }
    obj.insert("events", events);
    return QHttpServerResponse(obj);
}

QHttpServerResponse WebServer::handleIndex() const
{
    return QHttpServerResponse(QByteArray("text/html; charset=utf-8"), indexHtml().toUtf8());
}

// Talk to PGS directly over the shared TCP client instead of spawning
// pgs_bless.exe. Used for pure protocol round-trips (ping/list/get/policy/
// unregister/intentional/set-token) where no client-side launch logic is
// needed. Commands that must create processes (bless-start) still go through
// runTool() + pgs_bless.exe.
WebServer::CommandResult WebServer::runPgsDirect(const QString &wireCommand) const
{
    CommandResult result;
    ProcessGuard::client::ClientOptions opts;
    opts.host = m_options.pgsHost.toStdString();
    opts.port = m_options.pgsPort;
    opts.token = m_options.pgsToken.toStdString();
    const std::string envelope = ProcessGuard::client::withAuthToken(opts.token, wireCommand.toStdString());
    const auto resp = ProcessGuard::client::sendCommand(opts, envelope);
    result.started = resp.ok;
    result.finished = resp.ok;
    result.stdOut = QString::fromStdString(resp.payload);
    result.errorText = QString::fromStdString(resp.error);
    if (!resp.ok)
    {
        result.exitCode = -1;
        return result;
    }
    if (result.stdOut.trimmed().startsWith(QLatin1String("ERR")))
    {
        result.exitCode = 1;
        result.stdErr = result.stdOut;
        result.errorText = result.stdOut;
        return result;
    }
    result.exitCode = 0;
    return result;
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

QHttpServerResponse WebServer::jsonUnauthorized() const
{
    QHttpServerResponse response = jsonError(QStringLiteral("unauthorized"), 401);
    QHttpHeaders headers = response.headers();
    if (m_options.remote)
    {
        headers.replaceOrAppend(QByteArrayLiteral("WWW-Authenticate"), QByteArrayLiteral("Basic realm=\"PGS Admin\""));
    }
    response.setHeaders(std::move(headers));
    return response;
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
