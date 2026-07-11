#include "SimpleHttp.h"

#include <QHttpHeaders>
#include <QTcpServer>
#include <QTcpSocket>

namespace PgsHttp
{
namespace
{
QByteArray normalizeHeaderName(QByteArray name)
{
    return name.trimmed().toLower();
}

QHttpServerRequest::Method parseMethod(const QByteArray &method)
{
    using Method = QHttpServerRequest::Method;
    if (method == "GET")
        return Method::Get;
    if (method == "POST")
        return Method::Post;
    if (method == "DELETE")
        return Method::Delete;
    if (method == "PUT")
        return Method::Put;
    if (method == "PATCH")
        return Method::Patch;
    if (method == "HEAD")
        return Method::Head;
    if (method == "OPTIONS")
        return Method::Options;
    return Method::Unknown;
}

int statusCode(QHttpServerResponse::StatusCode status)
{
    return static_cast<int>(status);
}

QByteArray reasonPhrase(int code)
{
    switch (code)
    {
    case 200:
        return "OK";
    case 201:
        return "Created";
    case 204:
        return "No Content";
    case 400:
        return "Bad Request";
    case 401:
        return "Unauthorized";
    case 403:
        return "Forbidden";
    case 404:
        return "Not Found";
    case 405:
        return "Method Not Allowed";
    case 411:
        return "Length Required";
    case 415:
        return "Unsupported Media Type";
    case 500:
        return "Internal Server Error";
    case 504:
        return "Gateway Timeout";
    default:
        return QByteArray::number(code);
    }
}

QHttpServerResponse badRequest()
{
    return QHttpServerResponse(QByteArray("text/plain"), QByteArray("bad request"),
                               QHttpServerResponse::StatusCode::BadRequest);
}

QHttpServerResponse lengthRequired()
{
    return QHttpServerResponse(QByteArray("text/plain"), QByteArray("content length required"),
                               static_cast<QHttpServerResponse::StatusCode>(411));
}

QHttpServerResponse payloadTooLarge()
{
    return QHttpServerResponse(QByteArray("text/plain"), QByteArray("payload too large"),
                               static_cast<QHttpServerResponse::StatusCode>(413));
}
} // namespace

QByteArray Request::value(const QByteArray &key) const
{
    return m_headers.value(normalizeHeaderName(key));
}

Server::Server(QObject *parent) : QObject(parent)
{
}

bool Server::bind(QTcpServer *listener, Handler handler)
{
    if (!listener || !handler)
        return false;
    m_listener = listener;
    m_handler = std::move(handler);
    connect(m_listener, &QTcpServer::newConnection, this, &Server::drainConnections);
    connect(m_listener, &QTcpServer::pendingConnectionAvailable, this, &Server::drainConnections);
    return true;
}

void Server::drainConnections()
{
    while (m_listener && m_listener->hasPendingConnections())
    {
        QTcpSocket *socket = m_listener->nextPendingConnection();
        if (!socket)
            continue;
        socket->setParent(this);
        auto *buffer = new QByteArray();
        connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
        connect(socket, &QTcpSocket::readyRead, this, [this, socket, buffer]() {
            readSocket(socket, buffer);
        });
        connect(socket, &QObject::destroyed, this, [buffer]() {
            delete buffer;
        });
        if (socket->bytesAvailable() > 0)
            readSocket(socket, buffer);
    }
}

void Server::readSocket(QTcpSocket *socket, QByteArray *buffer)
{
    if (!socket || !buffer)
        return;
    buffer->append(socket->readAll());
    if (buffer->size() > 1024 * 1024)
    {
        sendResponse(socket, payloadTooLarge(), false);
        return;
    }
    tryHandle(socket, buffer);
}

bool Server::tryHandle(QTcpSocket *socket, QByteArray *buffer)
{
    const int headerEnd = buffer->indexOf("\r\n\r\n");
    if (headerEnd < 0)
        return false;

    const QByteArray head = buffer->left(headerEnd);
    const QList<QByteArray> lines = head.split('\n');
    if (lines.isEmpty())
    {
        sendResponse(socket, badRequest(), false);
        return true;
    }

    const QList<QByteArray> requestLine = lines.first().trimmed().split(' ');
    if (requestLine.size() < 3)
    {
        sendResponse(socket, badRequest(), false);
        return true;
    }

    Request request;
    request.m_method = parseMethod(requestLine.at(0));
    request.m_url = QUrl::fromEncoded(requestLine.at(1));
    if (request.m_url.path().isEmpty())
        request.m_url.setPath(QStringLiteral("/"));
    request.m_remoteAddress = socket->peerAddress();
    request.m_remotePort = socket->peerPort();
    request.m_localAddress = socket->localAddress();
    request.m_localPort = socket->localPort();

    for (int i = 1; i < lines.size(); ++i)
    {
        const QByteArray line = lines.at(i).trimmed();
        const int colon = line.indexOf(':');
        if (colon <= 0)
            continue;
        const QByteArray name = normalizeHeaderName(line.left(colon));
        const QByteArray value = line.mid(colon + 1).trimmed();
        request.m_headers.insert(name, value);
    }

    bool ok = true;
    const QByteArray transferEncoding = request.value("Transfer-Encoding").trimmed().toLower();
    if (!transferEncoding.isEmpty())
    {
        sendResponse(socket, lengthRequired(), false);
        return true;
    }
    const QByteArray contentLengthHeader = request.value("Content-Length");
    const int contentLength = contentLengthHeader.isEmpty() ? 0 : contentLengthHeader.toInt(&ok);
    if (!ok || contentLength < 0 || contentLength > 1024 * 1024)
    {
        sendResponse(socket, badRequest(), false);
        return true;
    }
    const int bodyStart = headerEnd + 4;
    if (buffer->size() < bodyStart + contentLength)
        return false;
    request.m_body = buffer->mid(bodyStart, contentLength);

    const bool headOnly = request.m_method == QHttpServerRequest::Method::Head;
    QHttpServerResponse response = m_handler ? m_handler(request) : badRequest();
    sendResponse(socket, std::move(response), headOnly);
    return true;
}

void Server::sendResponse(QTcpSocket *socket, QHttpServerResponse response, bool headOnly)
{
    if (!socket)
        return;

    const QByteArray body = response.data();
    const int code = statusCode(response.statusCode());
    QByteArray raw;
    raw += "HTTP/1.1 " + QByteArray::number(code) + ' ' + reasonPhrase(code) + "\r\n";

    QHttpHeaders headers = response.headers();
    if (!response.mimeType().isEmpty() && !headers.contains(QHttpHeaders::WellKnownHeader::ContentType))
        headers.append(QHttpHeaders::WellKnownHeader::ContentType, QString::fromLatin1(response.mimeType()));
    headers.replaceOrAppend(QHttpHeaders::WellKnownHeader::ContentLength, QString::number(body.size()));
    headers.replaceOrAppend(QHttpHeaders::WellKnownHeader::Connection, QStringLiteral("close"));
    for (const auto &header : headers.toListOfPairs())
        raw += header.first + ": " + header.second + "\r\n";
    raw += "\r\n";
    if (!headOnly)
        raw += body;

    socket->write(raw);
    socket->flush();
    socket->disconnectFromHost();
}

} // namespace PgsHttp
