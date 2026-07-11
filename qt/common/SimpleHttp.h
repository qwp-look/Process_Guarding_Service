#ifndef PGS_SIMPLE_HTTP_H
#define PGS_SIMPLE_HTTP_H

#include <QByteArray>
#include <QHash>
#include <QHostAddress>
#include <QHttpServerRequest>
#include <QHttpServerResponse>
#include <QObject>
#include <QUrl>
#include <QUrlQuery>
#include <functional>

class QTcpServer;
class QTcpSocket;

namespace PgsHttp
{

class Request
{
public:
    QByteArray value(const QByteArray &key) const;
    QUrl url() const { return m_url; }
    QUrlQuery query() const { return QUrlQuery(m_url); }
    QHttpServerRequest::Method method() const { return m_method; }
    QByteArray body() const { return m_body; }
    QHostAddress remoteAddress() const { return m_remoteAddress; }
    quint16 remotePort() const { return m_remotePort; }
    QHostAddress localAddress() const { return m_localAddress; }
    quint16 localPort() const { return m_localPort; }
    QString path() const { return m_url.path(); }

private:
    friend class Server;
    QHttpServerRequest::Method m_method = QHttpServerRequest::Method::Unknown;
    QUrl m_url;
    QHash<QByteArray, QByteArray> m_headers;
    QByteArray m_body;
    QHostAddress m_remoteAddress;
    quint16 m_remotePort = 0;
    QHostAddress m_localAddress;
    quint16 m_localPort = 0;
};

class Server : public QObject
{
    Q_OBJECT

public:
    using Handler = std::function<QHttpServerResponse(const Request &)>;

    explicit Server(QObject *parent = nullptr);
    bool bind(QTcpServer *listener, Handler handler);

private:
    void drainConnections();
    void readSocket(QTcpSocket *socket, QByteArray *buffer);
    bool tryHandle(QTcpSocket *socket, QByteArray *buffer);
    void sendResponse(QTcpSocket *socket, QHttpServerResponse response, bool headOnly);

    QTcpServer *m_listener = nullptr;
    Handler m_handler;
};

} // namespace PgsHttp

#endif // PGS_SIMPLE_HTTP_H
