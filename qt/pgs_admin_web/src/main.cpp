#include "WebServer.h"

#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QStringView>
#include <QTextStream>

namespace
{
bool parsePort(QStringView text, quint16 &outPort)
{
    bool ok = false;
    const uint value = text.toUInt(&ok);
    if (!ok || value == 0 || value > 65535)
    {
        return false;
    }
    outPort = static_cast<quint16>(value);
    return true;
}
} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("pgs_admin_web"));
    app.setApplicationVersion(QStringLiteral("1.0"));

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("ProcessGuard web control console"));
    parser.addHelpOption();
    parser.addVersionOption();

    QCommandLineOption bindOption(QStringList{QStringLiteral("bind")}, QStringLiteral("HTTP bind address"), QStringLiteral("address"), QStringLiteral("127.0.0.1"));
    QCommandLineOption httpPortOption(QStringList{QStringLiteral("http-port")}, QStringLiteral("HTTP listen port"), QStringLiteral("port"), QStringLiteral("18080"));
    QCommandLineOption pgsHostOption(QStringList{QStringLiteral("pgs-host")}, QStringLiteral("PGS host"), QStringLiteral("host"), QStringLiteral("127.0.0.1"));
    QCommandLineOption pgsPortOption(QStringList{QStringLiteral("pgs-port")}, QStringLiteral("PGS port"), QStringLiteral("port"), QStringLiteral("12345"));
    QCommandLineOption tokenOption(QStringList{QStringLiteral("pgs-token")}, QStringLiteral("PGS token held by the web backend"), QStringLiteral("token"));
    QCommandLineOption blessToolOption(QStringList{QStringLiteral("bless-tool")}, QStringLiteral("Path to pgs_bless.exe"), QStringLiteral("path"));
    QCommandLineOption serviceToolOption(QStringList{QStringLiteral("service-tool")}, QStringLiteral("Path to pgs_service.exe"), QStringLiteral("path"));
    QCommandLineOption remoteOption(QStringList{QStringLiteral("remote")}, QStringLiteral("Enable remote-gateway mode (forces TLS + RBAC, allows non-loopback bind)"));
    QCommandLineOption tlsCertOption(QStringList{QStringLiteral("tls-cert")}, QStringLiteral("TLS certificate PEM (remote mode)"), QStringLiteral("path"));
    QCommandLineOption tlsKeyOption(QStringList{QStringLiteral("tls-key")}, QStringLiteral("TLS private key PEM (remote mode)"), QStringLiteral("path"));
    QCommandLineOption usersOption(QStringList{QStringLiteral("users-file")}, QStringLiteral("RBAC users file: user;role;saltHex;hashHex"), QStringLiteral("path"));
    QCommandLineOption auditOption(QStringList{QStringLiteral("audit-log")}, QStringLiteral("Audit log path for mutating remote ops"), QStringLiteral("path"));

    parser.addOption(bindOption);
    parser.addOption(httpPortOption);
    parser.addOption(pgsHostOption);
    parser.addOption(pgsPortOption);
    parser.addOption(tokenOption);
    parser.addOption(blessToolOption);
    parser.addOption(serviceToolOption);
    parser.addOption(remoteOption);
    parser.addOption(tlsCertOption);
    parser.addOption(tlsKeyOption);
    parser.addOption(usersOption);
    parser.addOption(auditOption);
    parser.process(app);

    WebServer::Options options;
    // Default posture is local-only administration. Exposing the web console to
    // wider networks should be a deliberate deployment decision, not the default.
    options.bindAddress = parser.value(bindOption);
    if (options.remote && options.bindAddress == QStringLiteral("127.0.0.1"))
        options.bindAddress = QStringLiteral("0.0.0.0");
    options.pgsHost = parser.value(pgsHostOption);
    options.pgsToken = parser.value(tokenOption);
    options.blessToolPath = parser.value(blessToolOption);
    options.serviceToolPath = parser.value(serviceToolOption);
    options.remote = parser.isSet(remoteOption);
    options.tlsCertPath = parser.value(tlsCertOption);
    options.tlsKeyPath = parser.value(tlsKeyOption);
    options.tlsAutocert = false;
    options.usersFile = parser.value(usersOption);
    options.auditLogPath = parser.value(auditOption);

    if (!parsePort(parser.value(httpPortOption), options.httpPort))
    {
        QTextStream(stderr) << "Invalid --http-port: " << parser.value(httpPortOption) << "\n";
        return 1;
    }
    if (!parsePort(parser.value(pgsPortOption), options.pgsPort))
    {
        QTextStream(stderr) << "Invalid --pgs-port: " << parser.value(pgsPortOption) << "\n";
        return 1;
    }

    WebServer server(options);
    if (!server.start())
    {
        QTextStream(stderr) << "Failed to listen on " << options.bindAddress << ":" << options.httpPort << "\n";
        return 1;
    }

    QTextStream(stdout) << "PGS web console listening at " << server.listenUrl() << "\n";
    return app.exec();
}
