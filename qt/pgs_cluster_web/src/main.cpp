/**
 * @file main.cpp
 * @brief pgs_cluster_web entrypoint - the Stage D cluster dashboard server.
 *
 * Usage:
 *   pgs_cluster_web.exe --listen-address 127.0.0.1 --listen-port 19090 --nodes-file nodes.txt
 *   pgs_cluster_web.exe --listen-address 0.0.0.0 --listen-port 19090 --api-token <token> --tls-cert cert.pem --tls-key key.pem
 *   pgs_cluster_web.exe --node-ca-cert private-ca.pem
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "ClusterServer.h"

#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QTextStream>

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("pgs_cluster_web"));
    app.setApplicationVersion(QStringLiteral("1.0"));

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("PGS cluster monitoring dashboard"));
    parser.addHelpOption();
    parser.addVersionOption();

    QCommandLineOption portOption(QStringList{QStringLiteral("listen-port")}, QStringLiteral("HTTP(S) listen port"), QStringLiteral("port"), QStringLiteral("19090"));
    QCommandLineOption addressOption(QStringList{QStringLiteral("listen-address")}, QStringLiteral("Listen address; non-loopback requires --api-token, --tls-cert, and --tls-key"), QStringLiteral("address"), QStringLiteral("127.0.0.1"));
    QCommandLineOption nodesOption(QStringList{QStringLiteral("nodes-file")}, QStringLiteral("Node registry file (name;url;user:pass)"), QStringLiteral("path"), QStringLiteral("pgs_cluster_nodes.txt"));
    QCommandLineOption apiTokenOption(QStringList{QStringLiteral("api-token")}, QStringLiteral("Management API token for /api/cluster/*"), QStringLiteral("token"));
    QCommandLineOption tlsCertOption(QStringList{QStringLiteral("tls-cert")}, QStringLiteral("PEM certificate for HTTPS listener"), QStringLiteral("path"));
    QCommandLineOption tlsKeyOption(QStringList{QStringLiteral("tls-key")}, QStringLiteral("PEM private key for HTTPS listener"), QStringLiteral("path"));
    QCommandLineOption nodeCaCertOption(QStringList{QStringLiteral("node-ca-cert")}, QStringLiteral("PEM CA certificate for verifying node HTTPS"), QStringLiteral("path"));
    QCommandLineOption nodeInsecureTlsOption(QStringList{QStringLiteral("node-insecure-tls")}, QStringLiteral("Disable node TLS certificate verification (lab-only; exposes node Basic credentials to MITM)"));
    parser.addOption(portOption);
    parser.addOption(addressOption);
    parser.addOption(nodesOption);
    parser.addOption(apiTokenOption);
    parser.addOption(tlsCertOption);
    parser.addOption(tlsKeyOption);
    parser.addOption(nodeCaCertOption);
    parser.addOption(nodeInsecureTlsOption);
    parser.process(app);

    bool ok = false;
    const quint16 port = static_cast<quint16>(parser.value(portOption).toUShort(&ok));
    if (!ok || port == 0)
    {
        QTextStream(stderr) << "Invalid --listen-port\n";
        return 1;
    }

    ClusterServer server(parser.value(nodesOption), parser.value(addressOption), port,
                         parser.value(apiTokenOption), parser.value(tlsCertOption),
                         parser.value(tlsKeyOption), parser.value(nodeCaCertOption),
                         parser.isSet(nodeInsecureTlsOption));
    if (!server.start())
    {
        QTextStream(stderr) << "Failed to listen on " << parser.value(addressOption) << ':' << port
                            << " (invalid address, port in use, TLS error, node CA error, or non-loopback binding without explicit token+TLS)\n";
        return 1;
    }
    QTextStream(stdout) << "PGS cluster dashboard listening at " << server.listenUrl() << "\n";
    return app.exec();
}
