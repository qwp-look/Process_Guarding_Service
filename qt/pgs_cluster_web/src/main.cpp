/**
 * @file main.cpp
 * @brief pgs_cluster_web entrypoint - the Stage D cluster dashboard server.
 *
 * Usage:
 *   pgs_cluster_web.exe --listen-port 19090 --nodes-file nodes.txt
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

    QCommandLineOption portOption(QStringList{QStringLiteral("listen-port")}, QStringLiteral("HTTP listen port"), QStringLiteral("port"), QStringLiteral("19090"));
    QCommandLineOption nodesOption(QStringList{QStringLiteral("nodes-file")}, QStringLiteral("Node registry file (name;url;user:pass)"), QStringLiteral("path"), QStringLiteral("pgs_cluster_nodes.txt"));
    parser.addOption(portOption);
    parser.addOption(nodesOption);
    parser.process(app);

    bool ok = false;
    const quint16 port = static_cast<quint16>(parser.value(portOption).toUShort(&ok));
    if (!ok || port == 0)
    {
        QTextStream(stderr) << "Invalid --listen-port\n";
        return 1;
    }

    ClusterServer server(parser.value(nodesOption), port);
    if (!server.start())
    {
        QTextStream(stderr) << "Failed to listen on port " << port << "\n";
        return 1;
    }
    QTextStream(stdout) << "PGS cluster dashboard listening at " << server.listenUrl() << "\n";
    return app.exec();
}
