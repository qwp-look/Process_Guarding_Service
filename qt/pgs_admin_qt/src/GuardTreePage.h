/**
 * @file GuardTreePage.h
 * @brief Task-manager style main page for the PGS Qt admin.
 *
 * Shows ALL running processes (client-side Win32 snapshot, parent-child tree,
 * CPU/memory columns) and overlays the PGS guard state on top: protected
 * processes are highlighted and carry protected-time / trigger-count columns.
 * Right-click any unprotected process to protect it (protocol `bless <pid>`),
 * and any protected process to close protection, do an intentional exit,
 * retry/clear quarantine or manage its group. "Add protection" on the toolbar
 * launches a brand-new program via a one-shot pgs_bless bless-start.
 *
 * Data paths: the process list never crosses the protocol (the UI runs on the
 * same machine); the service protocol is used for the guard list (1 Hz `list`
 * poll) and for actions.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef GUARDTREEPAGE_H
#define GUARDTREEPAGE_H

#include <QHash>
#include <QPair>
#include <QString>
#include <QVector>
#include <QWidget>

class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QStandardItem;
class QStandardItemModel;
class QTimer;
class QTreeView;
class QProcess;

class GuardTreePage : public QWidget
{
    Q_OBJECT
public:
    explicit GuardTreePage(QWidget *parent = nullptr);

    void setChinese(bool ch);
    void setToolPath(const QString &path);
    void setToken(const QString &token);
    void setEndpoint(const QString &host, quint16 port);

private slots:
    void refreshNow();
    void addProtection();
    void protectProcess();
    void closeProtection();
    void intentionalExit();
    void retryQuarantine();
    void clearQuarantine();
    void assignGroup(const QString &group);
    void removeFromGroup();
    void groupPauseResume(const QString &group, bool pause);
    void groupRestart(const QString &group);
    void showDetails();

private:
    // One row of `list` (the service's guard summary line).
    struct GuardRow
    {
        quint64 guardId = 0;
        quint32 pid = 0;
        QString status;
        qint64 cumulativeRunMs = 0;
        int restartCount = 0;
        QString group;
        QString healthStatus;
        QString lastFailureCode;
        QString lastFailure;
        QString path;
        bool alive = false;
        QString rawLine;
    };
    // One process from the client-side snapshot.
    struct ProcRow
    {
        quint32 pid = 0;
        quint32 parentPid = 0;
        QString name;
        QString imagePath;
        double cpuPercent = 0.0;
        quint64 memoryBytes = 0;
        const GuardRow *guard = nullptr; // set when the pid is protected
    };

    void setupUi();
    void retranslateUi();
    void snapshotProcesses();
    void rebuildTree();
    void applyFilter();
    void sendAction(const QString &command);
    QString trUi(const QString &en, const QString &zh) const { return m_chinese ? zh : en; }
    static QString formatDuration(qint64 ms);
    static QString formatBytes(quint64 bytes);
    static QString statusText(const QString &status, bool chinese);
    static QString baseName(const QString &path);
    QString keyForPid(quint32 pid, bool guarded) const;
    QString currentProcKey() const;

    bool m_chinese = false;
    QString m_toolPath;
    QString m_token;
    QString m_host = QStringLiteral("127.0.0.1");
    quint16 m_port = 12345;

    QTimer *m_timer = nullptr;
    bool m_paused = false;
    bool m_onlyProtected = false;

    QPushButton *m_btnAdd = nullptr;
    QPushButton *m_btnOnlyProtected = nullptr;
    QPushButton *m_btnPauseRefresh = nullptr;
    QComboBox *m_intervalCombo = nullptr;
    QLineEdit *m_filterEdit = nullptr;
    QLineEdit *m_hostEdit = nullptr;
    QLineEdit *m_portEdit = nullptr;
    QLabel *m_statsLabel = nullptr;

    QTreeView *m_tree = nullptr;
    QStandardItemModel *m_model = nullptr;

    QProcess *m_addProcess = nullptr;

    QVector<GuardRow> m_guards;
    QHash<quint32, GuardRow> m_guardsByPid;
    QVector<ProcRow> m_procs;
    // pid -> (kernelTime100ns, userTime100ns) of the previous sample, for CPU%.
    QHash<quint32, QPair<quint64, quint64>> m_prevCpuTimes;
    qint64 m_prevWallMs = 0;
    QString m_lastError;
};

#endif // GUARDTREEPAGE_H
