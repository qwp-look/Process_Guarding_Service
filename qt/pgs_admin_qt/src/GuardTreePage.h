/**
 * @file GuardTreePage.h
 * @brief Task-manager style main page for the PGS Qt admin.
 *
 * Talks the management protocol directly through the shared ProcessGuard::client
 * (no QProcess per refresh): a timer polls `list` + `families` + `stats` and
 * renders guards as a tree — group nodes, guard rows (status / protected time /
 * trigger count / health / last failure) and, expandable per guard, the live
 * Job Object process family. Right-click offers add/close protection,
 * intentional exit, quarantine retry/clear and group operations.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef GUARDTREEPAGE_H
#define GUARDTREEPAGE_H

#include <QHash>
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
        QString appKind;
        bool alive = false;
        QString rawLine;
    };
    struct FamilyMember
    {
        quint32 pid = 0;
        QString name;
    };

    void setupUi();
    void retranslateUi();
    void rebuildTree();
    void applyFilter();
    void sendAction(const QString &command);
    QString trUi(const QString &en, const QString &zh) const { return m_chinese ? zh : en; }
    static QString formatDuration(qint64 ms);
    static QString statusText(const QString &status, bool chinese);
    QString currentGuardKey() const;

    bool m_chinese = false;
    QString m_toolPath;
    QString m_token;
    QString m_host = QStringLiteral("127.0.0.1");
    quint16 m_port = 12345;

    QTimer *m_timer = nullptr;
    bool m_paused = false;

    QLineEdit *m_hostEdit = nullptr;
    QLineEdit *m_portEdit = nullptr;
    QComboBox *m_intervalCombo = nullptr;
    QPushButton *m_btnAdd = nullptr;
    QPushButton *m_btnPauseRefresh = nullptr;
    QLineEdit *m_filterEdit = nullptr;
    QLabel *m_statsLabel = nullptr;

    QTreeView *m_tree = nullptr;
    QStandardItemModel *m_model = nullptr;

    QProcess *m_addProcess = nullptr;

    QVector<GuardRow> m_guards;
    QHash<quint64, QVector<FamilyMember>> m_families;
    QString m_lastError;
};

#endif // GUARDTREEPAGE_H
