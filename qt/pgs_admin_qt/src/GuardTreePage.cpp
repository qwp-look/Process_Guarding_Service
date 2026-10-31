/**
 * @file GuardTreePage.cpp
 * @brief Task-manager style main page (see GuardTreePage.h).
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "GuardTreePage.h"

#include "Process_Guard/PGSClient.h"

#include <QBrush>
#include <QColor>
#include <QComboBox>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QHash>
#include <QHeaderView>
#include <QInputDialog>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QSet>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QTimer>
#include <QTreeView>
#include <QVBoxLayout>

#include <algorithm>

using ProcessGuard::client::ClientOptions;
using ProcessGuard::client::sendCommand;

namespace
{
    constexpr int kColumnCount = 8;
    constexpr int kColName = 0;
    constexpr int kColPid = 1;
    constexpr int kColStatus = 2;
    constexpr int kColRuntime = 3;
    constexpr int kColRestarts = 4;
    constexpr int kColGroup = 5;
    constexpr int kColHealth = 6;
    constexpr int kColFailure = 7;

    QString kvValue(const QString &kv, const QString &key)
    {
        const int pos = kv.indexOf(key + QLatin1Char('='));
        if (pos < 0) return QString();
        const int start = pos + key.size() + 1;
        int end = kv.indexOf(QLatin1Char(';'), start);
        if (end < 0) end = kv.size();
        return kv.mid(start, end - start);
    }

    QString decodeB64(const QString &value)
    {
        if (value.isEmpty() || value == QLatin1String("-")) return QString();
        return QString::fromUtf8(QByteArray::fromBase64(value.toUtf8()));
    }

    QString baseName(const QString &path)
    {
        QString cleaned = path;
        cleaned.replace(QLatin1Char('/'), QLatin1Char('\\'));
        const int slash = cleaned.lastIndexOf(QLatin1Char('\\'));
        return slash >= 0 ? cleaned.mid(slash + 1) : cleaned;
    }

    QColor statusColor(const QString &status)
    {
        if (status == QLatin1String("active")) return QColor(0x39, 0xd3, 0x53);
        if (status == QLatin1String("paused")) return QColor(0xd2, 0x99, 0x22);
        if (status == QLatin1String("quarantined")) return QColor(0xf8, 0x51, 0x49);
        return QColor(0x8b, 0x94, 0x9e);
    }
} // namespace

GuardTreePage::GuardTreePage(QWidget *parent)
    : QWidget(parent)
{
    setupUi();
    retranslateUi();

    m_timer = new QTimer(this);
    connect(m_timer, &QTimer::timeout, this, &GuardTreePage::refreshNow);
    m_timer->start(1000);
    QTimer::singleShot(200, this, &GuardTreePage::refreshNow);
}

void GuardTreePage::setupUi()
{
    auto *layout = new QVBoxLayout(this);

    auto *toolbar = new QHBoxLayout();
    m_btnAdd = new QPushButton(this);
    toolbar->addWidget(m_btnAdd);

    m_btnPauseRefresh = new QPushButton(this);
    m_btnPauseRefresh->setCheckable(true);
    connect(m_btnPauseRefresh, &QPushButton::toggled, this, [this](bool checked) {
        m_paused = checked;
        retranslateUi();
    });
    toolbar->addWidget(m_btnPauseRefresh);

    m_intervalCombo = new QComboBox(this);
    m_intervalCombo->addItem(QStringLiteral("1s"), 1000);
    m_intervalCombo->addItem(QStringLiteral("2s"), 2000);
    m_intervalCombo->addItem(QStringLiteral("5s"), 5000);
    m_intervalCombo->addItem(QStringLiteral("10s"), 10000);
    connect(m_intervalCombo, &QComboBox::currentIndexChanged, this, [this](int index) {
        if (index >= 0 && m_timer)
        {
            m_timer->setInterval(m_intervalCombo->itemData(index).toInt());
        }
    });
    toolbar->addWidget(m_intervalCombo);

    toolbar->addStretch();
    m_filterEdit = new QLineEdit(this);
    m_filterEdit->setClearButtonEnabled(true);
    m_filterEdit->setMaximumWidth(220);
    connect(m_filterEdit, &QLineEdit::textChanged, this, [this](const QString &) { applyFilter(); });
    toolbar->addWidget(m_filterEdit);

    toolbar->addWidget(new QLabel(QStringLiteral("host"), this));
    m_hostEdit = new QLineEdit(this);
    m_hostEdit->setMaximumWidth(120);
    connect(m_hostEdit, &QLineEdit::editingFinished, this, [this]() {
        m_host = m_hostEdit->text().trimmed().isEmpty() ? QStringLiteral("127.0.0.1")
                                                        : m_hostEdit->text().trimmed();
    });
    toolbar->addWidget(m_hostEdit);

    toolbar->addWidget(new QLabel(QStringLiteral("port"), this));
    m_portEdit = new QLineEdit(this);
    m_portEdit->setMaximumWidth(70);
    connect(m_portEdit, &QLineEdit::editingFinished, this, [this]() {
        bool ok = false;
        const uint port = m_portEdit->text().toUInt(&ok);
        if (ok && port > 0 && port <= 65535) m_port = static_cast<quint16>(port);
    });
    toolbar->addWidget(m_portEdit);
    layout->addLayout(toolbar);

    m_model = new QStandardItemModel(this);
    m_model->setColumnCount(kColumnCount);
    m_tree = new QTreeView(this);
    m_tree->setModel(m_model);
    m_tree->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tree->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tree->setAlternatingRowColors(true);
    m_tree->setUniformRowHeights(true);
    m_tree->header()->setStretchLastSection(true);
    m_tree->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_tree, &QTreeView::customContextMenuRequested, this, [this](const QPoint &pos) {
        const QModelIndex index = m_tree->indexAt(pos);
        if (!index.isValid()) return;
        m_tree->setCurrentIndex(index);
        QMenu menu(this);
        menu.addAction(trUi("添加保护", "Add protection"), this, &GuardTreePage::addProtection);

        const QString key = currentGuardKey();
        if (key.startsWith(QLatin1String("guard:")))
        {
            menu.addSeparator();
            menu.addAction(trUi("关闭保护", "Close protection"), this, &GuardTreePage::closeProtection);
            menu.addAction(trUi("立即退出并解除", "Intentional exit and unregister"), this, &GuardTreePage::intentionalExit);
            const quint64 guardId = key.mid(QString::fromLatin1("guard:").size()).toULongLong();
            for (const GuardRow &row : m_guards)
            {
                if (row.guardId != guardId) continue;
                if (row.status == QLatin1String("quarantined"))
                {
                    menu.addAction(trUi("重试隔离的守护", "Retry quarantined guard"), this, &GuardTreePage::retryQuarantine);
                    menu.addAction(trUi("清除隔离记录", "Clear quarantine"), this, &GuardTreePage::clearQuarantine);
                }
                menu.addSeparator();
                QMenu *groupMenu = menu.addMenu(trUi("分组", "Group"));
                QSet<QString> groups;
                for (const GuardRow &candidate : m_guards)
                {
                    if (!candidate.group.isEmpty()) groups.insert(candidate.group);
                }
                groups.remove(row.group);
                for (const QString &group : groups)
                {
                    groupMenu->addAction(trUi("加入 %1", "Join %1").arg(group), this, [this, group]() { assignGroup(group); });
                }
                groupMenu->addAction(trUi("新建分组…", "New group…"), this, [this]() {
                    bool ok = false;
                    const QString name = QInputDialog::getText(this,
                        trUi("新建分组", "New group"),
                        trUi("分组名称", "Group name"), QLineEdit::Normal, QString(), &ok);
                    if (ok && !name.trimmed().isEmpty()) assignGroup(name.trimmed());
                });
                if (!row.group.isEmpty())
                {
                    groupMenu->addAction(trUi("从 %1 移除", "Remove from %1").arg(row.group), this, &GuardTreePage::removeFromGroup);
                    groupMenu->addSeparator();
                    groupMenu->addAction(trUi("暂停 %1", "Pause %1").arg(row.group), this, [this, row]() { groupPauseResume(row.group, true); });
                    groupMenu->addAction(trUi("恢复 %1", "Resume %1").arg(row.group), this, [this, row]() { groupPauseResume(row.group, false); });
                    groupMenu->addAction(trUi("重启 %1", "Restart %1").arg(row.group), this, [this, row]() { groupRestart(row.group); });
                }
                break;
            }
        }
        else if (key.startsWith(QLatin1String("group:")))
        {
            const QString group = key.mid(QString::fromLatin1("group:").size());
            menu.addSeparator();
            menu.addAction(trUi("重启分组", "Restart group"), this, [this, group]() { groupRestart(group); });
            menu.addAction(trUi("暂停分组", "Pause group"), this, [this, group]() { groupPauseResume(group, true); });
            menu.addAction(trUi("恢复分组", "Resume group"), this, [this, group]() { groupPauseResume(group, false); });
        }
        menu.addSeparator();
        menu.addAction(trUi("属性", "Properties"), this, &GuardTreePage::showDetails);
        menu.exec(m_tree->viewport()->mapToGlobal(pos));
    });
    connect(m_tree, &QTreeView::doubleClicked, this, [this](const QModelIndex &) { showDetails(); });
    layout->addWidget(m_tree, 1);

    auto *statusRow = new QHBoxLayout();
    m_statsLabel = new QLabel(this);
    m_statsLabel->setObjectName(QStringLiteral("guardStatsLabel"));
    statusRow->addWidget(m_statsLabel, 1);
    layout->addLayout(statusRow);

    connect(m_btnAdd, &QPushButton::clicked, this, &GuardTreePage::addProtection);
}

void GuardTreePage::retranslateUi()
{
    m_btnAdd->setText(trUi("添加保护", "Add protection"));
    m_btnPauseRefresh->setText(m_paused ? trUi("恢复刷新", "Resume refresh")
                                        : trUi("暂停刷新", "Pause refresh"));
    m_filterEdit->setPlaceholderText(trUi("按名称过滤", "Filter by name"));
    m_model->setHorizontalHeaderLabels(QStringList{
        trUi("名称", "Name"),
        trUi("PID", "PID"),
        trUi("状态", "Status"),
        trUi("保护时长", "Protected time"),
        trUi("触发保护", "Triggers"),
        trUi("分组", "Group"),
        trUi("健康", "Health"),
        trUi("上次失败", "Last failure")});
    m_tree->header()->resizeSection(kColName, 220);
    m_tree->header()->resizeSection(kColPid, 70);
    m_tree->header()->resizeSection(kColStatus, 100);
    m_tree->header()->resizeSection(kColRuntime, 110);
    m_tree->header()->resizeSection(kColRestarts, 80);
    m_tree->header()->resizeSection(kColGroup, 100);
    m_tree->header()->resizeSection(kColHealth, 80);
}

void GuardTreePage::setChinese(bool ch)
{
    if (m_chinese == ch) return;
    m_chinese = ch;
    retranslateUi();
}

void GuardTreePage::setToolPath(const QString &path)
{
    if (!path.isEmpty()) m_toolPath = path;
}

void GuardTreePage::setToken(const QString &token)
{
    m_token = token;
}

void GuardTreePage::setEndpoint(const QString &host, quint16 port)
{
    if (!host.isEmpty()) { m_host = host; m_hostEdit->setText(host); }
    if (port > 0) { m_port = port; m_portEdit->setText(QString::number(port)); }
}

void GuardTreePage::refreshNow()
{
    if (m_paused) return;

    ClientOptions options;
    options.host = m_host.toStdString();
    options.port = m_port;
    options.token = m_token.toStdString();

    QVector<GuardRow> guards;
    QHash<quint64, QVector<FamilyMember>> families;
    QString statsText;
    QString error;

    const ProcessGuard::client::ClientResponse listReply = sendCommand(options, "list", 800);
    if (!listReply.ok)
    {
        error = QString::fromStdString(listReply.error);
    }
    else
    {
        const QStringList lines = QString::fromStdString(listReply.payload).split(QLatin1Char('\n'));
        for (const QString &line : lines)
        {
            if (!line.startsWith(QLatin1String("PID="))) continue;
            GuardRow row;
            row.rawLine = line;
            row.pid = kvValue(line, "PID").toUInt();
            row.guardId = kvValue(line, "GUARD_ID").toULongLong();
            row.status = kvValue(line, "STATUS");
            row.cumulativeRunMs = kvValue(line, "CUMULATIVE_RUN_MS").toLongLong();
            row.restartCount = kvValue(line, "RESTART_COUNT").toInt();
            row.group = kvValue(line, "GROUP");
            if (row.group == QLatin1String("-")) row.group.clear();
            row.healthStatus = kvValue(line, "HEALTH_STATUS");
            row.lastFailureCode = kvValue(line, "LAST_FAILURE_CODE");
            if (row.lastFailureCode == QLatin1String("-")) row.lastFailureCode.clear();
            row.lastFailure = decodeB64(kvValue(line, "LAST_FAILURE_B64"));
            row.path = decodeB64(kvValue(line, "PATH_B64"));
            row.appKind = kvValue(line, "APP_KIND");
            row.alive = kvValue(line, "ALIVE") == QLatin1String("1");
            guards.push_back(row);
        }

        const ProcessGuard::client::ClientResponse familiesReply = sendCommand(options, "families", 800);
        if (familiesReply.ok)
        {
            const QStringList familyLines = QString::fromStdString(familiesReply.payload).split(QLatin1Char('\n'));
            for (const QString &line : familyLines)
            {
                if (!line.startsWith(QLatin1String("FAMILY "))) continue;
                const quint64 guardId = kvValue(line, "guard_id").toULongLong();
                const QByteArray membersJson = QByteArray::fromBase64(kvValue(line, "members_b64").toUtf8());
                QVector<FamilyMember> members;
                const QJsonDocument doc = QJsonDocument::fromJson(membersJson);
                if (doc.isArray())
                {
                    for (const QJsonValue &value : doc.array())
                    {
                        FamilyMember member;
                        member.pid = static_cast<quint32>(value.toObject().value(QLatin1String("pid")).toInt());
                        member.name = value.toObject().value(QLatin1String("name")).toString();
                        members.push_back(member);
                    }
                }
                families.insert(guardId, members);
            }
        }

        const ProcessGuard::client::ClientResponse statsReply = sendCommand(options, "stats", 800);
        if (statsReply.ok)
        {
            statsText = QString::fromStdString(statsReply.payload);
        }
    }

    m_guards = guards;
    m_families = families;
    m_lastError = error;
    if (!statsText.isEmpty())
    {
        m_statsLabel->setText(QString::fromStdString(statsText.toStdString()));
    }
    else if (!error.isEmpty())
    {
        m_statsLabel->setText(trUi("无法连接服务：%1", "Cannot reach service: %1").arg(error));
    }
    else
    {
        m_statsLabel->setText(QString());
    }
    rebuildTree();
    applyFilter();
}

void GuardTreePage::rebuildTree()
{
    // Preserve expansion + selection across rebuilds via node keys stored in
    // Qt::UserRole ("group:<name>" / "guard:<id>" / "member:<pid>").
    QSet<QString> expanded;
    for (int r = 0; r < m_model->rowCount(); ++r)
    {
        QStandardItem *groupItem = m_model->item(r, 0);
        if (m_tree->isExpanded(groupItem->index()))
        {
            expanded.insert(groupItem->data(Qt::UserRole).toString());
        }
        for (int gr = 0; gr < groupItem->rowCount(); ++gr)
        {
            QStandardItem *guardItem = groupItem->child(gr, 0);
            if (guardItem && m_tree->isExpanded(guardItem->index()))
            {
                expanded.insert(guardItem->data(Qt::UserRole).toString());
            }
        }
    }
    QStandardItem *selectedItem = m_model->itemFromIndex(m_tree->currentIndex().siblingAtColumn(0));
    const QString selectedKey = selectedItem ? selectedItem->data(Qt::UserRole).toString() : QString();

    m_model->removeRows(0, m_model->rowCount());

    // Group guards by their group name (empty group -> a synthetic bucket).
    QHash<QString, QVector<const GuardRow *>> byGroup;
    for (const GuardRow &row : m_guards)
    {
        byGroup[row.group.isEmpty() ? trUi("默认", "Default") : row.group].push_back(&row);
    }
    QStringList groupNames;
    for (auto it = byGroup.constBegin(); it != byGroup.constEnd(); ++it) groupNames << it.key();
    groupNames.sort();

    for (const QString &groupName : groupNames)
    {
        QList<const GuardRow *> rows;
        for (const GuardRow *row : byGroup[groupName]) rows.push_back(row);
        std::sort(rows.begin(), rows.end(), [](const GuardRow *a, const GuardRow *b) {
            return baseName(a->path).compare(baseName(b->path), Qt::CaseInsensitive) < 0;
        });

        QStandardItem *groupItem = new QStandardItem(groupName);
        groupItem->setData("group:" + groupName, Qt::UserRole);
        groupItem->setForeground(QBrush(QColor(0xd2, 0xa8, 0xff)));

        int groupActive = 0;
        int groupRestarts = 0;
        for (const GuardRow *row : rows)
        {
            if (row->status == QLatin1String("active")) ++groupActive;
            groupRestarts += row->restartCount;
        }
        QList<QStandardItem *> groupRow;
        groupRow << groupItem
                 << new QStandardItem(QString())
                 << new QStandardItem(trUi("%1/%2 运行中", "%1/%2 running").arg(groupActive).arg(rows.size()))
                 << new QStandardItem(QString())
                 << new QStandardItem(QString::number(groupRestarts))
                 << new QStandardItem(QString())
                 << new QStandardItem(QString())
                 << new QStandardItem(QString());
        m_model->appendRow(groupRow);

        for (const GuardRow *row : rows)
        {
            const QString name = baseName(row->path);
            const QString guardKey = "guard:" + QString::number(row->guardId);

            QStandardItem *nameItem = new QStandardItem(name);
            nameItem->setData(guardKey, Qt::UserRole);
            nameItem->setToolTip(row->path);

            QStandardItem *pidItem = new QStandardItem(row->alive ? QString::number(row->pid) : QStringLiteral("-"));
            pidItem->setData(guardKey, Qt::UserRole);

            QStandardItem *statusItem = new QStandardItem(statusText(row->status, m_chinese));
            statusItem->setData(guardKey, Qt::UserRole);
            statusItem->setForeground(QBrush(statusColor(row->status)));

            QStandardItem *runtimeItem = new QStandardItem(formatDuration(row->cumulativeRunMs));
            runtimeItem->setData(guardKey, Qt::UserRole);

            QStandardItem *restartItem = new QStandardItem(QString::number(row->restartCount));
            restartItem->setData(guardKey, Qt::UserRole);

            QStandardItem *groupCell = new QStandardItem(row->group);
            groupCell->setData(guardKey, Qt::UserRole);

            QStandardItem *healthItem = new QStandardItem(
                row->healthStatus == QLatin1String("disabled") ? QStringLiteral("-") : row->healthStatus);
            healthItem->setData(guardKey, Qt::UserRole);

            QStandardItem *failureItem = new QStandardItem(row->lastFailureCode);
            failureItem->setData(guardKey, Qt::UserRole);
            if (!row->lastFailure.isEmpty()) failureItem->setToolTip(row->lastFailure);

            QList<QStandardItem *> guardRow;
            guardRow << nameItem << pidItem << statusItem << runtimeItem
                     << restartItem << groupCell << healthItem << failureItem;
            groupItem->appendRow(guardRow);

            // Process family children (Job Object members) — the task-manager
            // style process tree under each guard.
            const QVector<FamilyMember> members = m_families.value(row->guardId);
            for (const FamilyMember &member : members)
            {
                if (member.pid == row->pid) continue;
                const QString memberKey = "member:" + QString::number(member.pid);
                QStandardItem *memberName = new QStandardItem(
                    member.name.isEmpty() ? trUi("(进程 %1)", "(process %1)").arg(member.pid) : member.name);
                memberName->setData(memberKey, Qt::UserRole);
                memberName->setForeground(QBrush(QColor(0x8b, 0x94, 0x9e)));
                QStandardItem *memberPid = new QStandardItem(QString::number(member.pid));
                memberPid->setData(memberKey, Qt::UserRole);
                memberPid->setForeground(QBrush(QColor(0x8b, 0x94, 0x9e)));
                QList<QStandardItem *> memberRow;
                memberRow << memberName << memberPid;
                for (int col = 2; col < kColumnCount; ++col)
                {
                    QStandardItem *placeholder = new QStandardItem();
                    placeholder->setData(memberKey, Qt::UserRole);
                    memberRow << placeholder;
                }
                nameItem->appendRow(memberRow);
            }

            if (expanded.contains(guardKey))
            {
                m_tree->expand(nameItem->index());
            }
            if (selectedKey == guardKey)
            {
                m_tree->setCurrentIndex(nameItem->index());
            }
        }
        if (expanded.contains("group:" + groupName))
        {
            m_tree->expand(groupItem->index());
        }
    }
}

void GuardTreePage::applyFilter()
{
    const QString filter = m_filterEdit->text().trimmed();
    for (int r = 0; r < m_model->rowCount(); ++r)
    {
        QStandardItem *groupItem = m_model->item(r, 0);
        bool groupVisible = filter.isEmpty();
        for (int gr = 0; gr < groupItem->rowCount(); ++gr)
        {
            QStandardItem *guardItem = groupItem->child(gr, 0);
            if (!guardItem) continue;
            const bool visible = filter.isEmpty() ||
                                 guardItem->text().contains(filter, Qt::CaseInsensitive) ||
                                 guardItem->toolTip().contains(filter, Qt::CaseInsensitive);
            m_tree->setRowHidden(gr, groupItem->index(), !visible);
            if (visible) groupVisible = true;
        }
        m_tree->setRowHidden(r, QModelIndex(), !groupVisible);
    }
}

QString GuardTreePage::formatDuration(qint64 ms)
{
    if (ms <= 0) return QStringLiteral("0:00");
    const qint64 totalSeconds = ms / 1000;
    const qint64 days = totalSeconds / 86400;
    const qint64 hours = (totalSeconds % 86400) / 3600;
    const qint64 minutes = (totalSeconds % 3600) / 60;
    const qint64 seconds = totalSeconds % 60;
    if (days > 0)
    {
        return QStringLiteral("%1d %2:%3:%4")
            .arg(days)
            .arg(hours, 2, 10, QLatin1Char('0'))
            .arg(minutes, 2, 10, QLatin1Char('0'))
            .arg(seconds, 2, 10, QLatin1Char('0'));
    }
    return QStringLiteral("%1:%2:%3")
        .arg(hours, 2, 10, QLatin1Char('0'))
        .arg(minutes, 2, 10, QLatin1Char('0'))
        .arg(seconds, 2, 10, QLatin1Char('0'));
}

QString GuardTreePage::statusText(const QString &status, bool chinese)
{
    if (status == QLatin1String("active")) return chinese ? QStringLiteral("运行中") : QStringLiteral("running");
    if (status == QLatin1String("paused")) return chinese ? QStringLiteral("已暂停") : QStringLiteral("paused");
    if (status == QLatin1String("quarantined")) return chinese ? QStringLiteral("已隔离") : QStringLiteral("quarantined");
    if (status == QLatin1String("missing")) return chinese ? QStringLiteral("已退出") : QStringLiteral("missing");
    return status;
}

QString GuardTreePage::currentGuardKey() const
{
    QStandardItem *item = m_model->itemFromIndex(m_tree->currentIndex().siblingAtColumn(0));
    while (item)
    {
        const QString key = item->data(Qt::UserRole).toString();
        if (key.startsWith(QLatin1String("guard:"))) return key;
        item = item->parent();
    }
    return QString();
}

void GuardTreePage::sendAction(const QString &command)
{
    ClientOptions options;
    options.host = m_host.toStdString();
    options.port = m_port;
    options.token = m_token.toStdString();
    const ProcessGuard::client::ClientResponse reply = sendCommand(options, command.toStdString(), 2000);
    if (!reply.ok || reply.payload.rfind("OK", 0) != 0)
    {
        QMessageBox::warning(this, trUi("操作失败", "Action failed"),
                             QString::fromStdString(reply.ok ? reply.payload : reply.error));
    }
    refreshNow();
}

void GuardTreePage::addProtection()
{
    const QString file = QFileDialog::getOpenFileName(this, trUi("选择要守护的程序", "Choose the program to guard"),
                                                      QString(), QStringLiteral("Executable (*.exe)"));
    if (file.isEmpty()) return;

    bool ok = false;
    const QString args = QInputDialog::getText(this, trUi("启动参数", "Start arguments"),
                                               trUi("启动参数（可留空）", "Start arguments (optional)"),
                                               QLineEdit::Normal, QString(), &ok);
    if (!ok) return;

    // bless-start performs the suspended-launch + register handshake locally,
    // so it is the one action that still needs the CLI (a single one-shot
    // QProcess, not the refresh path).
    const QString tool = m_toolPath.isEmpty() ? QStringLiteral("pgs_bless.exe") : m_toolPath;
    QStringList cliArgs;
    cliArgs << QStringLiteral("--host") << m_host
            << QStringLiteral("--port") << QString::number(m_port)
            << QStringLiteral("--token") << m_token
            << QStringLiteral("bless-start")
            << QStringLiteral("--path") << file;
    if (!args.trimmed().isEmpty())
    {
        cliArgs << QStringLiteral("--start-args") << args.trimmed();
    }
    QProcess *process = new QProcess(this);
    connect(process, &QProcess::finished, this, [this, process](int code, QProcess::ExitStatus) {
        const QString output = QString::fromUtf8(process->readAllStandardOutput() + process->readAllStandardError());
        if (code != 0 || !output.contains(QLatin1String("OK")))
        {
            QMessageBox::warning(this, trUi("添加保护失败", "Add protection failed"), output.trimmed());
        }
        process->deleteLater();
        refreshNow();
    });
    process->start(tool, cliArgs);
}

void GuardTreePage::closeProtection()
{
    const QString key = currentGuardKey();
    if (!key.startsWith(QLatin1String("guard:"))) return;
    const quint64 guardId = key.mid(QString::fromLatin1("guard:").size()).toULongLong();
    for (const GuardRow &row : m_guards)
    {
        if (row.guardId != guardId) continue;
        if (QMessageBox::question(this, trUi("关闭保护", "Close protection"),
                                  trUi("确定停止守护 %1？", "Stop guarding %1?").arg(baseName(row.path))) != QMessageBox::Yes)
        {
            return;
        }
        sendAction(QStringLiteral("unbless %1").arg(row.pid));
        return;
    }
}

void GuardTreePage::intentionalExit()
{
    const QString key = currentGuardKey();
    if (!key.startsWith(QLatin1String("guard:"))) return;
    const quint64 guardId = key.mid(QString::fromLatin1("guard:").size()).toULongLong();
    for (const GuardRow &row : m_guards)
    {
        if (row.guardId != guardId) continue;
        if (QMessageBox::question(this, trUi("立即退出", "Intentional exit"),
                                  trUi("让 %1 立即退出并解除守护？", "Make %1 exit now and unregister?").arg(baseName(row.path))) != QMessageBox::Yes)
        {
            return;
        }
        sendAction(QStringLiteral("intentional %1").arg(row.pid));
        return;
    }
}

void GuardTreePage::retryQuarantine()
{
    const QString key = currentGuardKey();
    if (!key.startsWith(QLatin1String("guard:"))) return;
    sendAction(QStringLiteral("guard retry --id %1").arg(key.mid(QString::fromLatin1("guard:").size())));
}

void GuardTreePage::clearQuarantine()
{
    const QString key = currentGuardKey();
    if (!key.startsWith(QLatin1String("guard:"))) return;
    sendAction(QStringLiteral("guard clear-quarantine --id %1").arg(key.mid(QString::fromLatin1("guard:").size())));
}

void GuardTreePage::assignGroup(const QString &group)
{
    const QString key = currentGuardKey();
    if (!key.startsWith(QLatin1String("guard:"))) return;
    const quint64 guardId = key.mid(QString::fromLatin1("guard:").size()).toULongLong();
    for (const GuardRow &row : m_guards)
    {
        if (row.guardId == guardId)
        {
            sendAction(QStringLiteral("group add --name \"%1\" --pid %2").arg(group).arg(row.pid));
            return;
        }
    }
}

void GuardTreePage::removeFromGroup()
{
    const QString key = currentGuardKey();
    if (!key.startsWith(QLatin1String("guard:"))) return;
    const quint64 guardId = key.mid(QString::fromLatin1("guard:").size()).toULongLong();
    for (const GuardRow &row : m_guards)
    {
        if (row.guardId == guardId)
        {
            if (!row.group.isEmpty())
            {
                sendAction(QStringLiteral("group remove --name \"%1\" --pid %2").arg(row.group).arg(row.pid));
            }
            return;
        }
    }
}

void GuardTreePage::groupPauseResume(const QString &group, bool pause)
{
    sendAction(QStringLiteral("group %1 --name \"%2\"").arg(pause ? QStringLiteral("pause") : QStringLiteral("resume"), group));
}

void GuardTreePage::groupRestart(const QString &group)
{
    sendAction(QStringLiteral("group restart --name \"%1\"").arg(group));
}

void GuardTreePage::showDetails()
{
    const QString key = currentGuardKey();
    if (!key.startsWith(QLatin1String("guard:"))) return;
    const quint64 guardId = key.mid(QString::fromLatin1("guard:").size()).toULongLong();
    for (const GuardRow &row : m_guards)
    {
        if (row.guardId != guardId) continue;
        QStringList lines;
        for (const QString &pair : row.rawLine.split(QLatin1Char(';')))
        {
            const int eq = pair.indexOf(QLatin1Char('='));
            if (eq <= 0) continue;
            QString keyText = pair.left(eq);
            QString valueText = pair.mid(eq + 1);
            if (keyText.endsWith(QLatin1String("_B64")))
            {
                keyText.chop(4);
                valueText = decodeB64(valueText);
            }
            lines << QStringLiteral("%1: %2").arg(keyText, valueText);
        }
        QMessageBox::information(this, trUi("守护属性", "Guard properties"), lines.join(QLatin1Char('\n')));
        return;
    }
}
