/**
 * @file GuardTreePage.cpp
 * @brief Task-manager style main page (see GuardTreePage.h).
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "GuardTreePage.h"

#include "Process_Guard/PGSClient.h"

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#include <QBrush>
#include <QDateTime>
#include <QColor>
#include <QComboBox>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
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
#include <functional>

using ProcessGuard::client::ClientOptions;
using ProcessGuard::client::sendCommand;

namespace
{
    constexpr int kColumnCount = 9;
    constexpr int kColName = 0;
    constexpr int kColPid = 1;
    constexpr int kColStatus = 2;
    constexpr int kColCpu = 3;
    constexpr int kColMemory = 4;
    constexpr int kColRuntime = 5;
    constexpr int kColRestarts = 6;
    constexpr int kColGroup = 7;
    constexpr int kColFailure = 8;

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

    QColor statusColor(const QString &status)
    {
        if (status == QLatin1String("active")) return QColor(0x39, 0xd3, 0x53);
        if (status == QLatin1String("paused")) return QColor(0xd2, 0x99, 0x22);
        if (status == QLatin1String("quarantined")) return QColor(0xf8, 0x51, 0x49);
        if (status == QLatin1String("protected")) return QColor(0x39, 0xd3, 0x53);
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

    m_btnOnlyProtected = new QPushButton(this);
    m_btnOnlyProtected->setCheckable(true);
    connect(m_btnOnlyProtected, &QPushButton::toggled, this, [this](bool checked) {
        m_onlyProtected = checked;
        retranslateUi();
        rebuildTree();
        applyFilter();
    });
    toolbar->addWidget(m_btnOnlyProtected);

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
        const QString key = currentProcKey();
        if (key.isEmpty()) return;
        const quint32 pid = key.mid(QString::fromLatin1("proc:").size()).toUInt();
        const GuardRow *guard = nullptr;
        for (const GuardRow &row : m_guards)
        {
            if (row.alive && row.pid == pid)
            {
                guard = &row;
                break;
            }
        }
        const ProcRow *proc = nullptr;
        for (const ProcRow &candidate : m_procs)
        {
            if (candidate.pid == pid)
            {
                proc = &candidate;
                break;
            }
        }
        if (!proc) return;

        QMenu menu(this);
        if (!guard)
        {
            menu.addAction(trUi("保护此进程", "Protect this process"), this, &GuardTreePage::protectProcess);
        }
        else
        {
            menu.addAction(trUi("关闭保护", "Close protection"), this, &GuardTreePage::closeProtection);
            menu.addAction(trUi("立即退出并解除", "Intentional exit and unregister"), this, &GuardTreePage::intentionalExit);
            if (guard->status == QLatin1String("quarantined"))
            {
                menu.addAction(trUi("重试隔离的守护", "Retry quarantined guard"), this, &GuardTreePage::retryQuarantine);
                menu.addAction(trUi("清除隔离记录", "Clear quarantine"), this, &GuardTreePage::clearQuarantine);
            }
            menu.addSeparator();
            QMenu *groupMenu = menu.addMenu(trUi("分组", "Group"));
            QSet<QString> groups;
            for (const GuardRow &candidate : m_guards)
            {
                if (!candidate.group.isEmpty() && candidate.group != guard->group) groups.insert(candidate.group);
            }
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
            if (!guard->group.isEmpty())
            {
                groupMenu->addAction(trUi("从 %1 移除", "Remove from %1").arg(guard->group), this, &GuardTreePage::removeFromGroup);
                groupMenu->addSeparator();
                groupMenu->addAction(trUi("暂停 %1", "Pause %1").arg(guard->group), this, [this, guard]() { groupPauseResume(guard->group, true); });
                groupMenu->addAction(trUi("恢复 %1", "Resume %1").arg(guard->group), this, [this, guard]() { groupPauseResume(guard->group, false); });
                groupMenu->addAction(trUi("重启 %1", "Restart %1").arg(guard->group), this, [this, guard]() { groupRestart(guard->group); });
            }
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
    m_btnAdd->setText(trUi("启动并保护新程序", "Launch && protect"));
    m_btnOnlyProtected->setText(m_onlyProtected ? trUi("显示全部进程", "Show all processes")
                                                : trUi("只看受保护", "Protected only"));
    m_btnPauseRefresh->setText(m_paused ? trUi("恢复刷新", "Resume refresh")
                                        : trUi("暂停刷新", "Pause refresh"));
    m_filterEdit->setPlaceholderText(trUi("按名称过滤", "Filter by name"));
    m_model->setHorizontalHeaderLabels(QStringList{
        trUi("名称", "Name"),
        trUi("PID", "PID"),
        trUi("状态", "Status"),
        trUi("CPU", "CPU"),
        trUi("内存", "Memory"),
        trUi("保护时长", "Protected time"),
        trUi("触发保护", "Triggers"),
        trUi("分组", "Group"),
        trUi("上次失败", "Last failure")});
    m_tree->header()->resizeSection(kColName, 240);
    m_tree->header()->resizeSection(kColPid, 70);
    m_tree->header()->resizeSection(kColStatus, 110);
    m_tree->header()->resizeSection(kColCpu, 60);
    m_tree->header()->resizeSection(kColMemory, 80);
    m_tree->header()->resizeSection(kColRuntime, 110);
    m_tree->header()->resizeSection(kColRestarts, 70);
    m_tree->header()->resizeSection(kColGroup, 90);
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

void GuardTreePage::snapshotProcesses()
{
    // Client-side process enumeration — the same API surface the Windows Task
    // Manager uses. One snapshot per refresh; CPU% comes from the per-process
    // kernel+user time delta between samples.
    QVector<ProcRow> procs;
    QHash<quint32, QPair<quint64, quint64>> cpuTimes;
    const qint64 wallNow = QDateTime::currentMSecsSinceEpoch();
    const double wallDeltaSec = (m_prevWallMs > 0)
        ? std::max(0.25, static_cast<double>(wallNow - m_prevWallMs) / 1000.0)
        : 0.0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snapshot, &pe))
        {
            do
            {
                ProcRow row;
                row.pid = pe.th32ProcessID;
                row.parentPid = pe.th32ParentProcessID;
                row.name = QString::fromWCharArray(pe.szExeFile);
                procs.push_back(row);
                cpuTimes.insert(row.pid, qMakePair(0ull, 0ull));
            } while (Process32NextW(snapshot, &pe));
        }
        CloseHandle(snapshot);
    }

    double systemCores = 1.0;
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    systemCores = si.dwNumberOfProcessors > 0 ? si.dwNumberOfProcessors : 1.0;

    for (ProcRow &row : procs)
    {
        HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, row.pid);
        if (!handle)
        {
            continue;
        }
        FILETIME createTime{}, exitTime{}, kernelTime{}, userTime{};
        if (GetProcessTimes(handle, &createTime, &exitTime, &kernelTime, &userTime))
        {
            const quint64 kernel100 = (static_cast<quint64>(kernelTime.dwHighDateTime) << 32) | kernelTime.dwLowDateTime;
            const quint64 user100 = (static_cast<quint64>(userTime.dwHighDateTime) << 32) | userTime.dwLowDateTime;
            cpuTimes.insert(row.pid, qMakePair(kernel100, user100));
            if (m_prevWallMs > 0 && m_prevCpuTimes.contains(row.pid))
            {
                const QPair<quint64, quint64> prev = m_prevCpuTimes.value(row.pid);
                const double procDeltaSec =
                    (static_cast<double>(kernel100 - prev.first) + static_cast<double>(user100 - prev.second)) / 10.0 / 1000000.0;
                row.cpuPercent = std::min(100.0 * systemCores,
                                          std::max(0.0, 100.0 * procDeltaSec / wallDeltaSec / systemCores));
            }
        }
        PROCESS_MEMORY_COUNTERS_EX pmc{};
        pmc.cb = sizeof(pmc);
        if (GetProcessMemoryInfo(handle, reinterpret_cast<PROCESS_MEMORY_COUNTERS *>(&pmc), sizeof(pmc)))
        {
            row.memoryBytes = pmc.WorkingSetSize;
        }
        WCHAR imagePathW[MAX_PATH] = {0};
        DWORD imagePathLen = MAX_PATH;
        if (QueryFullProcessImageNameW(handle, 0, imagePathW, &imagePathLen) && imagePathLen > 0)
        {
            row.imagePath = QString::fromWCharArray(imagePathW, static_cast<int>(imagePathLen));
        }
        CloseHandle(handle);
    }

    m_prevCpuTimes = cpuTimes;
    m_prevWallMs = wallNow;

    // Overlay the guard state (a guard pid may have exited: only alive guards
    // highlight a live process; quarantined records render separately).
    m_guardsByPid.clear();
    for (const GuardRow &row : m_guards)
    {
        if (row.alive) m_guardsByPid.insert(row.pid, row);
    }
    for (ProcRow &row : procs)
    {
        row.guard = m_guardsByPid.contains(row.pid) ? &m_guardsByPid[row.pid] : nullptr;
    }
    std::sort(procs.begin(), procs.end(), [](const ProcRow &a, const ProcRow &b) {
        if ((a.guard != nullptr) != (b.guard != nullptr)) return a.guard != nullptr;
        return a.name.compare(b.name, Qt::CaseInsensitive) < 0;
    });
    m_procs = procs;
}

void GuardTreePage::refreshNow()
{
    if (m_paused) return;

    // Guard list comes from the service; the process list is local. A service
    // hiccup must not blank the process tree.
    ClientOptions options;
    options.host = m_host.toStdString();
    options.port = m_port;
    options.token = m_token.toStdString();

    QVector<GuardRow> guards;
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
            row.alive = kvValue(line, "ALIVE") == QLatin1String("1");
            guards.push_back(row);
        }

        const ProcessGuard::client::ClientResponse statsReply = sendCommand(options, "stats", 800);
        if (statsReply.ok)
        {
            statsText = QString::fromStdString(statsReply.payload);
        }
    }

    m_guards = guards;
    m_lastError = error;
    if (!statsText.isEmpty())
    {
        m_statsLabel->setText(QString::fromStdString(statsText.toStdString()));
    }
    else if (!error.isEmpty())
    {
        m_statsLabel->setText(trUi("无法连接服务（进程列表仍可用）：%1", "Service unreachable (process list still works): %1").arg(error));
    }
    else
    {
        m_statsLabel->setText(QString());
    }

    snapshotProcesses();
    rebuildTree();
    applyFilter();
}

void GuardTreePage::rebuildTree()
{
    // Preserve expansion + selection across rebuilds via node keys stored in
    // Qt::UserRole ("proc:<pid>").
    QSet<QString> expanded;
    for (int r = 0; r < m_model->rowCount(); ++r)
    {
        QStandardItem *rootItem = m_model->item(r, 0);
        if (m_tree->isExpanded(rootItem->index()))
        {
            expanded.insert(rootItem->data(Qt::UserRole).toString());
        }
        for (int cr = 0; cr < rootItem->rowCount(); ++cr)
        {
            QStandardItem *child = rootItem->child(cr, 0);
            if (child && m_tree->isExpanded(child->index()))
            {
                expanded.insert(child->data(Qt::UserRole).toString());
            }
        }
    }
    QStandardItem *selectedItem = m_model->itemFromIndex(m_tree->currentIndex().siblingAtColumn(0));
    const QString selectedKey = selectedItem ? selectedItem->data(Qt::UserRole).toString() : QString();

    m_model->removeRows(0, m_model->rowCount());

    // Quarantined guard records have no live pid: render them in their own
    // section on top so they never disappear from view.
    for (const GuardRow &row : m_guards)
    {
        if (row.status != QLatin1String("quarantined")) continue;
        const QString key = QStringLiteral("quarantined:%1").arg(row.guardId);
        QStandardItem *nameItem = new QStandardItem(
            trUi("[已隔离] %1", "[quarantined] %1").arg(baseName(row.path)));
        nameItem->setData(key, Qt::UserRole);
        nameItem->setToolTip(row.path);
        nameItem->setForeground(QBrush(QColor(0xf8, 0x51, 0x49)));
        QList<QStandardItem *> quarantinedRow;
        quarantinedRow << nameItem
                       << new QStandardItem(QStringLiteral("-"))
                       << new QStandardItem(statusText(row.status, m_chinese))
                       << new QStandardItem(QStringLiteral("-"))
                       << new QStandardItem(QStringLiteral("-"))
                       << new QStandardItem(formatDuration(row.cumulativeRunMs))
                       << new QStandardItem(QString::number(row.restartCount))
                       << new QStandardItem(row.group)
                       << new QStandardItem(row.lastFailureCode);
        m_model->appendRow(quarantinedRow);
    }

    // Parent-child process tree: a process whose parent is also in the
    // snapshot becomes its child; orphans (parent exited) render at the root,
    // mirroring the Windows Task Manager behaviour.
    QHash<quint32, ProcRow *> byPid;
    for (ProcRow &row : m_procs) byPid.insert(row.pid, &row);
    QHash<quint32, QList<ProcRow *>> children;
    QList<ProcRow *> roots;
    for (ProcRow &row : m_procs)
    {
        ProcRow *parent = (row.parentPid != 0 && row.parentPid != row.pid) ? byPid.value(row.parentPid, nullptr) : nullptr;
        if (parent && parent->pid != row.pid)
        {
            children[parent->pid].push_back(&row);
        }
        else
        {
            roots.push_back(&row);
        }
    }
    std::sort(roots.begin(), roots.end(), [](const ProcRow *a, const ProcRow *b) {
        if ((a->guard != nullptr) != (b->guard != nullptr)) return a->guard != nullptr;
        return a->name.compare(b->name, Qt::CaseInsensitive) < 0;
    });
    for (auto it = children.begin(); it != children.end(); ++it)
    {
        std::sort(it->begin(), it->end(), [](const ProcRow *a, const ProcRow *b) {
            if ((a->guard != nullptr) != (b->guard != nullptr)) return a->guard != nullptr;
            return a->name.compare(b->name, Qt::CaseInsensitive) < 0;
        });
    }

    std::function<void(const ProcRow &, QStandardItem *)> appendProc = [&](const ProcRow &row, QStandardItem *parentItem) {
        const QString key = keyForPid(row.pid, row.guard != nullptr);
        const bool isGuard = row.guard != nullptr;

        QStandardItem *nameItem = new QStandardItem(row.name);
        nameItem->setData(key, Qt::UserRole);
        if (!row.imagePath.isEmpty()) nameItem->setToolTip(row.imagePath);
        if (isGuard)
        {
            nameItem->setForeground(QBrush(QColor(0x39, 0xd3, 0x53)));
        }

        QStandardItem *pidItem = new QStandardItem(QString::number(row.pid));
        pidItem->setData(key, Qt::UserRole);

        QStandardItem *statusItem = new QStandardItem(isGuard
            ? statusText(row.guard->status == QLatin1String("active") ? QStringLiteral("protected") : row.guard->status, m_chinese)
            : statusText(QStringLiteral("plain"), m_chinese));
        statusItem->setData(key, Qt::UserRole);
        statusItem->setForeground(QBrush(statusColor(isGuard ? row.guard->status : QStringLiteral("plain"))));

        QStandardItem *cpuItem = new QStandardItem(
            row.cpuPercent >= 0.05 ? QStringLiteral("%1%").arg(row.cpuPercent, 0, 'f', 1) : QString());
        cpuItem->setData(key, Qt::UserRole);

        QStandardItem *memItem = new QStandardItem(
            row.memoryBytes > 0 ? formatBytes(row.memoryBytes) : QStringLiteral("-"));
        memItem->setData(key, Qt::UserRole);

        QStandardItem *runtimeItem = new QStandardItem(isGuard ? formatDuration(row.guard->cumulativeRunMs) : QStringLiteral("-"));
        runtimeItem->setData(key, Qt::UserRole);

        QStandardItem *restartItem = new QStandardItem(isGuard ? QString::number(row.guard->restartCount) : QStringLiteral("-"));
        restartItem->setData(key, Qt::UserRole);

        QStandardItem *groupItem = new QStandardItem(isGuard ? row.guard->group : QString());
        groupItem->setData(key, Qt::UserRole);

        QStandardItem *failureItem = new QStandardItem(isGuard ? row.guard->lastFailureCode : QString());
        failureItem->setData(key, Qt::UserRole);
        if (isGuard && !row.guard->lastFailure.isEmpty()) failureItem->setToolTip(row.guard->lastFailure);

        QList<QStandardItem *> procRow;
        procRow << nameItem << pidItem << statusItem << cpuItem << memItem
                << runtimeItem << restartItem << groupItem << failureItem;

        if (parentItem) parentItem->appendRow(procRow);
        else m_model->appendRow(procRow);

        for (ProcRow *child : children.value(row.pid))
        {
            appendProc(*child, nameItem);
        }
        if (!children.value(row.pid).isEmpty() && expanded.contains(key))
        {
            m_tree->expand(nameItem->index());
        }
        if (selectedKey == key)
        {
            m_tree->setCurrentIndex(nameItem->index());
        }
    };
    for (const ProcRow *root : roots)
    {
        appendProc(*root, nullptr);
    }
}

void GuardTreePage::applyFilter()
{
    const QString filter = m_filterEdit->text().trimmed();
    for (int r = 0; r < m_model->rowCount(); ++r)
    {
        QStandardItem *rootItem = m_model->item(r, 0);
        if (!rootItem) continue;
        const bool visible = filter.isEmpty() ||
                             rootItem->text().contains(filter, Qt::CaseInsensitive) ||
                             rootItem->toolTip().contains(filter, Qt::CaseInsensitive);
        m_tree->setRowHidden(r, QModelIndex(), !visible);
    }
}

QString GuardTreePage::keyForPid(quint32 pid, bool guarded) const
{
    // Guarded and unprotected rows live in different key spaces so a pid that
    // gains/loses protection keeps its expansion state consistent per role.
    return guarded ? QStringLiteral("gproc:%1").arg(pid) : QStringLiteral("proc:%1").arg(pid);
}

QString GuardTreePage::currentProcKey() const
{
    QStandardItem *item = m_model->itemFromIndex(m_tree->currentIndex().siblingAtColumn(0));
    return item ? item->data(Qt::UserRole).toString() : QString();
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

QString GuardTreePage::formatBytes(quint64 bytes)
{
    const double mb = static_cast<double>(bytes) / (1024.0 * 1024.0);
    if (mb >= 1024.0)
    {
        return QStringLiteral("%1 GB").arg(mb / 1024.0, 0, 'f', 1);
    }
    return QStringLiteral("%1 MB").arg(mb, 0, 'f', 1);
}

QString GuardTreePage::statusText(const QString &status, bool chinese)
{
    if (status == QLatin1String("protected")) return chinese ? QStringLiteral("受保护") : QStringLiteral("protected");
    if (status == QLatin1String("active")) return chinese ? QStringLiteral("运行中") : QStringLiteral("running");
    if (status == QLatin1String("paused")) return chinese ? QStringLiteral("已暂停") : QStringLiteral("paused");
    if (status == QLatin1String("quarantined")) return chinese ? QStringLiteral("已隔离") : QStringLiteral("quarantined");
    if (status == QLatin1String("missing")) return chinese ? QStringLiteral("已退出") : QStringLiteral("missing");
    if (status == QLatin1String("plain")) return chinese ? QStringLiteral("运行中") : QStringLiteral("running");
    return status;
}

QString GuardTreePage::baseName(const QString &path)
{
    QString cleaned = path;
    cleaned.replace(QLatin1Char('/'), QLatin1Char('\\'));
    const int slash = cleaned.lastIndexOf(QLatin1Char('\\'));
    return slash >= 0 ? cleaned.mid(slash + 1) : cleaned;
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

void GuardTreePage::protectProcess()
{
    const QString key = currentProcKey();
    if (!key.startsWith(QLatin1String("proc:"))) return;
    const quint32 pid = key.mid(QString::fromLatin1("proc:").size()).toUInt();
    const ProcRow *proc = nullptr;
    for (const ProcRow &row : m_procs)
    {
        if (row.pid == pid)
        {
            proc = &row;
            break;
        }
    }
    if (!proc) return;

    bool ok = false;
    const QString maxText = QInputDialog::getText(this,
        trUi("保护此进程", "Protect this process"),
        trUi("重启上限（数字或 no = 无限）", "Restart limit (number or no = unlimited)"),
        QLineEdit::Normal, QStringLiteral("3"), &ok);
    if (!ok) return;
    const QString max = maxText.trimmed().isEmpty() ? QStringLiteral("3") : maxText.trimmed();

    QString path = proc->imagePath;
    if (path.isEmpty())
    {
        QMessageBox::warning(this, trUi("保护此进程", "Protect this process"),
                             trUi("无法读取进程镜像路径（权限不足或进程已退出）。", "Cannot read the process image path (access denied or the process exited)."));
        return;
    }
    sendAction(QStringLiteral("bless %1 %2 %3")
                   .arg(pid)
                   .arg(QString::fromUtf8(path.toUtf8().toBase64()))
                   .arg(max));
}

void GuardTreePage::closeProtection()
{
    const QString key = currentProcKey();
    if (key.isEmpty()) return;
    const quint32 pid = key.mid(key.lastIndexOf(QLatin1Char(':')) + 1).toUInt();
    for (const GuardRow &row : m_guards)
    {
        if (row.alive && row.pid == pid)
        {
            if (QMessageBox::question(this, trUi("关闭保护", "Close protection"),
                                      trUi("确定停止守护 %1？", "Stop guarding %1?").arg(baseName(row.path))) != QMessageBox::Yes)
            {
                return;
            }
            sendAction(QStringLiteral("unbless %1").arg(pid));
            return;
        }
    }
}

void GuardTreePage::intentionalExit()
{
    const QString key = currentProcKey();
    if (key.isEmpty()) return;
    const quint32 pid = key.mid(key.lastIndexOf(QLatin1Char(':')) + 1).toUInt();
    for (const GuardRow &row : m_guards)
    {
        if (row.alive && row.pid == pid)
        {
            if (QMessageBox::question(this, trUi("立即退出", "Intentional exit"),
                                      trUi("让 %1 立即退出并解除守护？", "Make %1 exit now and unregister?").arg(baseName(row.path))) != QMessageBox::Yes)
            {
                return;
            }
            sendAction(QStringLiteral("intentional %1").arg(pid));
            return;
        }
    }
}

void GuardTreePage::retryQuarantine()
{
    const QString key = currentProcKey();
    if (!key.startsWith(QLatin1String("quarantined:"))) return;
    sendAction(QStringLiteral("guard retry --id %1").arg(key.mid(QString::fromLatin1("quarantined:").size())));
}

void GuardTreePage::clearQuarantine()
{
    const QString key = currentProcKey();
    if (!key.startsWith(QLatin1String("quarantined:"))) return;
    sendAction(QStringLiteral("guard clear-quarantine --id %1").arg(key.mid(QString::fromLatin1("quarantined:").size())));
}

void GuardTreePage::assignGroup(const QString &group)
{
    const QString key = currentProcKey();
    if (key.isEmpty()) return;
    const quint32 pid = key.mid(key.lastIndexOf(QLatin1Char(':')) + 1).toUInt();
    sendAction(QStringLiteral("group add --name \"%1\" --pid %2").arg(group).arg(pid));
}

void GuardTreePage::removeFromGroup()
{
    const QString key = currentProcKey();
    if (key.isEmpty()) return;
    const quint32 pid = key.mid(key.lastIndexOf(QLatin1Char(':')) + 1).toUInt();
    for (const GuardRow &row : m_guards)
    {
        if (row.alive && row.pid == pid)
        {
            if (!row.group.isEmpty())
            {
                sendAction(QStringLiteral("group remove --name \"%1\" --pid %2").arg(row.group).arg(pid));
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
    const QString key = currentProcKey();
    if (key.isEmpty()) return;
    const quint32 pid = key.mid(key.lastIndexOf(QLatin1Char(':')) + 1).toUInt();

    QStringList lines;
    // Quarantined record details.
    if (key.startsWith(QLatin1String("quarantined:")))
    {
        const quint64 guardId = key.mid(QString::fromLatin1("quarantined:").size()).toULongLong();
        for (const GuardRow &row : m_guards)
        {
            if (row.guardId == guardId)
            {
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
                break;
            }
        }
        QMessageBox::information(this, trUi("守护属性", "Guard properties"), lines.join(QLatin1Char('\n')));
        return;
    }

    for (const ProcRow &row : m_procs)
    {
        if (row.pid != pid) continue;
        lines << QStringLiteral("PID: %1").arg(row.pid);
        lines << QStringLiteral("PPID: %1").arg(row.parentPid);
        if (!row.imagePath.isEmpty()) lines << QStringLiteral("IMAGE: %1").arg(row.imagePath);
        if (row.memoryBytes > 0) lines << QStringLiteral("WORKING SET: %1").arg(formatBytes(row.memoryBytes));
        if (row.guard)
        {
            for (const QString &pair : row.guard->rawLine.split(QLatin1Char(';')))
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
        }
        break;
    }
    QMessageBox::information(this, trUi("进程属性", "Process properties"), lines.join(QLatin1Char('\n')));
}
