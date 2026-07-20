/**
 * @file ModulePage.cpp
 * @brief Implementation of ModulePage.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "ModulePage.h"

#include <QComboBox>
#include <QCheckBox>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QIODevice>
#include <QLabel>
#include <QLineEdit>
#include <QProcess>
#include <QProcessEnvironment>
#include <QPushButton>
#include <QTextBrowser>
#include <QTextEdit>
#include <QVBoxLayout>

ModulePage::ModulePage(const QString &folder, const QString &moduleDir,
                       const QString &toolPath, const QString &token,
                       bool chinese, QWidget *parent)
    : QWidget(parent),
      m_folder(folder),
      m_moduleDir(moduleDir),
      m_toolPath(toolPath),
      m_token(token),
      m_chinese(chinese)
{
    setupUi();
    retranslateUi();
    reloadHtml();
}

QString ModulePage::trUi(const QString &en, const QString &zh) const
{
    return m_chinese ? zh : en;
}

void ModulePage::setupUi()
{
    auto *layout = new QVBoxLayout(this);

    m_html = new QTextBrowser(this);
    m_html->setOpenExternalLinks(true);
    layout->addWidget(m_html, 1);

    const bool isPpl = (m_folder.compare(QStringLiteral("ppl"), Qt::CaseInsensitive) == 0);
    const bool isMetrics = (m_folder.compare(QStringLiteral("metrics"), Qt::CaseInsensitive) == 0);
    const bool isBackup = (m_folder.compare(QStringLiteral("backup"), Qt::CaseInsensitive) == 0);
    const bool isEventlog = (m_folder.compare(QStringLiteral("eventlog"), Qt::CaseInsensitive) == 0);

    if (isPpl)
    {
        m_riskLabel = new QLabel(this);
        m_riskLabel->setWordWrap(true);
        layout->addWidget(m_riskLabel);
        m_pplBox = new QGroupBox(this);
        auto *row = new QHBoxLayout(m_pplBox);
        m_lblPid = new QLabel(m_pplBox);
        row->addWidget(m_lblPid);
        m_pidEdit = new QLineEdit(m_pplBox);
        m_pidEdit->setPlaceholderText(QStringLiteral("1234"));
        row->addWidget(m_pidEdit);
        m_lblSigner = new QLabel(m_pplBox);
        row->addWidget(m_lblSigner);
        m_signerCombo = new QComboBox(m_pplBox);
        m_signerCombo->addItems(QStringList{
            "None", "Authenticode", "CodeGen", "Antimalware",
            "Lsa", "Windows", "WinTcb", "WinSystem", "App"});
        m_signerCombo->setCurrentText("Antimalware");
        row->addWidget(m_signerCombo);
        m_btnPplSet = new QPushButton(m_pplBox);
        m_btnPplGet = new QPushButton(m_pplBox);
        m_btnPplClear = new QPushButton(m_pplBox);
        row->addWidget(m_btnPplSet);
        row->addWidget(m_btnPplGet);
        row->addWidget(m_btnPplClear);
        row->addStretch();
        layout->addWidget(m_pplBox);
    }

    if (isMetrics)
    {
        m_metricsBox = new QGroupBox(this);
        auto *row = new QHBoxLayout(m_metricsBox);
        m_btnMetricsSummary = new QPushButton(m_metricsBox);
        m_btnMetricsJson = new QPushButton(m_metricsBox);
        m_btnMetricsProm = new QPushButton(m_metricsBox);
        row->addWidget(m_btnMetricsSummary);
        row->addWidget(m_btnMetricsJson);
        row->addWidget(m_btnMetricsProm);
        row->addStretch();
        layout->addWidget(m_metricsBox);
    }

    if (isBackup)
    {
        m_backupBox = new QGroupBox(this);
        auto *row = new QHBoxLayout(m_backupBox);
        m_backupMaxBytesEdit = new QLineEdit(m_backupBox);
        m_backupMaxBytesEdit->setPlaceholderText(QStringLiteral("1048576"));
        m_backupArtifactCheck = new QCheckBox(m_backupBox);
        m_btnBackupStatus = new QPushButton(m_backupBox);
        m_btnBackupSnapshot = new QPushButton(m_backupBox);
        row->addWidget(m_backupMaxBytesEdit);
        row->addWidget(m_backupArtifactCheck);
        row->addWidget(m_btnBackupStatus);
        row->addWidget(m_btnBackupSnapshot);
        row->addStretch();
        layout->addWidget(m_backupBox);
    }

    if (isEventlog)
    {
        m_eventlogBox = new QGroupBox(this);
        auto *row = new QHBoxLayout(m_eventlogBox);
        m_eventlogLimitEdit = new QLineEdit(m_eventlogBox);
        m_eventlogLimitEdit->setPlaceholderText(QStringLiteral("20"));
        m_eventlogSourceEdit = new QLineEdit(m_eventlogBox);
        m_eventlogSourceEdit->setPlaceholderText(QStringLiteral("ProcessGuardService"));
        m_btnEventlogStatus = new QPushButton(m_eventlogBox);
        m_btnEventlogRecent = new QPushButton(m_eventlogBox);
        row->addWidget(m_eventlogLimitEdit);
        row->addWidget(m_eventlogSourceEdit, 1);
        row->addWidget(m_btnEventlogStatus);
        row->addWidget(m_btnEventlogRecent);
        row->addStretch();
        layout->addWidget(m_eventlogBox);
    }

    const QString moduleKey = m_folder.toLower();
    if (moduleKey == QStringLiteral("sched"))
    {
        m_schedBox = new QGroupBox(this);
        auto *row = new QHBoxLayout(m_schedBox);
        m_schedTypeCombo = new QComboBox(m_schedBox);
        m_schedTypeCombo->addItems(QStringList{QStringLiteral("interval"), QStringLiteral("cron"), QStringLiteral("once")});
        row->addWidget(m_schedTypeCombo);
        m_schedExprEdit = new QLineEdit(m_schedBox);
        m_schedExprEdit->setPlaceholderText(QStringLiteral("300"));
        row->addWidget(m_schedExprEdit);
        m_schedActionEdit = new QLineEdit(m_schedBox);
        m_schedActionEdit->setPlaceholderText(QStringLiteral("set-policy 1234|no"));
        row->addWidget(m_schedActionEdit, 1);
        m_schedCountEdit = new QLineEdit(m_schedBox);
        m_schedCountEdit->setPlaceholderText(QStringLiteral("count"));
        row->addWidget(m_schedCountEdit);
        m_schedIdEdit = new QLineEdit(m_schedBox);
        m_schedIdEdit->setPlaceholderText(QStringLiteral("id"));
        row->addWidget(m_schedIdEdit);
        m_btnSchedAdd = new QPushButton(m_schedBox);
        m_btnSchedList = new QPushButton(m_schedBox);
        m_btnSchedEnable = new QPushButton(m_schedBox);
        m_btnSchedDisable = new QPushButton(m_schedBox);
        m_btnSchedRemove = new QPushButton(m_schedBox);
        row->addWidget(m_btnSchedAdd);
        row->addWidget(m_btnSchedList);
        row->addWidget(m_btnSchedEnable);
        row->addWidget(m_btnSchedDisable);
        row->addWidget(m_btnSchedRemove);
        layout->addWidget(m_schedBox);
    }
    else if (moduleKey == QStringLiteral("notify"))
    {
        m_notifyBox = new QGroupBox(this);
        auto *row = new QHBoxLayout(m_notifyBox);
        m_notifyEventLogCheck = new QCheckBox(m_notifyBox);
        m_notifyEventLogCheck->setChecked(true);
        m_notifyPopupCheck = new QCheckBox(m_notifyBox);
        m_btnNotifyStatus = new QPushButton(m_notifyBox);
        m_btnNotifyApply = new QPushButton(m_notifyBox);
        row->addWidget(m_notifyEventLogCheck);
        row->addWidget(m_notifyPopupCheck);
        row->addWidget(m_btnNotifyStatus);
        row->addWidget(m_btnNotifyApply);
        row->addStretch();
        layout->addWidget(m_notifyBox);
    }
    else if (moduleKey == QStringLiteral("report"))
    {
        m_reportBox = new QGroupBox(this);
        auto *row = new QHBoxLayout(m_reportBox);
        m_reportLimitEdit = new QLineEdit(m_reportBox);
        m_reportLimitEdit->setPlaceholderText(QStringLiteral("limit"));
        m_reportArtifactCheck = new QCheckBox(m_reportBox);
        m_operationIdEdit = new QLineEdit(m_reportBox);
        m_operationIdEdit->setPlaceholderText(QStringLiteral("op_..."));
        m_artifactIdEdit = new QLineEdit(m_reportBox);
        m_artifactIdEdit->setPlaceholderText(QStringLiteral("art_..."));
        m_artifactOutEdit = new QLineEdit(m_reportBox);
        m_artifactOutEdit->setPlaceholderText(QStringLiteral("C:/temp/report.json"));
        m_artifactTtlEdit = new QLineEdit(m_reportBox);
        m_artifactTtlEdit->setPlaceholderText(QStringLiteral("86400000"));
        m_artifactAutoCleanupCheck = new QCheckBox(m_reportBox);
        m_artifactAutoCleanupCheck->setChecked(true);
        m_artifactVerifyStatusCheck = new QCheckBox(m_reportBox);
        m_btnReportSnapshot = new QPushButton(m_reportBox);
        m_btnReportBackup = new QPushButton(m_reportBox);
        m_btnOperationStatus = new QPushButton(m_reportBox);
        m_btnArtifactMeta = new QPushButton(m_reportBox);
        m_btnArtifactStatus = new QPushButton(m_reportBox);
        m_btnArtifactPolicy = new QPushButton(m_reportBox);
        m_btnArtifactDownload = new QPushButton(m_reportBox);
        row->addWidget(m_reportLimitEdit);
        row->addWidget(m_reportArtifactCheck);
        row->addWidget(m_operationIdEdit);
        row->addWidget(m_artifactIdEdit);
        row->addWidget(m_artifactOutEdit, 1);
        row->addWidget(m_artifactTtlEdit);
        row->addWidget(m_artifactAutoCleanupCheck);
        row->addWidget(m_artifactVerifyStatusCheck);
        row->addWidget(m_btnReportSnapshot);
        row->addWidget(m_btnReportBackup);
        row->addWidget(m_btnOperationStatus);
        row->addWidget(m_btnArtifactMeta);
        row->addWidget(m_btnArtifactStatus);
        row->addWidget(m_btnArtifactPolicy);
        row->addWidget(m_btnArtifactDownload);
        layout->addWidget(m_reportBox);
    }

    const bool hasShortcutModule = moduleKey == QStringLiteral("dump") ||
        moduleKey == QStringLiteral("service_guard") || moduleKey == QStringLiteral("file_watch") ||
        moduleKey == QStringLiteral("policy") || moduleKey == QStringLiteral("remote_agent") ||
        moduleKey == QStringLiteral("update") || moduleKey == QStringLiteral("script_runner");
    if (hasShortcutModule)
    {
        m_shortcutBox = new QGroupBox(this);
        auto *row = new QHBoxLayout(m_shortcutBox);
        m_shortcutPidEdit = new QLineEdit(m_shortcutBox);
        m_shortcutPidEdit->setPlaceholderText(QStringLiteral("pid"));
        m_shortcutNameEdit = new QLineEdit(m_shortcutBox);
        m_shortcutNameEdit->setPlaceholderText(QStringLiteral("name"));
        m_shortcutIdEdit = new QLineEdit(m_shortcutBox);
        m_shortcutIdEdit->setPlaceholderText(QStringLiteral("id"));
        m_shortcutPathEdit = new QLineEdit(m_shortcutBox);
        m_shortcutPathEdit->setPlaceholderText(QStringLiteral("path"));
        m_shortcutArgsEdit = new QLineEdit(m_shortcutBox);
        m_shortcutArgsEdit->setPlaceholderText(QStringLiteral("args"));
        m_shortcutMaxEdit = new QLineEdit(m_shortcutBox);
        m_shortcutMaxEdit->setPlaceholderText(QStringLiteral("max"));
        m_shortcutWindowEdit = new QLineEdit(m_shortcutBox);
        m_shortcutWindowEdit->setPlaceholderText(QStringLiteral("window"));
        m_shortcutDelayEdit = new QLineEdit(m_shortcutBox);
        m_shortcutDelayEdit->setPlaceholderText(QStringLiteral("delay"));
        m_shortcutHangEdit = new QLineEdit(m_shortcutBox);
        m_shortcutHangEdit->setPlaceholderText(QStringLiteral("hang"));
        m_shortcutTypeCombo = new QComboBox(m_shortcutBox);
        m_shortcutTypeCombo->addItems(QStringList{QStringLiteral("normal"), QStringLiteral("with-data")});
        m_shortcutStateCombo = new QComboBox(m_shortcutBox);
        m_shortcutStateCombo->addItems(QStringList{QStringLiteral("running"), QStringLiteral("stopped")});
        m_shortcutActionCombo = new QComboBox(m_shortcutBox);
        m_shortcutActionCombo->addItems(QStringList{QStringLiteral("event"), QStringLiteral("none")});
        m_shortcutConfirmCheck = new QCheckBox(m_shortcutBox);
        m_shortcutEnableCheck = new QCheckBox(m_shortcutBox);
        m_shortcutBackoffCheck = new QCheckBox(m_shortcutBox);
        m_shortcutKillCheck = new QCheckBox(m_shortcutBox);
        m_btnShortcutStatus = new QPushButton(m_shortcutBox);
        m_btnShortcutPrimary = new QPushButton(m_shortcutBox);
        m_btnShortcutSecondary = new QPushButton(m_shortcutBox);
        m_btnShortcutTertiary = new QPushButton(m_shortcutBox);
        m_btnShortcutQuaternary = new QPushButton(m_shortcutBox);
        row->addWidget(m_shortcutPidEdit);
        row->addWidget(m_shortcutNameEdit);
        row->addWidget(m_shortcutIdEdit);
        row->addWidget(m_shortcutPathEdit, 1);
        row->addWidget(m_shortcutArgsEdit);
        row->addWidget(m_shortcutMaxEdit);
        row->addWidget(m_shortcutWindowEdit);
        row->addWidget(m_shortcutDelayEdit);
        row->addWidget(m_shortcutHangEdit);
        row->addWidget(m_shortcutTypeCombo);
        row->addWidget(m_shortcutStateCombo);
        row->addWidget(m_shortcutActionCombo);
        row->addWidget(m_shortcutConfirmCheck);
        row->addWidget(m_shortcutEnableCheck);
        row->addWidget(m_shortcutBackoffCheck);
        row->addWidget(m_shortcutKillCheck);
        row->addWidget(m_btnShortcutStatus);
        row->addWidget(m_btnShortcutPrimary);
        row->addWidget(m_btnShortcutSecondary);
        row->addWidget(m_btnShortcutTertiary);
        row->addWidget(m_btnShortcutQuaternary);
        layout->addWidget(m_shortcutBox);
    }

    auto *callRow = new QHBoxLayout();
    m_lblMethod = new QLabel(this);
    callRow->addWidget(m_lblMethod);
    m_methodEdit = new QLineEdit(this);
    m_methodEdit->setPlaceholderText(QStringLiteral("profile.apply"));
    m_methodEdit->setText(defaultMethod());
    callRow->addWidget(m_methodEdit);
    m_lblRequest = new QLabel(this);
    callRow->addWidget(m_lblRequest);
    m_requestEdit = new QLineEdit(this);
    m_requestEdit->setPlaceholderText(QStringLiteral("{\"pid\":1234}"));
    m_requestEdit->setText(QStringLiteral("{}"));
    callRow->addWidget(m_requestEdit, 1);
    m_btnCall = new QPushButton(this);
    m_btnList = new QPushButton(this);
    m_btnReload = new QPushButton(this);
    callRow->addWidget(m_btnCall);
    callRow->addWidget(m_btnList);
    callRow->addWidget(m_btnReload);
    layout->addLayout(callRow);

    m_output = new QTextEdit(this);
    m_output->setReadOnly(true);
    layout->addWidget(m_output, 0);

    m_process = new QProcess(this);
    m_process->setProcessEnvironment(QProcessEnvironment::systemEnvironment());
    connect(m_process, &QProcess::readyReadStandardOutput, this, [this]() {
        appendOutput(QString::fromUtf8(m_process->readAllStandardOutput()));
    });
    connect(m_process, &QProcess::readyReadStandardError, this, [this]() {
        appendOutput(QString::fromUtf8(m_process->readAllStandardError()));
    });
    connect(m_process, &QProcess::finished, this, [this](int exitCode, QProcess::ExitStatus status) {
        const QString st = (status == QProcess::NormalExit) ? "NormalExit" : "CrashExit";
        appendOutput(trUi("process finished: exitCode=", "进程结束：exitCode=") +
                     QString::number(exitCode) + ", status=" + st);
    });
    connect(m_process, &QProcess::errorOccurred, this, [this](QProcess::ProcessError err) {
        QString name;
        switch (err)
        {
        case QProcess::FailedToStart: name = "FailedToStart"; break;
        case QProcess::Crashed: name = "Crashed"; break;
        case QProcess::Timedout: name = "Timedout"; break;
        case QProcess::WriteError: name = "WriteError"; break;
        case QProcess::ReadError: name = "ReadError"; break;
        default: name = "UnknownError"; break;
        }
        appendOutput(trUi("process error: ", "进程错误：") + name);
    });

    connect(m_btnCall, &QPushButton::clicked, this, [this]() {
        const QString req = m_requestEdit->text().trimmed();
        const QString method = m_methodEdit->text().trimmed();
        if (req.isEmpty())
        {
            appendOutput(trUi("JSON params are required for module invoke", "module invoke 需要 JSON 参数"));
            return;
        }
        if (method.isEmpty())
        {
            appendOutput(trUi("method is required for module invoke", "module invoke 需要方法名"));
            return;
        }
        runCommand({"module", "invoke", "--name", m_folder, "--method", method, "--params-json", req});
    });
    connect(m_btnList, &QPushButton::clicked, this, [this]() {
        runCommand({"module", "list"});
    });
    connect(m_btnReload, &QPushButton::clicked, this, [this]() {
        reloadHtml();
    });
    if (isPpl)
    {
        connect(m_btnPplSet, &QPushButton::clicked, this, [this]() {
            if (pidArg().isEmpty()) { appendOutput(trUi("PID is required", "需要 PID")); return; }
            runCommand({"ppl", "set", "--pid", pidArg(), "--signer", m_signerCombo->currentText()});
        });
        connect(m_btnPplGet, &QPushButton::clicked, this, [this]() {
            if (pidArg().isEmpty()) { appendOutput(trUi("PID is required", "需要 PID")); return; }
            runCommand({"ppl", "get", "--pid", pidArg()});
        });
        connect(m_btnPplClear, &QPushButton::clicked, this, [this]() {
            if (pidArg().isEmpty()) { appendOutput(trUi("PID is required", "需要 PID")); return; }
            runCommand({"ppl", "clear", "--pid", pidArg()});
        });
    }
    if (m_metricsBox)
    {
        connect(m_btnMetricsSummary, &QPushButton::clicked, this, [this]() { runCommand({"metrics", "summary"}); });
        connect(m_btnMetricsJson, &QPushButton::clicked, this, [this]() { runCommand({"metrics", "json"}); });
        connect(m_btnMetricsProm, &QPushButton::clicked, this, [this]() { runCommand({"metrics", "prometheus"}); });
    }
    if (m_backupBox)
    {
        connect(m_btnBackupStatus, &QPushButton::clicked, this, [this]() { runCommand({"backup", "status"}); });
        connect(m_btnBackupSnapshot, &QPushButton::clicked, this, [this]() {
            QStringList args{"backup", "snapshot"};
            if (m_backupArtifactCheck && m_backupArtifactCheck->isChecked()) args << "--artifact";
            const QString maxBytes = textOf(m_backupMaxBytesEdit);
            if (!maxBytes.isEmpty()) args << "--max-bytes" << maxBytes;
            runCommand(args);
        });
    }
    if (m_eventlogBox)
    {
        connect(m_btnEventlogStatus, &QPushButton::clicked, this, [this]() { runCommand({"eventlog", "status"}); });
        connect(m_btnEventlogRecent, &QPushButton::clicked, this, [this]() {
            QStringList args{"eventlog", "recent"};
            const QString limit = textOf(m_eventlogLimitEdit);
            const QString source = textOf(m_eventlogSourceEdit);
            if (!limit.isEmpty()) args << "--limit" << limit;
            if (!source.isEmpty()) args << "--source" << source;
            runCommand(args);
        });
    }
    if (m_schedBox)
    {
        connect(m_btnSchedAdd, &QPushButton::clicked, this, [this]() {
            const QString expr = textOf(m_schedExprEdit);
            const QString action = textOf(m_schedActionEdit);
            if (expr.isEmpty() || action.isEmpty()) { appendOutput(trUi("Expression and action are required", "需要表达式和动作")); return; }
            QStringList args{"sched", "add", "--action", action};
            const QString type = m_schedTypeCombo->currentText();
            if (type == QStringLiteral("cron")) args << "--cron" << expr;
            else if (type == QStringLiteral("once")) args << "--once" << expr;
            else args << "--interval" << expr;
            const QString count = textOf(m_schedCountEdit);
            if (!count.isEmpty()) args << "--count" << count;
            runCommand(args);
        });
        connect(m_btnSchedList, &QPushButton::clicked, this, [this]() { runCommand({"sched", "list"}); });
        connect(m_btnSchedEnable, &QPushButton::clicked, this, [this]() {
            const QString id = textOf(m_schedIdEdit); if (id.isEmpty()) { appendOutput(trUi("Schedule ID is required", "需要计划 ID")); return; } runCommand({"sched", "enable", "--id", id});
        });
        connect(m_btnSchedDisable, &QPushButton::clicked, this, [this]() {
            const QString id = textOf(m_schedIdEdit); if (id.isEmpty()) { appendOutput(trUi("Schedule ID is required", "需要计划 ID")); return; } runCommand({"sched", "disable", "--id", id});
        });
        connect(m_btnSchedRemove, &QPushButton::clicked, this, [this]() {
            const QString id = textOf(m_schedIdEdit); if (id.isEmpty()) { appendOutput(trUi("Schedule ID is required", "需要计划 ID")); return; } runCommand({"sched", "remove", "--id", id});
        });
    }
    if (m_notifyBox)
    {
        connect(m_btnNotifyStatus, &QPushButton::clicked, this, [this]() { runCommand({"notify", "status"}); });
        connect(m_btnNotifyApply, &QPushButton::clicked, this, [this]() {
            QStringList args{"notify", "config"};
            args << (m_notifyEventLogCheck->isChecked() ? "--eventlog" : "--no-eventlog");
            args << (m_notifyPopupCheck->isChecked() ? "--popup" : "--no-popup");
            runCommand(args);
        });
    }
    if (m_reportBox)
    {
        auto buildReportArgs = [this](const QString &kind) {
            QStringList args{"report", kind};
            const QString limit = textOf(m_reportLimitEdit);
            if (!limit.isEmpty()) args << "--limit" << limit;
            if (m_reportArtifactCheck->isChecked()) args << "--artifact";
            return args;
        };
        connect(m_btnReportSnapshot, &QPushButton::clicked, this, [this, buildReportArgs]() { runCommand(buildReportArgs(QStringLiteral("snapshot"))); });
        connect(m_btnReportBackup, &QPushButton::clicked, this, [this, buildReportArgs]() { runCommand(buildReportArgs(QStringLiteral("backup"))); });
        connect(m_btnOperationStatus, &QPushButton::clicked, this, [this]() {
            const QString id = textOf(m_operationIdEdit); if (id.isEmpty()) { appendOutput(trUi("Operation ID is required", "需要操作 ID")); return; } runCommand({"module", "op-status", id, "--json"});
        });
        connect(m_btnArtifactMeta, &QPushButton::clicked, this, [this]() {
            const QString id = textOf(m_artifactIdEdit); if (id.isEmpty()) { appendOutput(trUi("Artifact ID is required", "需要工件 ID")); return; } runCommand({"module", "artifact", "get", id, "--json"});
        });
        connect(m_btnArtifactStatus, &QPushButton::clicked, this, [this]() {
            QStringList args{"module", "artifact", "status", "--json"};
            if (m_artifactVerifyStatusCheck && m_artifactVerifyStatusCheck->isChecked()) args << "--verify";
            runCommand(args);
        });
        connect(m_btnArtifactPolicy, &QPushButton::clicked, this, [this]() {
            QStringList args{"module", "artifact", "policy", "--json"};
            const QString ttl = textOf(m_artifactTtlEdit);
            if (!ttl.isEmpty()) args << "--ttl-ms" << ttl;
            args << ((m_artifactAutoCleanupCheck && m_artifactAutoCleanupCheck->isChecked()) ? "--auto-cleanup" : "--no-auto-cleanup");
            args << ((m_artifactVerifyStatusCheck && m_artifactVerifyStatusCheck->isChecked()) ? "--verify-on-status" : "--no-verify-on-status");
            runCommand(args);
        });
        connect(m_btnArtifactDownload, &QPushButton::clicked, this, [this]() {
            const QString id = textOf(m_artifactIdEdit); const QString out = textOf(m_artifactOutEdit); if (id.isEmpty() || out.isEmpty()) { appendOutput(trUi("Artifact ID and output path are required", "需要工件 ID 和输出路径")); return; } runCommand({"module", "artifact", "get", id, "--out", out});
        });
    }
    if (m_shortcutBox)
    {
        const QString key = m_folder.toLower();
        auto requirePid = [this]() { const QString pid = textOf(m_shortcutPidEdit); if (pid.isEmpty()) appendOutput(trUi("PID is required", "需要 PID")); return pid; };
        auto requireName = [this]() { const QString name = textOf(m_shortcutNameEdit); if (name.isEmpty()) appendOutput(trUi("Name is required", "需要名称")); return name; };
        auto requireId = [this]() { const QString id = textOf(m_shortcutIdEdit); if (id.isEmpty()) appendOutput(trUi("ID is required", "需要 ID")); return id; };
        auto requirePath = [this]() { const QString path = textOf(m_shortcutPathEdit); if (path.isEmpty()) appendOutput(trUi("Path is required", "需要路径")); return path; };
        connect(m_btnShortcutStatus, &QPushButton::clicked, this, [this, key]() {
            if (key == QStringLiteral("service_guard")) runCommand({"service-guard", "status"});
            else if (key == QStringLiteral("file_watch")) runCommand({"file-watch", "status"});
            else if (key == QStringLiteral("policy")) runCommand({"policy-template", "status"});
            else if (key == QStringLiteral("remote_agent")) runCommand({"remote-agent", "status"});
            else if (key == QStringLiteral("script_runner")) runCommand({"script-runner", "status"});
            else { QString command = key; command.replace('_', '-'); runCommand({command, "status"}); }
        });
        connect(m_btnShortcutPrimary, &QPushButton::clicked, this, [this, key, requirePid, requireName, requireId, requirePath]() {
            if (key == QStringLiteral("dump")) { const QString pid = requirePid(); if (!pid.isEmpty()) { QStringList args{"dump", "collect", "--pid", pid, "--type", m_shortcutTypeCombo->currentText()}; if (m_shortcutConfirmCheck->isChecked()) args << "--confirm"; runCommand(args); } }
            else if (key == QStringLiteral("service_guard")) { const QString name = requireName(); if (!name.isEmpty()) { QStringList args{"service-guard", "query", "--name", name}; runCommand(args); } }
            else if (key == QStringLiteral("file_watch")) { const QString path = requirePath(); if (!path.isEmpty()) { QStringList args{"file-watch", "add", "--path", path, "--action", m_shortcutActionCombo->currentText()}; const QString id = textOf(m_shortcutIdEdit); if (!id.isEmpty()) args << "--id" << id; runCommand(args); } }
            else if (key == QStringLiteral("policy")) { const QString name = requireName(); if (!name.isEmpty()) { QStringList args{"policy-template", "set", "--name", name}; const QString max = textOf(m_shortcutMaxEdit); if (!max.isEmpty()) args << "--max-restarts" << max; const QString a = textOf(m_shortcutArgsEdit); if (!a.isEmpty()) args << "--restart-args" << a; const QString w = textOf(m_shortcutWindowEdit); if (!w.isEmpty()) args << "--restart-window" << w; const QString d = textOf(m_shortcutDelayEdit); if (!d.isEmpty()) args << "--restart-delay" << d; const QString h = textOf(m_shortcutHangEdit); if (!h.isEmpty()) args << "--hang-timeout" << h; if (m_shortcutBackoffCheck->isChecked()) args << "--restart-backoff"; if (m_shortcutKillCheck->isChecked()) args << "--kill-on-exit"; runCommand(args); } }
            else if (key == QStringLiteral("remote_agent")) runCommand({"remote-agent", "heartbeat"});
            else if (key == QStringLiteral("update")) { const QString path = requirePath(); if (!path.isEmpty()) runCommand({"update", "verify", "--path", path}); }
            else if (key == QStringLiteral("script_runner")) { const QString id = requireId(); const QString path = requirePath(); if (!id.isEmpty() && !path.isEmpty()) { QStringList args{"script-runner", "add", "--id", id, "--path", path}; const QString a = textOf(m_shortcutArgsEdit); if (!a.isEmpty()) args << "--start-args" << a; runCommand(args); } }
        });
        connect(m_btnShortcutSecondary, &QPushButton::clicked, this, [this, key, requireName, requireId]() {
            if (key == QStringLiteral("service_guard")) { const QString name = requireName(); if (!name.isEmpty()) { QStringList args{"service-guard", "ensure", "--name", name, "--state", m_shortcutStateCombo->currentText()}; if (m_shortcutConfirmCheck->isChecked()) args << "--confirm"; runCommand(args); } }
            else if (key == QStringLiteral("file_watch")) runCommand({"file-watch", "list"});
            else if (key == QStringLiteral("policy")) runCommand({"policy-template", "list"});
            else if (key == QStringLiteral("remote_agent")) runCommand({"remote-agent", "guards"});
            else if (key == QStringLiteral("script_runner")) runCommand({"script-runner", "list"});
            else if (key == QStringLiteral("update")) runCommand({"update", "status"});
            else if (key == QStringLiteral("dump")) runCommand({"dump", "status"});
        });
        connect(m_btnShortcutTertiary, &QPushButton::clicked, this, [this, key, requireName, requireId]() {
            if (key == QStringLiteral("service_guard")) { const QString name = requireName(); if (!name.isEmpty()) { QStringList args{"service-guard", "start", "--name", name}; if (m_shortcutConfirmCheck->isChecked()) args << "--confirm"; runCommand(args); } }
            else if (key == QStringLiteral("file_watch")) runCommand({"file-watch", "check"});
            else if (key == QStringLiteral("policy")) { const QString name = requireName(); const QString pid = textOf(m_shortcutPidEdit); if (!name.isEmpty() && !pid.isEmpty()) runCommand({"policy-template", "apply", "--name", name, "--pid", pid}); else appendOutput(trUi("Name and PID are required", "需要名称和 PID")); }
            else if (key == QStringLiteral("script_runner")) { const QString id = requireId(); if (!id.isEmpty()) { QStringList args{"script-runner", "run", "--id", id}; if (m_shortcutConfirmCheck->isChecked()) args << "--confirm"; runCommand(args); } }
        });
        connect(m_btnShortcutQuaternary, &QPushButton::clicked, this, [this, key, requireName, requireId]() {
            if (key == QStringLiteral("service_guard")) { const QString name = requireName(); if (!name.isEmpty()) { QStringList args{"service-guard", "stop", "--name", name}; if (m_shortcutConfirmCheck->isChecked()) args << "--confirm"; runCommand(args); } }
            else if (key == QStringLiteral("file_watch")) { const QString id = requireId(); if (!id.isEmpty()) runCommand({"file-watch", "remove", "--id", id}); }
            else if (key == QStringLiteral("policy")) { const QString name = requireName(); if (!name.isEmpty()) runCommand({"policy-template", "remove", "--name", name}); }
            else if (key == QStringLiteral("script_runner")) runCommand({"script-runner", "config", m_shortcutEnableCheck->isChecked() ? "--enable" : "--disable"});
        });
    }
}

void ModulePage::retranslateUi()
{
    if (m_riskLabel) m_riskLabel->setText(trUi("High-risk module: loading and invoking driver/kernel features requires explicit service opt-in and trusted module files.", "高风险模块：加载和调用驱动/内核能力需要服务显式启用，并且模块文件必须已受信任。"));
    if (m_lblPid) m_lblPid->setText(trUi("PID:", "PID："));
    if (m_lblSigner) m_lblSigner->setText(trUi("Signer:", "签名："));
    if (m_lblMethod) m_lblMethod->setText(trUi("Method:", "方法："));
    if (m_lblRequest) m_lblRequest->setText(trUi("Request:", "请求："));
    if (m_btnCall) m_btnCall->setText(trUi("Invoke", "调用"));
    if (m_btnList) m_btnList->setText(trUi("List modules", "列出模块"));
    if (m_btnReload) m_btnReload->setText(trUi("Reload HTML", "重载 HTML"));
    if (m_btnPplSet) m_btnPplSet->setText(trUi("PPL Set", "PPL 设置"));
    if (m_btnPplGet) m_btnPplGet->setText(trUi("PPL Get", "PPL 查询"));
    if (m_btnPplClear) m_btnPplClear->setText(trUi("PPL Clear", "PPL 清除"));
    if (m_pplBox) m_pplBox->setTitle(trUi("PPL convenience (ppl set/get/clear)", "PPL 便捷操作 (ppl set/get/clear)"));
    if (m_metricsBox) m_metricsBox->setTitle(trUi("Metrics", "指标"));
    if (m_btnMetricsSummary) m_btnMetricsSummary->setText(trUi("Summary", "摘要"));
    if (m_btnMetricsJson) m_btnMetricsJson->setText(trUi("JSON", "JSON"));
    if (m_btnMetricsProm) m_btnMetricsProm->setText(trUi("Prometheus", "Prometheus"));
    if (m_backupBox) m_backupBox->setTitle(trUi("Backup", "备份"));
    if (m_backupArtifactCheck) m_backupArtifactCheck->setText(trUi("Artifact", "存为工件"));
    if (m_btnBackupStatus) m_btnBackupStatus->setText(trUi("Status", "状态"));
    if (m_btnBackupSnapshot) m_btnBackupSnapshot->setText(trUi("Snapshot", "快照"));
    if (m_eventlogBox) m_eventlogBox->setTitle(trUi("Event log", "事件日志"));
    if (m_btnEventlogStatus) m_btnEventlogStatus->setText(trUi("Status", "状态"));
    if (m_btnEventlogRecent) m_btnEventlogRecent->setText(trUi("Recent", "最近"));
    if (m_schedBox) m_schedBox->setTitle(trUi("Scheduler convenience", "计划模块便捷操作"));
    if (m_btnSchedAdd) m_btnSchedAdd->setText(trUi("Add", "添加"));
    if (m_btnSchedList) m_btnSchedList->setText(trUi("List", "列表"));
    if (m_btnSchedEnable) m_btnSchedEnable->setText(trUi("Enable", "启用"));
    if (m_btnSchedDisable) m_btnSchedDisable->setText(trUi("Disable", "禁用"));
    if (m_btnSchedRemove) m_btnSchedRemove->setText(trUi("Remove", "删除"));
    if (m_notifyBox) m_notifyBox->setTitle(trUi("Windows-native notifications", "Windows 本机通知"));
    if (m_notifyEventLogCheck) m_notifyEventLogCheck->setText(trUi("Event Log", "事件日志"));
    if (m_notifyPopupCheck) m_notifyPopupCheck->setText(trUi("Local popup", "本机弹窗"));
    if (m_btnNotifyStatus) m_btnNotifyStatus->setText(trUi("Status", "状态"));
    if (m_btnNotifyApply) m_btnNotifyApply->setText(trUi("Apply", "应用"));
    if (m_reportBox) m_reportBox->setTitle(trUi("Reports and artifacts", "报告与工件"));
    if (m_reportArtifactCheck) m_reportArtifactCheck->setText(trUi("Artifact", "存为工件"));
    if (m_btnReportSnapshot) m_btnReportSnapshot->setText(trUi("Snapshot", "快照"));
    if (m_btnReportBackup) m_btnReportBackup->setText(trUi("Backup", "备份"));
    if (m_btnOperationStatus) m_btnOperationStatus->setText(trUi("Operation", "操作"));
    if (m_btnArtifactMeta) m_btnArtifactMeta->setText(trUi("Meta", "元数据"));
    if (m_btnArtifactStatus) m_btnArtifactStatus->setText(trUi("Store", "存储"));
    if (m_btnArtifactPolicy) m_btnArtifactPolicy->setText(trUi("Policy", "策略"));
    if (m_artifactAutoCleanupCheck) m_artifactAutoCleanupCheck->setText(trUi("Auto cleanup", "自动清理"));
    if (m_artifactVerifyStatusCheck) m_artifactVerifyStatusCheck->setText(trUi("Verify", "校验"));
    if (m_btnArtifactDownload) m_btnArtifactDownload->setText(trUi("Download", "下载"));
    if (m_shortcutBox) m_shortcutBox->setTitle(trUi("Bundled module actions", "内置模块操作"));
    if (m_shortcutConfirmCheck) m_shortcutConfirmCheck->setText(trUi("Confirm", "确认"));
    if (m_shortcutEnableCheck) m_shortcutEnableCheck->setText(trUi("Enable", "启用"));
    if (m_shortcutBackoffCheck) m_shortcutBackoffCheck->setText(trUi("Backoff", "退避"));
    if (m_shortcutKillCheck) m_shortcutKillCheck->setText(trUi("Kill", "级联"));
    if (m_btnShortcutStatus) m_btnShortcutStatus->setText(trUi("Status", "状态"));
    if (m_btnShortcutPrimary) m_btnShortcutPrimary->setText(trUi("Primary", "主操作"));
    if (m_btnShortcutSecondary) m_btnShortcutSecondary->setText(trUi("Secondary", "次操作"));
    if (m_btnShortcutTertiary) m_btnShortcutTertiary->setText(trUi("Apply/Run", "应用/运行"));
    if (m_btnShortcutQuaternary) m_btnShortcutQuaternary->setText(trUi("Remove/Stop", "删除/停止"));
}

void ModulePage::setChinese(bool ch)
{
    m_chinese = ch;
    retranslateUi();
}

void ModulePage::setToolPath(const QString &path) { m_toolPath = path; }
void ModulePage::setToken(const QString &token) { m_token = token; }

void ModulePage::reloadHtml()
{
    const QString path = QDir(m_moduleDir).filePath(m_folder + QStringLiteral("/module.html"));
    QFile f(path);
    if (f.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        m_html->setHtml(QString::fromUtf8(f.readAll()));
    }
    else
    {
        m_html->setPlainText(trUi("No module.html found at: ", "未找到 module.html：") + path);
    }
}

void ModulePage::runCommand(const QStringList &args)
{
    if (m_process->state() != QProcess::NotRunning)
    {
        appendOutput(trUi("previous command still running", "上一个命令仍在执行"));
        return;
    }
    QString program = m_toolPath;
    if (program.isEmpty() || !QFileInfo::exists(program))
    {
        appendOutput(trUi("pgs_bless not found: ", "未找到 pgs_bless：") + program);
        return;
    }
    QStringList finalArgs = args;
    // Pass the auth token via the environment instead of the command line.
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    if (!m_token.isEmpty())
        env.insert(QStringLiteral("PGS_AUTH_TOKEN"), m_token);
    appendOutput(">>> " + program + " " + finalArgs.join(' '));
    m_process->setWorkingDirectory(QFileInfo(program).absolutePath());
    m_process->setProcessEnvironment(env);
    m_process->start(program, finalArgs);
}

void ModulePage::appendOutput(const QString &text)
{
    m_output->append(text.trimmed());
}

QString ModulePage::defaultMethod() const
{
    const QString key = m_folder.toLower();
    if (key == QStringLiteral("ppl")) return QStringLiteral("ppl.get");
    if (key == QStringLiteral("sched")) return QStringLiteral("sched.list");
    if (key == QStringLiteral("health")) return QStringLiteral("health.summary");
    if (key == QStringLiteral("profile")) return QStringLiteral("profile.list");
    if (key == QStringLiteral("report")) return QStringLiteral("report.snapshot");
    if (key == QStringLiteral("notify")) return QStringLiteral("notify.status");
    if (key == QStringLiteral("metrics")) return QStringLiteral("metrics.summary");
    if (key == QStringLiteral("backup")) return QStringLiteral("backup.status");
    if (key == QStringLiteral("eventlog")) return QStringLiteral("eventlog.status");
    if (key == QStringLiteral("dump")) return QStringLiteral("dump.status");
    if (key == QStringLiteral("service_guard")) return QStringLiteral("service_guard.status");
    if (key == QStringLiteral("file_watch")) return QStringLiteral("file_watch.status");
    if (key == QStringLiteral("policy")) return QStringLiteral("policy.status");
    if (key == QStringLiteral("remote_agent")) return QStringLiteral("remote_agent.status");
    if (key == QStringLiteral("update")) return QStringLiteral("update.status");
    if (key == QStringLiteral("script_runner")) return QStringLiteral("script_runner.status");
    return key + QStringLiteral(".info");
}

QString ModulePage::pidArg() const
{
    return m_pidEdit ? m_pidEdit->text().trimmed() : QString();
}

QString ModulePage::textOf(QLineEdit *edit) const
{
    return edit ? edit->text().trimmed() : QString();
}
