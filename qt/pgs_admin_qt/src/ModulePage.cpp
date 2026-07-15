/**
 * @file ModulePage.cpp
 * @brief Implementation of ModulePage.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "ModulePage.h"

#include <QComboBox>
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
    return key + QStringLiteral(".info");
}

QString ModulePage::pidArg() const
{
    return m_pidEdit ? m_pidEdit->text().trimmed() : QString();
}
