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
    m_lblRequest = new QLabel(this);
    callRow->addWidget(m_lblRequest);
    m_requestEdit = new QLineEdit(this);
    m_requestEdit->setPlaceholderText(QStringLiteral("op=set;pid=1234;signer=Antimalware"));
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
        if (req.isEmpty())
        {
            appendOutput(trUi("request is required for module call", "module call 需要请求内容"));
            return;
        }
        runCommand({"module", "call", "--name", m_folder, "--request", req});
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
    if (m_lblPid) m_lblPid->setText(trUi("PID:", "PID："));
    if (m_lblSigner) m_lblSigner->setText(trUi("Signer:", "签名："));
    if (m_lblRequest) m_lblRequest->setText(trUi("Request:", "请求："));
    if (m_btnCall) m_btnCall->setText(trUi("Call (module call)", "调用 (module call)"));
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
    if (!m_token.isEmpty())
        finalArgs << "--token" << m_token;
    appendOutput(">>> " + program + " " + finalArgs.join(' '));
    m_process->setWorkingDirectory(QFileInfo(program).absolutePath());
    m_process->start(program, finalArgs);
}

void ModulePage::appendOutput(const QString &text)
{
    m_output->append(text.trimmed());
}

QString ModulePage::pidArg() const
{
    return m_pidEdit ? m_pidEdit->text().trimmed() : QString();
}