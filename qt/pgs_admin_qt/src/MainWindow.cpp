#include "MainWindow.h"
#include "ModulePage.h"

#include <QCheckBox>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QProcess>
#include <QProcessEnvironment>
#include <QPushButton>
#include <QAbstractItemView>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextEdit>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>
#include <QStatusBar>
#include <QSettings>
#include <QBrush>
#include <QColor>
#include <QFile>
#include <QApplication>

namespace
{
QStringList redactedArgsForLog(QStringList args)
{
    static const QStringList sensitiveFlags{
        QStringLiteral("--token"),
        QStringLiteral("--old-token"),
        QStringLiteral("--new-token"),
        QStringLiteral("--service-password")
    };
    for (int i = 0; i + 1 < args.size(); ++i)
    {
        if (sensitiveFlags.contains(args.at(i)))
        {
            args[i + 1] = QStringLiteral("<redacted>");
            ++i;
        }
    }
    return args;
}
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      m_blessProcess(new QProcess(this)),
      m_serviceProcess(new QProcess(this)),
      m_tableProcess(new QProcess(this))
{
    setupUi();
    loadSavedPrefs();
    attachProcessHandlers();
}

void MainWindow::attachProcessHandlers()
{
    connect(m_blessProcess, &QProcess::readyReadStandardOutput, this, [this]() {
        appendBlessOutput(QString::fromUtf8(m_blessProcess->readAllStandardOutput()));
    });
    connect(m_blessProcess, &QProcess::readyReadStandardError, this, [this]() {
        appendBlessOutput(QString::fromUtf8(m_blessProcess->readAllStandardError()));
    });
    connect(m_blessProcess, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
        QString msg = trUi("process error: ", "进程错误：");
        switch (error)
        {
        case QProcess::FailedToStart:
            msg += "FailedToStart";
            break;
        case QProcess::Crashed:
            msg += "Crashed";
            break;
        case QProcess::Timedout:
            msg += "Timedout";
            break;
        case QProcess::WriteError:
            msg += "WriteError";
            break;
        case QProcess::ReadError:
            msg += "ReadError";
            break;
        case QProcess::UnknownError:
        default:
            msg += "UnknownError";
            break;
        }
        m_blessBusyNoticeShown = false;
        appendBlessOutput(msg);
    });
    connect(m_blessProcess, &QProcess::finished, this, [this](int exitCode, QProcess::ExitStatus status) {
        const QString statusText = (status == QProcess::NormalExit) ? "NormalExit" : "CrashExit";
        m_blessBusyNoticeShown = false;
        appendBlessOutput(trUi("process finished: exitCode=", "进程结束：exitCode=") +
                          QString::number(exitCode) + ", status=" + statusText);
    });

    connect(m_serviceProcess, &QProcess::readyReadStandardOutput, this, [this]() {
        appendServiceOutput(QString::fromUtf8(m_serviceProcess->readAllStandardOutput()));
    });
    connect(m_serviceProcess, &QProcess::readyReadStandardError, this, [this]() {
        appendServiceOutput(QString::fromUtf8(m_serviceProcess->readAllStandardError()));
    });
    connect(m_serviceProcess, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
        QString msg = trUi("service process error: ", "服务进程错误：");
        switch (error)
        {
        case QProcess::FailedToStart:
            msg += "FailedToStart";
            break;
        case QProcess::Crashed:
            msg += "Crashed";
            break;
        case QProcess::Timedout:
            msg += "Timedout";
            break;
        case QProcess::WriteError:
            msg += "WriteError";
            break;
        case QProcess::ReadError:
            msg += "ReadError";
            break;
        case QProcess::UnknownError:
        default:
            msg += "UnknownError";
            break;
        }
        m_serviceBusyNoticeShown = false;
        m_serviceSequenceRunning = false;
        m_serviceRunModeActive = false;
        m_serviceStopPending = false;
        m_serviceSequenceCommands.clear();
        appendServiceOutput(msg);
    });
    connect(m_serviceProcess, &QProcess::finished, this, [this](int exitCode, QProcess::ExitStatus status) {
        const QString statusText = (status == QProcess::NormalExit) ? "NormalExit" : "CrashExit";
        m_serviceBusyNoticeShown = false;
        m_serviceRunModeActive = false;
        m_serviceStopPending = false;
        appendServiceOutput(trUi("process finished: exitCode=", "进程结束：exitCode=") +
                            QString::number(exitCode) + ", status=" + statusText);

        if (!m_serviceSequenceRunning)
        {
            return;
        }
        if (exitCode != 0 || status != QProcess::NormalExit)
        {
            m_serviceSequenceRunning = false;
            m_serviceSequenceCommands.clear();
            appendServiceOutput(trUi("service reset aborted due to previous step failure",
                                     "服务重置中止：前一步失败"));
            return;
        }
        runNextServiceSequenceStep();
    });

    connect(m_tableProcess, &QProcess::readyReadStandardOutput, this, [this]() {
        const QByteArray bytes = m_tableProcess->readAllStandardOutput();
        m_tableStdoutBuffer += QString::fromUtf8(bytes);
    });
    connect(m_tableProcess, &QProcess::readyReadStandardError, this, [this]() {
        m_tableStderrBuffer += QString::fromUtf8(m_tableProcess->readAllStandardError());
    });
    connect(m_tableProcess, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
        QString msg = trUi("table process error: ", "表格进程错误：");
        switch (error)
        {
        case QProcess::FailedToStart:
            msg += "FailedToStart";
            break;
        case QProcess::Crashed:
            msg += "Crashed";
            break;
        case QProcess::Timedout:
            msg += "Timedout";
            break;
        case QProcess::WriteError:
            msg += "WriteError";
            break;
        case QProcess::ReadError:
            msg += "ReadError";
            break;
        case QProcess::UnknownError:
        default:
            msg += "UnknownError";
            break;
        }
        statusBar()->showMessage(msg, 5000);
        m_tableStdoutBuffer.clear();
        m_tableStderrBuffer.clear();
    });
    connect(m_tableProcess, &QProcess::finished, this, [this](int exitCode, QProcess::ExitStatus status) {
        if (exitCode == 0 && status == QProcess::NormalExit)
        {
            populateGuardTableFromJson(m_tableStdoutBuffer.trimmed(), m_tableStderrBuffer.trimmed());
        }
        else
        {
            const QString detail = m_tableStderrBuffer.trimmed();
            QString message = trUi("guard table refresh failed", "守护表格刷新失败");
            if (!detail.isEmpty())
            {
                message += QStringLiteral(": ") + detail.left(240);
            }
            statusBar()->showMessage(message, 5000);
        }
        m_tableStdoutBuffer.clear();
        m_tableStderrBuffer.clear();
    });
}

void MainWindow::setupUi()
{
    auto *central = new QWidget(this);
    auto *rootLayout = new QVBoxLayout(central);
    m_tabs = new QTabWidget(central);

    // Bless tab
    auto *blessPage = new QWidget(m_tabs);
    auto *blessLayout = new QVBoxLayout(blessPage);

    auto *connectionBox = new QGroupBox(blessPage);
    auto *connectionLayout = new QGridLayout(connectionBox);
    m_titleConnection = new QLabel(connectionBox);
    connectionLayout->addWidget(m_titleConnection, 0, 0, 1, 2);

    m_labelToolPath = new QLabel(connectionBox);
    connectionLayout->addWidget(m_labelToolPath, 1, 0);
    m_toolPathEdit = new QLineEdit(blessToolPath(), connectionBox);
    connectionLayout->addWidget(m_toolPathEdit, 1, 1);

    m_labelToken = new QLabel(connectionBox);
    connectionLayout->addWidget(m_labelToken, 2, 0);
    m_tokenEdit = new QLineEdit(connectionBox);
    m_tokenEdit->setEchoMode(QLineEdit::Password);
    connectionLayout->addWidget(m_tokenEdit, 2, 1);

    m_labelLanguage = new QLabel(connectionBox);
    connectionLayout->addWidget(m_labelLanguage, 3, 0);
    m_languageCombo = new QComboBox(connectionBox);
    m_languageCombo->addItem("中文");
    m_languageCombo->addItem("English");
    connectionLayout->addWidget(m_languageCombo, 3, 1);

    m_labelTheme = new QLabel(connectionBox);
    connectionLayout->addWidget(m_labelTheme, 4, 0);
    m_themeCombo = new QComboBox(connectionBox);
    m_themeCombo->addItem("Light");
    m_themeCombo->addItem("Dark");
    connectionLayout->addWidget(m_themeCombo, 4, 1);

    m_labelNewToken = new QLabel(connectionBox);
    connectionLayout->addWidget(m_labelNewToken, 5, 0);
    m_newTokenEdit = new QLineEdit(connectionBox);
    m_newTokenEdit->setEchoMode(QLineEdit::Password);
    connectionLayout->addWidget(m_newTokenEdit, 5, 1);

    m_jsonCheck = new QCheckBox(connectionBox);
    connectionLayout->addWidget(m_jsonCheck, 6, 1);

    auto *targetBox = new QGroupBox(blessPage);
    auto *targetLayout = new QGridLayout(targetBox);
    m_titleTarget = new QLabel(targetBox);
    targetLayout->addWidget(m_titleTarget, 0, 0, 1, 2);

    m_labelPid = new QLabel(targetBox);
    targetLayout->addWidget(m_labelPid, 1, 0);
    m_pidEdit = new QLineEdit(targetBox);
    targetLayout->addWidget(m_pidEdit, 1, 1);

    m_labelLaunchPath = new QLabel(targetBox);
    targetLayout->addWidget(m_labelLaunchPath, 2, 0);
    m_launchPathEdit = new QLineEdit(targetBox);
    targetLayout->addWidget(m_launchPathEdit, 2, 1);

    m_labelLaunchArgs = new QLabel(targetBox);
    targetLayout->addWidget(m_labelLaunchArgs, 3, 0);
    m_launchArgsEdit = new QLineEdit(targetBox);
    targetLayout->addWidget(m_launchArgsEdit, 3, 1);

    m_labelLaunchCommand = new QLabel(targetBox);
    targetLayout->addWidget(m_labelLaunchCommand, 4, 0);
    m_launchCommandEdit = new QLineEdit(targetBox);
    targetLayout->addWidget(m_launchCommandEdit, 4, 1);

    m_labelMaxRestarts = new QLabel(targetBox);
    targetLayout->addWidget(m_labelMaxRestarts, 5, 0);
    m_maxRestartsEdit = new QLineEdit("3", targetBox);
    targetLayout->addWidget(m_maxRestartsEdit, 5, 1);

    m_labelRestartArgs = new QLabel(targetBox);
    targetLayout->addWidget(m_labelRestartArgs, 6, 0);
    m_restartArgsEdit = new QLineEdit(targetBox);
    targetLayout->addWidget(m_restartArgsEdit, 6, 1);

    auto *buttonRow1 = new QHBoxLayout();
    m_btnPing = new QPushButton(blessPage);
    m_btnList = new QPushButton(blessPage);
    m_btnGet = new QPushButton(blessPage);
    m_btnClear = new QPushButton(blessPage);
    buttonRow1->addWidget(m_btnPing);
    buttonRow1->addWidget(m_btnList);
    buttonRow1->addWidget(m_btnGet);
    buttonRow1->addWidget(m_btnClear);

    auto *buttonRow2 = new QHBoxLayout();
    m_btnBless = new QPushButton(blessPage);
    m_btnBlessStart = new QPushButton(blessPage);
    m_btnUnbless = new QPushButton(blessPage);
    m_btnPolicy = new QPushButton(blessPage);
    m_btnIntentional = new QPushButton(blessPage);
    m_btnTokenSet = new QPushButton(blessPage);
    buttonRow2->addWidget(m_btnBless);
    buttonRow2->addWidget(m_btnBlessStart);
    buttonRow2->addWidget(m_btnUnbless);
    buttonRow2->addWidget(m_btnPolicy);
    buttonRow2->addWidget(m_btnIntentional);
    buttonRow2->addWidget(m_btnTokenSet);

    m_blessOutput = new QTextEdit(blessPage);
    m_blessOutput->setReadOnly(true);

    blessLayout->addWidget(connectionBox);
    blessLayout->addWidget(targetBox);
    blessLayout->addLayout(buttonRow1);
    blessLayout->addLayout(buttonRow2);
    blessLayout->addWidget(m_blessOutput, 1);

    // Service tab
    auto *servicePage = new QWidget(m_tabs);
    auto *serviceLayout = new QVBoxLayout(servicePage);

    auto *serviceBox = new QGroupBox(servicePage);
    auto *serviceGrid = new QGridLayout(serviceBox);
    m_titleService = new QLabel(serviceBox);
    serviceGrid->addWidget(m_titleService, 0, 0, 1, 2);

    m_labelServicePath = new QLabel(serviceBox);
    serviceGrid->addWidget(m_labelServicePath, 1, 0);
    m_servicePathEdit = new QLineEdit(serviceToolPath(), serviceBox);
    serviceGrid->addWidget(m_servicePathEdit, 1, 1);

    m_labelServiceToken = new QLabel(serviceBox);
    serviceGrid->addWidget(m_labelServiceToken, 2, 0);
    m_serviceTokenEdit = new QLineEdit(serviceBox);
    m_serviceTokenEdit->setEchoMode(QLineEdit::Password);
    serviceGrid->addWidget(m_serviceTokenEdit, 2, 1);

    auto *serviceRow1 = new QHBoxLayout();
    m_btnServiceInstall = new QPushButton(servicePage);
    m_btnServiceStatus = new QPushButton(servicePage);
    m_btnServiceStart = new QPushButton(servicePage);
    m_btnServiceStop = new QPushButton(servicePage);
    serviceRow1->addWidget(m_btnServiceInstall);
    serviceRow1->addWidget(m_btnServiceStatus);
    serviceRow1->addWidget(m_btnServiceStart);
    serviceRow1->addWidget(m_btnServiceStop);

    auto *serviceRow2 = new QHBoxLayout();
    m_btnServiceUninstall = new QPushButton(servicePage);
    m_btnServiceReset = new QPushButton(servicePage);
    m_btnServiceRun = new QPushButton(servicePage);
    m_btnServiceRunStop = new QPushButton(servicePage);
    m_btnServiceClear = new QPushButton(servicePage);
    serviceRow2->addWidget(m_btnServiceUninstall);
    serviceRow2->addWidget(m_btnServiceReset);
    serviceRow2->addWidget(m_btnServiceRun);
    serviceRow2->addWidget(m_btnServiceRunStop);
    serviceRow2->addWidget(m_btnServiceClear);

    m_serviceOutput = new QTextEdit(servicePage);
    m_serviceOutput->setReadOnly(true);

    serviceLayout->addWidget(serviceBox);
    serviceLayout->addLayout(serviceRow1);
    serviceLayout->addLayout(serviceRow2);
    serviceLayout->addWidget(m_serviceOutput, 1);

    m_tabs->addTab(blessPage, "");
    m_tabs->addTab(servicePage, "");

    // Table tab
    auto *tablePage = new QWidget(m_tabs);
    auto *tableLayout = new QVBoxLayout(tablePage);

    auto *tableConfigBox = new QGroupBox(tablePage);
    auto *tableGrid = new QGridLayout(tableConfigBox);
    m_titleTable = new QLabel(tableConfigBox);
    tableGrid->addWidget(m_titleTable, 0, 0, 1, 2);

    m_labelTableToolPath = new QLabel(tableConfigBox);
    tableGrid->addWidget(m_labelTableToolPath, 1, 0);
    m_tableToolPathEdit = new QLineEdit(blessToolPath(), tableConfigBox);
    tableGrid->addWidget(m_tableToolPathEdit, 1, 1);

    m_labelTableToken = new QLabel(tableConfigBox);
    tableGrid->addWidget(m_labelTableToken, 2, 0);
    m_tableTokenEdit = new QLineEdit(tableConfigBox);
    m_tableTokenEdit->setEchoMode(QLineEdit::Password);
    tableGrid->addWidget(m_tableTokenEdit, 2, 1);

    m_labelTableInterval = new QLabel(tableConfigBox);
    tableGrid->addWidget(m_labelTableInterval, 3, 0);
    m_tableIntervalCombo = new QComboBox(tableConfigBox);
    m_tableIntervalCombo->addItem("100 ms", 100);
    m_tableIntervalCombo->addItem("250 ms", 250);
    m_tableIntervalCombo->addItem("500 ms", 500);
    m_tableIntervalCombo->addItem("1000 ms", 1000);
    m_tableIntervalCombo->setCurrentIndex(3);
    tableGrid->addWidget(m_tableIntervalCombo, 3, 1);

    auto *tableButtons = new QHBoxLayout();
    m_btnTableRefresh = new QPushButton(tablePage);
    m_btnTableClear = new QPushButton(tablePage);
    tableButtons->addWidget(m_btnTableRefresh);
    tableButtons->addWidget(m_btnTableClear);

    m_guardTable = new QTableWidget(tablePage);
    m_guardTable->setColumnCount(8);
    m_guardTable->setHorizontalHeaderLabels(QStringList{
        "PID", "Path", "Hash", "Restarts", "Max", "Alive", "Session", "HashVerified"});
    m_guardTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_guardTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_guardTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_guardTable->horizontalHeader()->setStretchLastSection(true);

    tableLayout->addWidget(tableConfigBox);
    tableLayout->addLayout(tableButtons);
    tableLayout->addWidget(m_guardTable, 1);

    m_tabs->addTab(tablePage, "");

    // Module management tab (4th tab).
    auto *modulePage = new QWidget(m_tabs);
    setupModuleTab(modulePage);
    m_tabs->addTab(modulePage, "");
    rootLayout->addWidget(m_tabs);

    setCentralWidget(central);
    resize(1080, 760);

    connect(m_languageCombo, &QComboBox::currentIndexChanged, this, [this](int) {
        applyLanguage();
    });

    connect(m_themeCombo, &QComboBox::currentIndexChanged, this, [this](int idx) {
        applyTheme(idx);
        QSettings settings("OpenStarlight", "PGSAdminQt");
        settings.setValue("theme", idx);
    });
    connect(m_toolPathEdit, &QLineEdit::editingFinished, this, [this]() {
        QSettings settings("OpenStarlight", "PGSAdminQt");
        settings.setValue("blessToolPath", m_toolPathEdit->text().trimmed());
    });
    connect(m_servicePathEdit, &QLineEdit::editingFinished, this, [this]() {
        QSettings settings("OpenStarlight", "PGSAdminQt");
        settings.setValue("serviceToolPath", m_servicePathEdit->text().trimmed());
    });
    connect(m_tableToolPathEdit, &QLineEdit::editingFinished, this, [this]() {
        QSettings settings("OpenStarlight", "PGSAdminQt");
        settings.setValue("tableToolPath", m_tableToolPathEdit->text().trimmed());
    });

    connect(m_btnPing, &QPushButton::clicked, this, [this]() {
        runBlessCommand({"ping"});
    });
    connect(m_btnList, &QPushButton::clicked, this, [this]() {
        QStringList args{"list"};
        if (m_jsonCheck->isChecked())
        {
            args << "--json";
        }
        runBlessCommand(args);
    });
    connect(m_btnGet, &QPushButton::clicked, this, [this]() {
        if (pidArg().isEmpty())
        {
            appendBlessOutput(trUi("PID is required for get", "get 操作需要 PID"));
            return;
        }
        QStringList args{"get", "--pid", pidArg()};
        if (m_jsonCheck->isChecked())
        {
            args << "--json";
        }
        runBlessCommand(args);
    });
    connect(m_btnBless, &QPushButton::clicked, this, [this]() {
        if (pidArg().isEmpty())
        {
            appendBlessOutput(trUi("PID is required for bless", "bless 操作需要 PID"));
            return;
        }
        QStringList args{"bless", "--pid", pidArg(), "--hash", "auto"};
        const QString max = m_maxRestartsEdit->text().trimmed();
        if (!max.isEmpty())
        {
            args << "--max-restarts" << max;
        }
        const QString restartArgs = m_restartArgsEdit->text().trimmed();
        if (!restartArgs.isEmpty())
        {
            args << "--restart-args" << restartArgs;
        }
        runBlessCommand(args);
    });
    connect(m_btnBlessStart, &QPushButton::clicked, this, [this]() {
        const QString path = m_launchPathEdit->text().trimmed();
        const QString commandLine = m_launchCommandEdit->text().trimmed();
        if (path.isEmpty() && commandLine.isEmpty())
        {
            appendBlessOutput(trUi("Path or command is required for bless-start", "bless-start 操作需要路径或命令"));
            return;
        }
        QStringList args{"bless-start", "--hash", "auto"};
        if (!commandLine.isEmpty())
        {
            args << "--command" << commandLine;
        }
        else
        {
            args << "--path" << path;
        }
        const QString startArgs = m_launchArgsEdit->text().trimmed();
        if (!startArgs.isEmpty() && commandLine.isEmpty())
        {
            args << "--start-args" << startArgs;
        }
        const QString max = m_maxRestartsEdit->text().trimmed();
        if (!max.isEmpty())
        {
            args << "--max-restarts" << max;
        }
        const QString restartArgs = m_restartArgsEdit->text().trimmed();
        if (!restartArgs.isEmpty())
        {
            args << "--restart-args" << restartArgs;
        }
        runBlessCommand(args);
    });
    connect(m_btnUnbless, &QPushButton::clicked, this, [this]() {
        if (!m_launchPathEdit->text().trimmed().isEmpty())
        {
            runBlessCommand({"unbless-path", "--path", m_launchPathEdit->text().trimmed()});
            return;
        }
        if (pidArg().isEmpty())
        {
            appendBlessOutput(trUi("PID is required for unbless", "unbless 操作需要 PID"));
            return;
        }
        runBlessCommand({"unbless", "--pid", pidArg()});
    });
    connect(m_btnPolicy, &QPushButton::clicked, this, [this]() {
        if (pidArg().isEmpty())
        {
            appendBlessOutput(trUi("PID is required for policy", "policy 操作需要 PID"));
            return;
        }
        const QString max = m_maxRestartsEdit->text().trimmed();
        if (max.isEmpty())
        {
            appendBlessOutput(trUi("--max-restarts is required for policy", "policy 操作需要 --max-restarts"));
            return;
        }
        QStringList args{"policy", "--pid", pidArg(), "--max-restarts", max};
        const QString restartArgs = m_restartArgsEdit->text().trimmed();
        if (!restartArgs.isEmpty())
        {
            args << "--restart-args" << restartArgs;
        }
        runBlessCommand(args);
    });
    connect(m_btnIntentional, &QPushButton::clicked, this, [this]() {
        if (pidArg().isEmpty())
        {
            appendBlessOutput(trUi("PID is required for intentional", "intentional 操作需要 PID"));
            return;
        }
        runBlessCommand({"intentional", "--pid", pidArg()});
    });
    connect(m_btnTokenSet, &QPushButton::clicked, this, [this]() {
        const QString nextToken = m_newTokenEdit->text();
        runBlessCommand({"token-set", "--new-token", nextToken});
    });
    connect(m_btnClear, &QPushButton::clicked, this, [this]() {
        m_blessOutput->clear();
    });

    connect(m_btnServiceInstall, &QPushButton::clicked, this, [this]() {
        runServiceCommand({"install"});
    });
    connect(m_btnServiceStatus, &QPushButton::clicked, this, [this]() {
        runServiceCommand({"status"});
    });
    connect(m_btnServiceStart, &QPushButton::clicked, this, [this]() {
        runServiceCommand({"start"});
    });
    connect(m_btnServiceStop, &QPushButton::clicked, this, [this]() {
        runServiceCommand({"stop"});
    });
    connect(m_btnServiceUninstall, &QPushButton::clicked, this, [this]() {
        runServiceCommand({"uninstall"});
    });
    connect(m_btnServiceRun, &QPushButton::clicked, this, [this]() {
        QStringList args{"run"};
        runServiceCommand(args);
    });
    connect(m_btnServiceRunStop, &QPushButton::clicked, this, [this]() {
        if (m_serviceProcess->state() == QProcess::NotRunning)
        {
            appendServiceOutput(trUi("console mode is not running", "控制台运行未启动"));
            return;
        }
        if (!m_serviceRunModeActive)
        {
            appendServiceOutput(trUi("current service command is not run mode", "当前服务命令不是 run 模式"));
            return;
        }
        if (m_serviceStopPending)
        {
            appendServiceOutput(trUi("stop is already in progress", "停止操作正在进行"));
            return;
        }
        m_serviceStopPending = true;
        appendServiceOutput(trUi("stopping run mode process...", "正在停止 run 模式进程..."));
        m_serviceProcess->terminate();
        QTimer::singleShot(1500, this, [this]() {
            if (!m_serviceStopPending)
            {
                return;
            }
            if (m_serviceProcess->state() == QProcess::NotRunning)
            {
                m_serviceStopPending = false;
                return;
            }
            appendServiceOutput(trUi("terminate timeout, forcing kill...", "terminate 超时，执行强制结束..."));
            m_serviceProcess->kill();
        });
    });
    connect(m_btnServiceReset, &QPushButton::clicked, this, [this]() {
        startServiceResetSequence();
    });
    connect(m_btnServiceClear, &QPushButton::clicked, this, [this]() {
        m_serviceOutput->clear();
    });
    connect(m_btnTableRefresh, &QPushButton::clicked, this, [this]() {
        runTableRefresh(false);
    });
    connect(m_btnTableClear, &QPushButton::clicked, this, [this]() {
        m_guardTable->setRowCount(0);
        m_guardTableColumnsSized = false;
    });
    m_tableRefreshTimer = new QTimer(this);
    m_tableRefreshTimer->setInterval(m_tableIntervalCombo->currentData().toInt());
    connect(m_tableRefreshTimer, &QTimer::timeout, this, [this]() {
        if (m_tabs->currentIndex() == 2)
        {
            runTableRefresh(true);
        }
    });
    m_tableRefreshTimer->start();
    connect(m_tableIntervalCombo, &QComboBox::currentIndexChanged, this, [this](int) {
        const int ms = m_tableIntervalCombo->currentData().toInt();
        if (ms > 0)
        {
            m_tableRefreshTimer->setInterval(ms);
            QSettings settings("OpenStarlight", "PGSAdminQt");
            settings.setValue("tableRefreshIntervalMs", ms);
        }
    });

    applyLanguage();
    statusBar()->showMessage(trUi("ready", "就绪"), 2000);
    refreshModuleTabs();
}

QString MainWindow::blessToolPath() const
{
    const QString appDir = QCoreApplication::applicationDirPath();
    QString candidate = QDir(appDir).filePath("../pgs_bless.exe");
    if (QFileInfo::exists(candidate))
    {
        return QDir::cleanPath(candidate);
    }
    candidate = QDir(appDir).filePath("pgs_bless.exe");
    if (QFileInfo::exists(candidate))
    {
        return QDir::cleanPath(candidate);
    }
    return QStringLiteral("pgs_bless.exe");
}

QString MainWindow::serviceToolPath() const
{
    const QString appDir = QCoreApplication::applicationDirPath();
    QString candidate = QDir(appDir).filePath("../pgs_service.exe");
    if (QFileInfo::exists(candidate))
    {
        return QDir::cleanPath(candidate);
    }
    candidate = QDir(appDir).filePath("pgs_service.exe");
    if (QFileInfo::exists(candidate))
    {
        return QDir::cleanPath(candidate);
    }
    return QStringLiteral("pgs_service.exe");
}

QString MainWindow::pidArg() const
{
    return m_pidEdit->text().trimmed();
}

bool MainWindow::isChineseUi() const
{
    return m_languageCombo && m_languageCombo->currentIndex() == 0;
}

QString MainWindow::trUi(const QString &en, const QString &zh) const
{
    return isChineseUi() ? zh : en;
}

void MainWindow::applyTheme(int index)
{
    // 0 = light, 1 = dark. Apply a bundled QSS via qApp so all widgets,
    // including ModulePage sub-tabs, restyle consistently.
    const QString res = (index == 1) ? QStringLiteral(":/dark.qss") : QStringLiteral(":/light.qss");
    QFile f(res);
    if (f.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        static_cast<QApplication *>(QCoreApplication::instance())->setStyleSheet(QString::fromUtf8(f.readAll()));
    }
    else
    {
        static_cast<QApplication *>(QCoreApplication::instance())->setStyleSheet(QString());
    }
}

void MainWindow::loadSavedPrefs()
{
    QSettings settings("OpenStarlight", "PGSAdminQt");
    const int theme = settings.value("theme", 0).toInt();
    const int lang = settings.value("language", 0).toInt();
    const QString blessTool = settings.value("blessToolPath").toString().trimmed();
    const QString serviceTool = settings.value("serviceToolPath").toString().trimmed();
    const QString tableTool = settings.value("tableToolPath").toString().trimmed();
    const QString moduleTool = settings.value("moduleToolPath").toString().trimmed();
    const QString moduleDir = settings.value("moduleDir").toString().trimmed();
    const int tableIntervalMs = settings.value("tableRefreshIntervalMs", 1000).toInt();
    if (m_themeCombo)
    {
        m_themeCombo->blockSignals(true);
        m_themeCombo->setCurrentIndex(theme == 1 ? 1 : 0);
        m_themeCombo->blockSignals(false);
        applyTheme(m_themeCombo->currentIndex());
    }
    if (m_languageCombo)
    {
        m_languageCombo->blockSignals(true);
        m_languageCombo->setCurrentIndex(lang == 1 ? 1 : 0);
        m_languageCombo->blockSignals(false);
        applyLanguage();
    }
    if (m_toolPathEdit && !blessTool.isEmpty())
    {
        m_toolPathEdit->setText(blessTool);
    }
    if (m_servicePathEdit && !serviceTool.isEmpty())
    {
        m_servicePathEdit->setText(serviceTool);
    }
    if (m_tableToolPathEdit && !tableTool.isEmpty())
    {
        m_tableToolPathEdit->setText(tableTool);
    }
    if (m_moduleToolPathEdit)
    {
        const QString savedModuleTool = moduleTool.isEmpty() ? blessTool : moduleTool;
        if (!savedModuleTool.isEmpty())
        {
            m_moduleToolPathEdit->setText(savedModuleTool);
        }
    }
    if (m_moduleDirEdit && !moduleDir.isEmpty())
    {
        m_moduleDirEdit->setText(moduleDir);
    }
    if (m_tableIntervalCombo)
    {
        const int idx = m_tableIntervalCombo->findData(tableIntervalMs);
        if (idx >= 0)
        {
            m_tableIntervalCombo->blockSignals(true);
            m_tableIntervalCombo->setCurrentIndex(idx);
            m_tableIntervalCombo->blockSignals(false);
            if (m_tableRefreshTimer && tableIntervalMs > 0)
            {
                m_tableRefreshTimer->setInterval(tableIntervalMs);
            }
        }
    }
    refreshModuleTabs();
}

void MainWindow::applyLanguage()
{
    setWindowTitle(trUi("PGS Admin (Qt)", "PGS 管理端（Qt）"));
    m_tabs->setTabText(0, trUi("Bless Console", "守护管理"));
    m_tabs->setTabText(1, trUi("Service Console", "服务管理"));
    m_tabs->setTabText(2, trUi("Guard Table", "守护表格"));
    m_tabs->setTabText(3, trUi("Module Management", "模块管理"));
    m_titleModule->setText(trUi("Module Management", "模块管理"));
    m_labelModuleToolPath->setText(trUi("pgs_bless path", "pgs_bless 路径"));
    m_labelModuleToken->setText(trUi("token", "token"));
    m_labelModuleDir->setText(trUi("modules directory", "modules 目录"));
    m_btnModuleRefresh->setText(trUi("Refresh Module List", "刷新模块列表"));
    for (int i = 0; i < m_moduleSubTabs->count(); ++i)
    {
        if (auto *p = qobject_cast<ModulePage *>(m_moduleSubTabs->widget(i)))
            p->setChinese(isChineseUi());
    }

    m_titleConnection->setText(trUi("PGS_Bless Tool", "PGS_Bless 工具"));
    m_titleTarget->setText(trUi("Target", "目标参数"));
    m_titleService->setText(trUi("PGS_Service Tool", "PGS_Service 工具"));
    m_titleTable->setText(trUi("Guard Table Source", "守护表格数据源"));

    m_labelToolPath->setText(trUi("pgs_bless path", "pgs_bless 路径"));
    m_labelToken->setText(trUi("token", "当前 token"));
    m_labelLanguage->setText(trUi("language", "语言"));
    m_labelTheme->setText(trUi("theme", "主题"));
    m_labelNewToken->setText(trUi("new token", "新 token"));
    m_jsonCheck->setText(trUi("json output", "JSON 输出"));
    m_labelPid->setText(trUi("pid", "进程 PID"));
    m_labelLaunchPath->setText(trUi("launch path", "启动路径"));
    m_labelLaunchArgs->setText(trUi("launch args", "启动参数"));
    m_labelLaunchCommand->setText(trUi("launch command", "自定义启动命令"));
    m_labelMaxRestarts->setText(trUi("max restarts", "最大重启次数"));
    m_labelRestartArgs->setText(trUi("restart args", "重启参数"));
    m_labelServicePath->setText(trUi("pgs_service path", "pgs_service 路径"));
    m_labelServiceToken->setText(trUi("run token", "run token"));
    m_labelTableToolPath->setText(trUi("pgs_bless path", "pgs_bless 路径"));
    m_labelTableToken->setText(trUi("token", "token"));
    m_labelTableInterval->setText(trUi("auto refresh", "自动刷新"));

    m_restartArgsEdit->setPlaceholderText(trUi("--mode worker", "--mode worker"));
    m_launchArgsEdit->setPlaceholderText(trUi("--flag value", "--参数 值"));
    m_launchCommandEdit->setPlaceholderText(trUi("\"C:/app.exe\" --arg1 x", "\"C:/程序.exe\" --参数 值"));
    m_newTokenEdit->setPlaceholderText(trUi("new token", "新 token"));
    m_serviceTokenEdit->setPlaceholderText(trUi("used by PGS_SERVICE_TOKEN", "用于 PGS_SERVICE_TOKEN"));

    m_btnPing->setText(trUi("Ping", "探活"));
    m_btnList->setText(trUi("List", "列表"));
    m_btnGet->setText(trUi("Get", "查询"));
    m_btnClear->setText(trUi("Clear Log", "清空日志"));
    m_btnBless->setText(trUi("Bless PID", "按 PID 守护"));
    m_btnBlessStart->setText(trUi("Start + Bless", "路径启动并守护"));
    m_btnUnbless->setText(trUi("Unbless", "取消守护"));
    m_btnPolicy->setText(trUi("Set Policy", "设置策略"));
    m_btnIntentional->setText(trUi("Intentional", "主动退出"));
    m_btnTokenSet->setText(trUi("Set Token", "更新 Token"));

    m_btnServiceInstall->setText(trUi("Install", "安装服务"));
    m_btnServiceStatus->setText(trUi("Status", "查看状态"));
    m_btnServiceStart->setText(trUi("Start", "启动服务"));
    m_btnServiceStop->setText(trUi("Stop", "停止服务"));
    m_btnServiceUninstall->setText(trUi("Uninstall", "卸载服务"));
    m_btnServiceReset->setText(trUi("Reset Service", "重置服务"));
    m_btnServiceRun->setText(trUi("Run Console", "控制台运行"));
    m_btnServiceRunStop->setText(trUi("Stop Console", "停止控制台"));
    m_btnServiceClear->setText(trUi("Clear Log", "清空日志"));
    m_btnTableRefresh->setText(trUi("Refresh", "刷新"));
    m_btnTableClear->setText(trUi("Clear Table", "清空表格"));
    m_guardTable->setHorizontalHeaderLabels(isChineseUi()
                                                ? QStringList{"PID", "路径", "哈希", "已重启", "最大重启", "存活", "会话", "哈希校验"}
                                                : QStringList{"PID", "Path", "Hash", "Restarts", "Max", "Alive", "Session", "HashVerified"});
    QSettings settings("OpenStarlight", "PGSAdminQt");
    settings.setValue("language", isChineseUi() ? 0 : 1);
}

void MainWindow::setupModuleTab(QWidget *page)
{
    auto *layout = new QVBoxLayout(page);

    auto *cfgBox = new QGroupBox(page);
    auto *cfgGrid = new QGridLayout(cfgBox);
    m_titleModule = new QLabel(cfgBox);
    cfgGrid->addWidget(m_titleModule, 0, 0, 1, 2);

    m_labelModuleToolPath = new QLabel(cfgBox);
    cfgGrid->addWidget(m_labelModuleToolPath, 1, 0);
    m_moduleToolPathEdit = new QLineEdit(blessToolPath(), cfgBox);
    cfgGrid->addWidget(m_moduleToolPathEdit, 1, 1);

    m_labelModuleToken = new QLabel(cfgBox);
    cfgGrid->addWidget(m_labelModuleToken, 2, 0);
    m_moduleTokenEdit = new QLineEdit(cfgBox);
    m_moduleTokenEdit->setEchoMode(QLineEdit::Password);
    cfgGrid->addWidget(m_moduleTokenEdit, 2, 1);

    m_labelModuleDir = new QLabel(cfgBox);
    cfgGrid->addWidget(m_labelModuleDir, 3, 0);
    m_moduleDirEdit = new QLineEdit(defaultModuleDir(), cfgBox);
    cfgGrid->addWidget(m_moduleDirEdit, 3, 1);

    m_btnModuleRefresh = new QPushButton(cfgBox);
    cfgGrid->addWidget(m_btnModuleRefresh, 4, 1);

    layout->addWidget(cfgBox);

    m_moduleSubTabs = new QTabWidget(page);
    layout->addWidget(m_moduleSubTabs, 1);

    connect(m_btnModuleRefresh, &QPushButton::clicked, this, [this]() {
        refreshModuleTabs();
    });
    connect(m_moduleTokenEdit, &QLineEdit::textChanged, this, [this](const QString &) {
        syncModulePageSettings();
    });
    connect(m_moduleToolPathEdit, &QLineEdit::textChanged, this, [this](const QString &) {
        syncModulePageSettings();
    });
    connect(m_moduleToolPathEdit, &QLineEdit::editingFinished, this, [this]() {
        QSettings settings("OpenStarlight", "PGSAdminQt");
        settings.setValue("moduleToolPath", m_moduleToolPathEdit->text().trimmed());
    });
    connect(m_moduleDirEdit, &QLineEdit::editingFinished, this, [this]() {
        QSettings settings("OpenStarlight", "PGSAdminQt");
        settings.setValue("moduleDir", m_moduleDirEdit->text().trimmed());
    });
}

QString MainWindow::defaultModuleDir() const
{
    // modules\ lives beside pgs_service.exe at runtime; fall back to beside
    // pgs_bless.exe so the tab is useful in console-only test layouts too.
    QString dir = QFileInfo(serviceToolPath()).absolutePath() + QStringLiteral("/modules");
    if (QDir(dir).exists())
        return QDir::cleanPath(dir);
    dir = QFileInfo(blessToolPath()).absolutePath() + QStringLiteral("/modules");
    return QDir::cleanPath(dir);
}

void MainWindow::refreshModuleTabs()
{
    // Drop existing sub-tabs (this deletes their ModulePage widgets).
    while (m_moduleSubTabs->count() > 0)
    {
        QWidget *w = m_moduleSubTabs->widget(0);
        m_moduleSubTabs->removeTab(0);
        w->deleteLater();
    }

    const QString dir = m_moduleDirEdit->text().trimmed().isEmpty()
                            ? defaultModuleDir()
                            : m_moduleDirEdit->text().trimmed();
    const QString toolPath = m_moduleToolPathEdit->text().trimmed().isEmpty()
                                 ? blessToolPath()
                                 : m_moduleToolPathEdit->text().trimmed();
    const QString token = m_moduleTokenEdit->text();
    const bool zh = isChineseUi();

    const QStringList folders = QDir(dir).entryList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name);
    if (folders.isEmpty())
    {
        auto *ph = new QTextEdit(m_moduleSubTabs);
        ph->setReadOnly(true);
        ph->setPlainText(trUi("No module folders found under:", "未在以下目录发现模块文件夹：") + "\n" + dir);
        m_moduleSubTabs->addTab(ph, trUi("(empty)", "(空)"));
        return;
    }

    for (const QString &folder : folders)
    {
        auto *mp = new ModulePage(folder, dir, toolPath, token, zh, m_moduleSubTabs);
        m_moduleSubTabs->addTab(mp, folder);
    }
}

void MainWindow::syncModulePageSettings()
{
    if (!m_moduleSubTabs)
        return;
    const QString token = m_moduleTokenEdit ? m_moduleTokenEdit->text() : QString();
    QString toolPath = m_moduleToolPathEdit ? m_moduleToolPathEdit->text().trimmed() : QString();
    if (toolPath.isEmpty())
    {
        toolPath = blessToolPath();
    }
    for (int i = 0; i < m_moduleSubTabs->count(); ++i)
    {
        if (auto *page = qobject_cast<ModulePage *>(m_moduleSubTabs->widget(i)))
        {
            page->setToken(token);
            page->setToolPath(toolPath);
        }
    }
}

void MainWindow::runBlessCommand(const QStringList &args)
{
    if (m_blessProcess->state() != QProcess::NotRunning)
    {
        if (!m_blessBusyNoticeShown)
        {
            appendBlessOutput(trUi("previous command still running", "上一个命令仍在执行"));
            m_blessBusyNoticeShown = true;
        }
        return;
    }
    m_blessBusyNoticeShown = false;

    QString program = m_toolPathEdit->text().trimmed();
    if (program.isEmpty())
    {
        program = blessToolPath();
    }
    if (!QFileInfo::exists(program))
    {
        appendBlessOutput(trUi("pgs_bless not found: ", "未找到 pgs_bless：") + program);
        return;
    }

    QStringList finalArgs = args;
    const QString token = m_tokenEdit->text();

    // Pass the auth token via the environment (PGS_AUTH_TOKEN) instead of the
    // command line so it is not visible to other local users.
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    if (!token.isNull() && !token.isEmpty())
    {
        env.insert(QStringLiteral("PGS_AUTH_TOKEN"), token);
    }

    appendBlessOutput(">>> " + program + " " + redactedArgsForLog(finalArgs).join(' '));
    m_blessProcess->setWorkingDirectory(QFileInfo(program).absolutePath());
    m_blessProcess->setProcessEnvironment(env);
    m_blessProcess->start(program, finalArgs);
}

void MainWindow::runServiceCommand(const QStringList &args)
{
    if (m_serviceProcess->state() != QProcess::NotRunning)
    {
        if (!m_serviceBusyNoticeShown)
        {
            appendServiceOutput(trUi("previous command still running", "上一个命令仍在执行"));
            m_serviceBusyNoticeShown = true;
        }
        return;
    }
    m_serviceBusyNoticeShown = false;

    QString program = m_servicePathEdit->text().trimmed();
    if (program.isEmpty())
    {
        program = serviceToolPath();
    }
    if (!QFileInfo::exists(program))
    {
        appendServiceOutput(trUi("pgs_service not found: ", "未找到 pgs_service：") + program);
        return;
    }

    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    if (!args.isEmpty() && args.first() == "run")
    {
        const QString token = m_serviceTokenEdit->text();
        if (!token.isEmpty())
        {
            env.insert(QStringLiteral("PGS_SERVICE_TOKEN"), token);
        }
    }

    appendServiceOutput(">>> " + program + " " + redactedArgsForLog(args).join(' '));
    m_serviceRunModeActive = (!args.isEmpty() && args.first() == "run");
    m_serviceProcess->setWorkingDirectory(QFileInfo(program).absolutePath());
    m_serviceProcess->setProcessEnvironment(env);
    m_serviceProcess->start(program, args);
}

void MainWindow::startServiceResetSequence()
{
    if (m_serviceProcess->state() != QProcess::NotRunning || m_serviceSequenceRunning)
    {
        appendServiceOutput(trUi("service command still running", "服务命令仍在执行"));
        return;
    }

    m_serviceSequenceCommands.clear();
    m_serviceSequenceCommands << "stop" << "uninstall" << "install" << "start";
    m_serviceSequenceRunning = true;
    appendServiceOutput(trUi("service reset started (stop -> uninstall -> install -> start)",
                             "服务重置开始（停止 -> 卸载 -> 安装 -> 启动）"));
    runNextServiceSequenceStep();
}

void MainWindow::runNextServiceSequenceStep()
{
    if (!m_serviceSequenceRunning)
    {
        return;
    }
    if (m_serviceSequenceCommands.isEmpty())
    {
        m_serviceSequenceRunning = false;
        appendServiceOutput(trUi("service reset completed", "服务重置完成"));
        return;
    }
    const QString nextCommand = m_serviceSequenceCommands.takeFirst();
    runServiceCommand(QStringList{nextCommand});
}

void MainWindow::appendBlessOutput(const QString &text)
{
    const QString stamp = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
    m_blessOutput->append("[" + stamp + "] " + text.trimmed());
}

void MainWindow::appendServiceOutput(const QString &text)
{
    const QString stamp = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
    m_serviceOutput->append("[" + stamp + "] " + text.trimmed());
}

void MainWindow::runTableRefresh(bool silentIfBusy)
{
    if (m_tableProcess->state() != QProcess::NotRunning)
    {
        if (!silentIfBusy)
        {
            statusBar()->showMessage(trUi("guard table refresh already running", "守护表格刷新已在执行"), 3000);
        }
        return;
    }

    QString program = m_tableToolPathEdit->text().trimmed();
    if (program.isEmpty())
    {
        program = blessToolPath();
    }
    if (!QFileInfo::exists(program))
    {
        if (!silentIfBusy)
        {
            statusBar()->showMessage(trUi("pgs_bless not found for table refresh", "表格刷新未找到 pgs_bless"), 5000);
        }
        return;
    }

    QStringList args{"list", "--json"};
    const QString token = m_tableTokenEdit->text();

    // Pass the auth token via the environment instead of the command line.
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    if (!token.isNull() && !token.isEmpty())
    {
        env.insert(QStringLiteral("PGS_AUTH_TOKEN"), token);
    }

    m_lastTableRefreshWasAuto = silentIfBusy;
    m_tableStdoutBuffer.clear();
    m_tableStderrBuffer.clear();
    m_tableProcess->setWorkingDirectory(QFileInfo(program).absolutePath());
    m_tableProcess->setProcessEnvironment(env);
    m_tableProcess->start(program, args);
}

void MainWindow::populateGuardTableFromJson(const QString &jsonText, const QString &stderrText)
{
    QJsonParseError parseError;
    const QJsonDocument doc = QJsonDocument::fromJson(jsonText.toUtf8(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isArray())
    {
        // Preserve the previous table snapshot on transient failures so the UI
        // does not flicker between "valid data" and "empty table" during brief
        // command or parse hiccups.
        QString message = trUi("guard table JSON parse failed", "守护表格 JSON 解析失败");
        const QString detail = stderrText.trimmed();
        if (!detail.isEmpty())
        {
            message += QStringLiteral(": ") + detail.left(240);
        }
        statusBar()->showMessage(message, 5000);
        return;
    }

    const QJsonArray arr = doc.array();
    m_guardTable->setRowCount(arr.size());
    for (int i = 0; i < arr.size(); ++i)
    {
        const QJsonObject obj = arr.at(i).toObject();
        auto setCell = [&](int col, const QString &value, const QColor &color = QColor()) {
            auto *item = new QTableWidgetItem(value);
            if (color.isValid())
                item->setForeground(QBrush(color));
            m_guardTable->setItem(i, col, item);
            return item;
        };
        setCell(0, obj.value("pid").toString());
        setCell(1, obj.value("path").toString());
        setCell(2, obj.value("hash").toString());
        // Restart count: yellow when within 1 of the limit (and limit != no/unlimited).
        const QString restartText = obj.value("restart_count").toString();
        const QString maxText = obj.value("max_restarts").toString();
        QColor restartColor;
        {
            bool rok = false, mok = false;
            int rc = restartText.toInt(&rok);
            int mc = maxText.toInt(&mok);
            if (rok && mok && mc > 0 && rc >= mc - 1)
                restartColor = QColor(0xc8, 0x8a, 0x00); // amber
        }
        setCell(3, restartText, restartColor);
        setCell(4, maxText);
        // Alive status: green=alive, red=dead.
        const QString aliveText = obj.value("alive").toString();
        QColor aliveColor = (aliveText == "1" || aliveText.compare("true", Qt::CaseInsensitive) == 0)
                                ? QColor(0x16, 0x8c, 0x2e) : QColor(0xd4, 0x3a, 0x3a);
        setCell(5, aliveText, aliveColor);
        setCell(6, obj.value("session").toString());
        // Hash verification: orange when failed (hash_verified != 1/true).
        const QString hashText = obj.value("hash_verified").toString();
        QColor hashColor;
        if (hashText != "1" && hashText.compare("true", Qt::CaseInsensitive) != 0)
            hashColor = QColor(0xd9, 0x6a, 0x10); // orange
        setCell(7, hashText, hashColor);
    }
    if (!m_guardTableColumnsSized || !m_lastTableRefreshWasAuto)
    {
        // Column auto-sizing is intentionally skipped on steady-state auto
        // refreshes because it is visually noisy and surprisingly expensive for
        // large tables.
        m_guardTable->resizeColumnsToContents();
        m_guardTableColumnsSized = true;
    }
    if (!m_lastTableRefreshWasAuto)
    {
        statusBar()->showMessage(trUi("guard table refreshed", "守护表格已刷新"), 2000);
    }
}
