#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStringList>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QProcess;
class QPushButton;
class QTabWidget;
class QTextEdit;
class QTableWidget;
class QTimer;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override = default;

private:
    void runBlessCommand(const QStringList &args);
    void runServiceCommand(const QStringList &args);
    void startServiceResetSequence();
    void runNextServiceSequenceStep();
    QString blessToolPath() const;
    QString serviceToolPath() const;
    void appendBlessOutput(const QString &text);
    void appendServiceOutput(const QString &text);
    void runTableRefresh(bool silentIfBusy = false);
    void populateGuardTableFromJson(const QString &jsonText);
    void setupUi();
    QString pidArg() const;
    bool isChineseUi() const;
    QString trUi(const QString &en, const QString &zh) const;
    void applyLanguage();
    void attachProcessHandlers();

    QTabWidget *m_tabs = nullptr;

    // bless tab
    QLineEdit *m_toolPathEdit = nullptr;
    QLineEdit *m_pidEdit = nullptr;
    QLineEdit *m_launchPathEdit = nullptr;
    QLineEdit *m_launchArgsEdit = nullptr;
    QLineEdit *m_launchCommandEdit = nullptr;
    QLineEdit *m_maxRestartsEdit = nullptr;
    QLineEdit *m_restartArgsEdit = nullptr;
    QLineEdit *m_tokenEdit = nullptr;
    QLineEdit *m_newTokenEdit = nullptr;

    // service tab
    QLineEdit *m_servicePathEdit = nullptr;
    QLineEdit *m_serviceTokenEdit = nullptr;
    QLineEdit *m_tableToolPathEdit = nullptr;
    QLineEdit *m_tableTokenEdit = nullptr;
    QComboBox *m_tableIntervalCombo = nullptr;

    QComboBox *m_languageCombo = nullptr;
    QCheckBox *m_jsonCheck = nullptr;
    QTextEdit *m_blessOutput = nullptr;
    QTextEdit *m_serviceOutput = nullptr;
    QTableWidget *m_guardTable = nullptr;
    QProcess *m_blessProcess = nullptr;
    QProcess *m_serviceProcess = nullptr;
    QProcess *m_tableProcess = nullptr;

    QStringList m_serviceSequenceCommands;
    bool m_serviceSequenceRunning = false;

    QLabel *m_titleConnection = nullptr;
    QLabel *m_titleTarget = nullptr;
    QLabel *m_titleService = nullptr;
    QLabel *m_labelToolPath = nullptr;
    QLabel *m_labelToken = nullptr;
    QLabel *m_labelLanguage = nullptr;
    QLabel *m_labelNewToken = nullptr;
    QLabel *m_labelServicePath = nullptr;
    QLabel *m_labelServiceToken = nullptr;
    QLabel *m_titleTable = nullptr;
    QLabel *m_labelTableToolPath = nullptr;
    QLabel *m_labelTableToken = nullptr;
    QLabel *m_labelTableInterval = nullptr;
    QLabel *m_labelPid = nullptr;
    QLabel *m_labelLaunchPath = nullptr;
    QLabel *m_labelLaunchArgs = nullptr;
    QLabel *m_labelLaunchCommand = nullptr;
    QLabel *m_labelMaxRestarts = nullptr;
    QLabel *m_labelRestartArgs = nullptr;
    QPushButton *m_btnPing = nullptr;
    QPushButton *m_btnList = nullptr;
    QPushButton *m_btnGet = nullptr;
    QPushButton *m_btnClear = nullptr;
    QPushButton *m_btnBless = nullptr;
    QPushButton *m_btnBlessStart = nullptr;
    QPushButton *m_btnUnbless = nullptr;
    QPushButton *m_btnPolicy = nullptr;
    QPushButton *m_btnIntentional = nullptr;
    QPushButton *m_btnTokenSet = nullptr;
    QPushButton *m_btnServiceInstall = nullptr;
    QPushButton *m_btnServiceStatus = nullptr;
    QPushButton *m_btnServiceStart = nullptr;
    QPushButton *m_btnServiceStop = nullptr;
    QPushButton *m_btnServiceUninstall = nullptr;
    QPushButton *m_btnServiceReset = nullptr;
    QPushButton *m_btnServiceRun = nullptr;
    QPushButton *m_btnServiceRunStop = nullptr;
    QPushButton *m_btnServiceClear = nullptr;
    QPushButton *m_btnTableRefresh = nullptr;
    QPushButton *m_btnTableClear = nullptr;

    bool m_blessBusyNoticeShown = false;
    bool m_serviceBusyNoticeShown = false;
    bool m_serviceRunModeActive = false;
    bool m_serviceStopPending = false;
    bool m_guardTableColumnsSized = false;
    bool m_lastTableRefreshWasAuto = false;
    QString m_tableStdoutBuffer;
    QTimer *m_tableRefreshTimer = nullptr;
};

#endif // MAINWINDOW_H
