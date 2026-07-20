#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStringList>

class QCheckBox;
class QComboBox;
class QLabel;
class QGroupBox;
class QLineEdit;
class QProcess;
class QPushButton;
class QTabWidget;
class QSettings;
class QTextEdit;
class QTableWidget;
class QTimer;

class ModulePage;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override = default;

private:
    void runBlessCommand(const QStringList &args);
    void runServiceCommand(const QStringList &args);
    void runDoctorCommand(const QStringList &args, bool parseJson);
    void runGuardTableAction(const QString &action);
    void runHealthCheckAction(const QString &action);
    void startServiceResetSequence();
    void runNextServiceSequenceStep();
    QString blessToolPath() const;
    QString serviceToolPath() const;
    void appendBlessOutput(const QString &text);
    void appendServiceOutput(const QString &text);
    void appendDoctorOutput(const QString &text);
    void runTableRefresh(bool silentIfBusy = false);
    void populateGuardTableFromJson(const QString &jsonText, const QString &stderrText);
    void populateDoctorTableFromJson(const QString &jsonText, const QString &stderrText);
    QString selectedGuardId() const;
    QString selectedGuardPid() const;
    void setupUi();
    QString pidArg() const;
    void appendAdvancedGuardArgs(QStringList &args) const;
    bool isChineseUi() const;
    QString trUi(const QString &en, const QString &zh) const;
    void applyLanguage();
    void applyTheme(int index);
    void loadSavedPrefs();
    void attachProcessHandlers();
    void setupModuleTab(QWidget *page);
    void refreshModuleTabs();
    void syncModulePageSettings();
    QString defaultModuleDir() const;

    QTabWidget *m_tabs = nullptr;

    // bless tab
    QLineEdit *m_toolPathEdit = nullptr;
    QLineEdit *m_pidEdit = nullptr;
    QLineEdit *m_launchPathEdit = nullptr;
    QLineEdit *m_launchArgsEdit = nullptr;
    QLineEdit *m_launchCommandEdit = nullptr;
    QLineEdit *m_maxRestartsEdit = nullptr;
    QLineEdit *m_restartArgsEdit = nullptr;
    QLineEdit *m_restartWindowEdit = nullptr;
    QLineEdit *m_restartDelayEdit = nullptr;
    QLineEdit *m_hangTimeoutEdit = nullptr;
    QLineEdit *m_aumidEdit = nullptr;
    QCheckBox *m_restartBackoffCheck = nullptr;
    QCheckBox *m_killOnExitCheck = nullptr;
    QCheckBox *m_winappCheck = nullptr;
    QLineEdit *m_tokenEdit = nullptr;
    QLineEdit *m_newTokenEdit = nullptr;

    // service tab
    QLineEdit *m_servicePathEdit = nullptr;
    QLineEdit *m_serviceTokenEdit = nullptr;
    QLineEdit *m_tableToolPathEdit = nullptr;
    QLineEdit *m_tableTokenEdit = nullptr;
    QComboBox *m_tableIntervalCombo = nullptr;

    QComboBox *m_languageCombo = nullptr;
    QComboBox *m_themeCombo = nullptr;
    QLabel *m_labelTheme = nullptr;
    QCheckBox *m_jsonCheck = nullptr;
    QTextEdit *m_blessOutput = nullptr;
    QTextEdit *m_serviceOutput = nullptr;
    QTableWidget *m_guardTable = nullptr;
    QTableWidget *m_doctorTable = nullptr;
    QProcess *m_blessProcess = nullptr;
    QProcess *m_serviceProcess = nullptr;
    QProcess *m_tableProcess = nullptr;
    QProcess *m_doctorProcess = nullptr;
    QProcess *m_guardActionProcess = nullptr;

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
    QLabel *m_labelRestartWindow = nullptr;
    QLabel *m_labelRestartDelay = nullptr;
    QLabel *m_labelHangTimeout = nullptr;
    QLabel *m_labelAumid = nullptr;
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
    QLineEdit *m_guardActionIdEdit = nullptr;
    QLabel *m_labelGuardActionId = nullptr;
    QPushButton *m_btnGuardRetry = nullptr;
    QPushButton *m_btnGuardClearQuarantine = nullptr;
    QGroupBox *m_healthPolicyBox = nullptr;
    QLabel *m_labelHealthPid = nullptr;
    QLineEdit *m_healthPidEdit = nullptr;
    QCheckBox *m_healthEnabledCheck = nullptr;
    QComboBox *m_healthTypeCombo = nullptr;
    QLineEdit *m_healthHostEdit = nullptr;
    QLineEdit *m_healthPortEdit = nullptr;
    QLineEdit *m_healthUrlEdit = nullptr;
    QLineEdit *m_healthIntervalEdit = nullptr;
    QLineEdit *m_healthTimeoutEdit = nullptr;
    QLineEdit *m_healthFailuresEdit = nullptr;
    QComboBox *m_healthActionCombo = nullptr;
    QPushButton *m_btnHealthSet = nullptr;
    QPushButton *m_btnHealthGet = nullptr;
    QPushButton *m_btnHealthClear = nullptr;

    bool m_blessBusyNoticeShown = false;
    bool m_serviceBusyNoticeShown = false;
    bool m_serviceRunModeActive = false;
    bool m_serviceStopPending = false;
    bool m_guardTableColumnsSized = false;
    bool m_lastTableRefreshWasAuto = false;
    QString m_tableStdoutBuffer;
    QString m_tableStderrBuffer;
    QString m_doctorStdoutBuffer;
    QString m_doctorStderrBuffer;
    QString m_guardActionStdoutBuffer;
    QString m_guardActionStderrBuffer;
    bool m_doctorParseJson = false;
    bool m_doctorBusyNoticeShown = false;
    bool m_guardActionBusyNoticeShown = false;
    QTimer *m_tableRefreshTimer = nullptr;

    // module management tab
    QTabWidget *m_moduleSubTabs = nullptr;
    QLineEdit *m_moduleToolPathEdit = nullptr;
    QLineEdit *m_moduleTokenEdit = nullptr;
    QLineEdit *m_moduleDirEdit = nullptr;
    QPushButton *m_btnModuleRefresh = nullptr;
    QLabel *m_titleModule = nullptr;
    QLabel *m_labelModuleToolPath = nullptr;
    QLabel *m_labelModuleToken = nullptr;
    QLabel *m_labelModuleDir = nullptr;

    // doctor tab
    QLineEdit *m_doctorToolPathEdit = nullptr;
    QLineEdit *m_doctorTokenEdit = nullptr;
    QLineEdit *m_doctorModulesDirEdit = nullptr;
    QLabel *m_titleDoctor = nullptr;
    QLabel *m_labelDoctorToolPath = nullptr;
    QLabel *m_labelDoctorToken = nullptr;
    QLabel *m_labelDoctorModulesDir = nullptr;
    QPushButton *m_btnDoctorRun = nullptr;
    QPushButton *m_btnDoctorRepairState = nullptr;
    QPushButton *m_btnDoctorRepairModulesAcl = nullptr;
    QPushButton *m_btnDoctorRepairModulesLock = nullptr;
    QPushButton *m_btnDoctorClear = nullptr;
    QTextEdit *m_doctorOutput = nullptr;
};

#endif // MAINWINDOW_H
