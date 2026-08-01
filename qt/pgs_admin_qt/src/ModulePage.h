/**
 * @file ModulePage.h
 * @brief One dynamic sub-page of the PGS Admin "Module Management" tab.
 *
 * Created per module folder found under the modules directory. Renders the
 * folder's module.html in a QTextBrowser and exposes generic
 * `module call --name <folder>` plus, for the ppl module, set/get/clear
 * convenience buttons. All commands run through pgs_bless (which talks to the
 * running pgs_service).
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef MODULEPAGE_H
#define MODULEPAGE_H

#include <QWidget>

class QComboBox;
class QCheckBox;
class QGroupBox;
class QLabel;
class QLineEdit;
class QProcess;
class QPushButton;
class QTextBrowser;
class QTextEdit;

class ModulePage : public QWidget
{
    Q_OBJECT
public:
    ModulePage(const QString &folder, const QString &moduleDir,
               const QString &toolPath, const QString &token,
               bool chinese, QWidget *parent = nullptr);

    void setChinese(bool ch);
    void setToolPath(const QString &path);
    void setToken(const QString &token);
    void reloadHtml();

private:
    void setupUi();
    void retranslateUi();
    void runCommand(const QStringList &args);
    void appendOutput(const QString &text);
    QString trUi(const QString &en, const QString &zh) const;
    QString defaultMethod() const;
    QString pidArg() const;
    QString textOf(QLineEdit *edit) const;

    const QString m_folder;
    QString m_moduleDir;
    QString m_toolPath;
    QString m_token;
    bool m_chinese = false;

    QTextBrowser *m_html = nullptr;
    QTextEdit *m_output = nullptr;
    QLineEdit *m_methodEdit = nullptr;
    QLineEdit *m_requestEdit = nullptr;
    QLineEdit *m_pidEdit = nullptr;
    QComboBox *m_signerCombo = nullptr;
    QLabel *m_riskLabel = nullptr;
    QLabel *m_lblPid = nullptr;
    QLabel *m_lblSigner = nullptr;
    QLabel *m_lblMethod = nullptr;
    QLabel *m_lblRequest = nullptr;
    QPushButton *m_btnReload = nullptr;
    QPushButton *m_btnList = nullptr;
    QPushButton *m_btnCall = nullptr;
    QPushButton *m_btnPplSet = nullptr;
    QPushButton *m_btnPplGet = nullptr;
    QPushButton *m_btnPplClear = nullptr;
    QGroupBox *m_pplBox = nullptr;
    QGroupBox *m_schedBox = nullptr;
    QComboBox *m_schedTypeCombo = nullptr;
    QLineEdit *m_schedExprEdit = nullptr;
    QLineEdit *m_schedActionEdit = nullptr;
    QLineEdit *m_schedCountEdit = nullptr;
    QLineEdit *m_schedIdEdit = nullptr;
    QPushButton *m_btnSchedAdd = nullptr;
    QPushButton *m_btnSchedList = nullptr;
    QPushButton *m_btnSchedEnable = nullptr;
    QPushButton *m_btnSchedDisable = nullptr;
    QPushButton *m_btnSchedRemove = nullptr;
    QGroupBox *m_notifyBox = nullptr;
    QCheckBox *m_notifyEventLogCheck = nullptr;
    QCheckBox *m_notifyPopupCheck = nullptr;
    QPushButton *m_btnNotifyStatus = nullptr;
    QPushButton *m_btnNotifyApply = nullptr;
    QGroupBox *m_reportBox = nullptr;
    QLineEdit *m_reportLimitEdit = nullptr;
    QLineEdit *m_operationIdEdit = nullptr;
    QLineEdit *m_artifactIdEdit = nullptr;
    QLineEdit *m_artifactOutEdit = nullptr;
    QCheckBox *m_reportArtifactCheck = nullptr;
    QPushButton *m_btnReportSnapshot = nullptr;
    QPushButton *m_btnReportBackup = nullptr;
    QPushButton *m_btnOperationStatus = nullptr;
    QPushButton *m_btnArtifactMeta = nullptr;
    QPushButton *m_btnArtifactDownload = nullptr;
    QLineEdit *m_artifactTtlEdit = nullptr;
    QLineEdit *m_artifactMaxBytesEdit = nullptr;
    QLineEdit *m_artifactMaxTotalBytesEdit = nullptr;
    QCheckBox *m_artifactAutoCleanupCheck = nullptr;
    QCheckBox *m_artifactVerifyStatusCheck = nullptr;
    QPushButton *m_btnArtifactStatus = nullptr;
    QPushButton *m_btnArtifactPolicy = nullptr;
    QGroupBox *m_metricsBox = nullptr;
    QPushButton *m_btnMetricsSummary = nullptr;
    QPushButton *m_btnMetricsJson = nullptr;
    QPushButton *m_btnMetricsProm = nullptr;
    QGroupBox *m_backupBox = nullptr;
    QLineEdit *m_backupMaxBytesEdit = nullptr;
    QCheckBox *m_backupArtifactCheck = nullptr;
    QPushButton *m_btnBackupStatus = nullptr;
    QPushButton *m_btnBackupSnapshot = nullptr;
    QGroupBox *m_eventlogBox = nullptr;
    QLineEdit *m_eventlogLimitEdit = nullptr;
    QLineEdit *m_eventlogSourceEdit = nullptr;
    QPushButton *m_btnEventlogStatus = nullptr;
    QPushButton *m_btnEventlogRecent = nullptr;
    QGroupBox *m_shortcutBox = nullptr;
    QLineEdit *m_shortcutPidEdit = nullptr;
    QLineEdit *m_shortcutNameEdit = nullptr;
    QLineEdit *m_shortcutIdEdit = nullptr;
    QLineEdit *m_shortcutPathEdit = nullptr;
    QLineEdit *m_shortcutArgsEdit = nullptr;
    QLineEdit *m_shortcutMaxEdit = nullptr;
    QLineEdit *m_shortcutWindowEdit = nullptr;
    QLineEdit *m_shortcutDelayEdit = nullptr;
    QLineEdit *m_shortcutHangEdit = nullptr;
    QComboBox *m_shortcutTypeCombo = nullptr;
    QComboBox *m_shortcutStateCombo = nullptr;
    QComboBox *m_shortcutActionCombo = nullptr;
    QCheckBox *m_shortcutConfirmCheck = nullptr;
    QCheckBox *m_shortcutEnableCheck = nullptr;
    QCheckBox *m_shortcutBackoffCheck = nullptr;
    QCheckBox *m_shortcutKillCheck = nullptr;
    QPushButton *m_btnShortcutStatus = nullptr;
    QPushButton *m_btnShortcutPrimary = nullptr;
    QPushButton *m_btnShortcutSecondary = nullptr;
    QPushButton *m_btnShortcutTertiary = nullptr;
    QPushButton *m_btnShortcutQuaternary = nullptr;
    QProcess *m_process = nullptr;
};

#endif // MODULEPAGE_H
