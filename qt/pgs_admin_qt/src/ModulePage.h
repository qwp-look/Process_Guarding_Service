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
    QString pidArg() const;

    const QString m_folder;
    QString m_moduleDir;
    QString m_toolPath;
    QString m_token;
    bool m_chinese = false;

    QTextBrowser *m_html = nullptr;
    QTextEdit *m_output = nullptr;
    QLineEdit *m_requestEdit = nullptr;
    QLineEdit *m_pidEdit = nullptr;
    QComboBox *m_signerCombo = nullptr;
    QLabel *m_lblPid = nullptr;
    QLabel *m_lblSigner = nullptr;
    QLabel *m_lblRequest = nullptr;
    QPushButton *m_btnReload = nullptr;
    QPushButton *m_btnList = nullptr;
    QPushButton *m_btnCall = nullptr;
    QPushButton *m_btnPplSet = nullptr;
    QPushButton *m_btnPplGet = nullptr;
    QPushButton *m_btnPplClear = nullptr;
    QGroupBox *m_pplBox = nullptr;
    QProcess *m_process = nullptr;
};

#endif // MODULEPAGE_H