#pragma once

#include <QDialog>
#include <QString>
#include <QStringList>

class QTextBrowser;
class QLineEdit;
class QPushButton;
class QThread;

class TaskChatDialog : public QDialog
{
    Q_OBJECT

public:
    explicit TaskChatDialog(const QString &taskId, const QString &taskName,
                            const QStringList &targets, QWidget *parent = nullptr);
    ~TaskChatDialog();

private slots:
    void onSend();
    void onStop();
    void onResult(const QString &reply, int rc);

protected:
    void closeEvent(QCloseEvent *event) override;

private:
    void setupUi();
    void loadSettings();
    void loadHistory();
    void saveHistory();
    void appendMessage(const QString &role, const QString &text);
    void appendHtml(const QString &html);
    QString buildSystemPrompt() const;
    QString historyFilePath() const;

    QString m_taskId;
    QString m_taskName;
    QStringList m_targets;

    QString m_apiKey;
    QString m_provider;
    QString m_endpoint;
    QString m_model;

    QTextBrowser *m_chat = nullptr;
    QLineEdit *m_input = nullptr;
    QPushButton *m_btnSend = nullptr;
    QPushButton *m_btnClose = nullptr;

    QThread *m_thread = nullptr;
    bool m_running = false;
    bool m_aborted = false;
    QString m_historyBuffer;
};
