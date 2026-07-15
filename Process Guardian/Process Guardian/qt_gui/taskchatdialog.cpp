#include "taskchatdialog.h"
#include "mainwindow.h"
#include "aiworker.h"
#include "chatstyle.h"
extern "C" {
#include "ai_service.h"
}
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTextBrowser>
#include <QLineEdit>
#include <QPushButton>
#include <QThread>
#include <QFile>
#include <QTextStream>
#include <QDir>
#include <QCloseEvent>
#include <QRegularExpression>
#include <QScrollBar>
#include <QLabel>
#include <QFrame>
#include <windows.h>

static QString moduleDir()
{
    wchar_t buf[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, buf, MAX_PATH);
    QString path = QString::fromWCharArray(buf);
    int idx = path.lastIndexOf('\\');
    return idx >= 0 ? path.left(idx) : QDir::currentPath();
}

TaskChatDialog::TaskChatDialog(const QString &taskId, const QString &taskName,
                               const QStringList &targets, QWidget *parent)
    : QDialog(parent), m_taskId(taskId), m_taskName(taskName), m_targets(targets)
{
    setupUi();
    loadSettings();
    loadHistory();
    setWindowTitle(tr("Task AI: %1").arg(taskName));
    resize(700, 500);
}

TaskChatDialog::~TaskChatDialog()
{
    if (m_thread && m_thread->isRunning()) {
        m_thread->quit();
        m_thread->wait(2000);
    }
}

void TaskChatDialog::setupUi()
{
    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    this->setStyleSheet("background: #1c1c1e;");

    /* Header */
    QHBoxLayout *headerLayout = new QHBoxLayout();
    headerLayout->setContentsMargins(16, 12, 16, 12);
    QLabel *title = new QLabel(tr("Task AI: %1").arg(m_taskName), this);
    QFont tf = title->font();
    tf.setPointSize(12);
    tf.setBold(true);
    title->setFont(tf);
    title->setStyleSheet("color: #f2f2f7;");
    headerLayout->addWidget(title);
    headerLayout->addStretch();
    m_btnClose = new QPushButton(tr("Close"), this);
    m_btnClose->setStyleSheet(
        "QPushButton { background: transparent; color: #0a84ff; border: 1px solid #0a84ff; "
        "border-radius: 6px; padding: 4px 14px; }"
        "QPushButton:hover { background: #0a84ff; color: white; }");
    headerLayout->addWidget(m_btnClose);
    layout->addLayout(headerLayout);

    QFrame *sep = new QFrame(this);
    sep->setFrameShape(QFrame::HLine);
    sep->setStyleSheet("color: #3a3a3c;");
    layout->addWidget(sep);

    /* Info bar */
    QLabel *info = new QLabel(tr("Targets: %1").arg(m_targets.isEmpty() ? tr("none") : m_targets.join(", ")), this);
    info->setStyleSheet("color: #8e8e93; font-size: 12px; padding: 6px 16px; background: #2c2c2e;");
    layout->addWidget(info);

    /* Chat */
    m_chat = new QTextBrowser(this);
    m_chat->setOpenExternalLinks(true);
    m_chat->setStyleSheet("QTextBrowser { border: none; background: #1c1c1e; }");
    m_chat->setHtml(ChatStyle::pageHeader() + "</body></html>");
    layout->addWidget(m_chat, 1);

    /* Input */
    QWidget *inputPanel = new QWidget(this);
    inputPanel->setStyleSheet("background: #2c2c2e; border-top: 1px solid #3a3a3c;");
    QHBoxLayout *inputLayout = new QHBoxLayout(inputPanel);
    inputLayout->setContentsMargins(16, 12, 16, 12);
    inputLayout->setSpacing(10);

    m_input = new QLineEdit(this);
    m_input->setPlaceholderText(tr("Ask about %1...").arg(m_taskName));
    m_input->setStyleSheet(
        "QLineEdit { border: 1px solid #48484a; border-radius: 20px; padding: 8px 16px; "
        "background: #3a3a3c; color: #f2f2f7; font-size: 14px; }"
        "QLineEdit:focus { border: 1px solid #0a84ff; background: #48484a; }");
    m_input->setMinimumHeight(36);

    m_btnSend = new QPushButton(this);
    m_btnSend->setText(tr("Send"));
    m_btnSend->setCursor(Qt::PointingHandCursor);
    m_btnSend->setStyleSheet(
        "QPushButton { background: #0a84ff; color: white; border: none; "
        "border-radius: 20px; padding: 8px 22px; font-weight: bold; font-size: 14px; }"
        "QPushButton:hover { background: #0066d4; }"
        "QPushButton:disabled { background: #48484a; color: #8e8e93; }");
    m_btnSend->setMinimumHeight(36);

    inputLayout->addWidget(m_input, 1);
    inputLayout->addWidget(m_btnSend);
    layout->addWidget(inputPanel);

    connect(m_btnSend, &QPushButton::clicked, this, &TaskChatDialog::onSend);
    connect(m_btnClose, &QPushButton::clicked, this, &QDialog::reject);
    connect(m_input, &QLineEdit::returnPressed, this, &TaskChatDialog::onSend);
}

void TaskChatDialog::loadSettings()
{
    QString path = QDir(moduleDir()).filePath("data/ai_config.txt");
    QFile f(path);
    m_provider = "api.siliconflow.cn";
    m_endpoint = "/v1/chat/completions";
    m_model = "qwen-plus";
    if (f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream in(&f);
        in.setEncoding(QStringConverter::Utf8);
        while (!in.atEnd()) {
            QString line = in.readLine().trimmed();
            if (line.isEmpty() || line.startsWith('#')) continue;
            int eq = line.indexOf('=');
            if (eq < 0) continue;
            QString k = line.left(eq).trimmed().toLower();
            QString v = line.mid(eq + 1).trimmed();
            if (k == "provider") m_provider = v;
            else if (k == "endpoint") m_endpoint = v;
            else if (k == "model") m_model = v;
            else if (k == "api_key") m_apiKey = v;
        }
    }
}

QString TaskChatDialog::historyFilePath() const
{
    return QDir(moduleDir()).filePath(QString("data/ai_memory/task_%1.log").arg(m_taskId));
}

void TaskChatDialog::loadHistory()
{
    QFile f(historyFilePath());
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return;
    QTextStream in(&f);
    in.setEncoding(QStringConverter::Utf8);
    while (!in.atEnd()) {
        QString line = in.readLine();
        if (line.startsWith("[USER] ")) {
            appendMessage("User", line.mid(7));
        } else if (line.startsWith("[AI] ")) {
            appendMessage("AI", line.mid(5));
        }
    }
}

void TaskChatDialog::saveHistory()
{
    QString dir = QDir(moduleDir()).filePath("data/ai_memory");
    QDir().mkpath(dir);
    QFile f(historyFilePath());
    if (!f.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) return;
    QTextStream out(&f);
    out.setEncoding(QStringConverter::Utf8);
    out << m_historyBuffer;
    m_historyBuffer.clear();
}

QString TaskChatDialog::buildSystemPrompt() const
{
    QString prompt = "You are a task-specific security analyst for Process Guardian. "
                     "You only monitor and answer questions about the following target processes:\n";
    for (const QString &t : m_targets) prompt += "- " + t + "\n";
    prompt += "\nKeep answers focused on these targets. Do not discuss unrelated processes. "
              "If the user asks about threats, analyze based on the task targets only.";
    return prompt;
}

void TaskChatDialog::appendMessage(const QString &role, const QString &text)
{
    appendHtml(ChatStyle::formatMessage(role, text));
}

void TaskChatDialog::appendHtml(const QString &html)
{
    QString body = m_chat->toHtml();
    body.replace("</body></html>", html + "</body></html>");
    m_chat->setHtml(body);
    QScrollBar *sb = m_chat->verticalScrollBar();
    sb->setValue(sb->maximum());
}

void TaskChatDialog::onSend()
{
    QString userText = m_input->text().trimmed();
    if (userText.isEmpty() || m_running) return;

    appendMessage("User", userText);
    m_input->clear();
    m_running = true;
    m_aborted = false;
    m_btnSend->setText(tr("Stop"));
    disconnect(m_btnSend, &QPushButton::clicked, this, &TaskChatDialog::onSend);
    connect(m_btnSend, &QPushButton::clicked, this, &TaskChatDialog::onStop);

    m_historyBuffer += "[USER] " + userText + "\n";

    QString systemPrompt = buildSystemPrompt();
    QString userPrompt = "User: " + userText + "\nAssistant:";

    m_thread = new QThread(this);
    AiWorker *worker = new AiWorker(systemPrompt, userPrompt, m_apiKey, m_provider, m_endpoint, m_model, false,
                                     8192, 4096, 0.7f);
    worker->moveToThread(m_thread);
    connect(m_thread, &QThread::started, worker, &AiWorker::process);
    connect(worker, &AiWorker::resultReady, this, &TaskChatDialog::onResult);
    connect(worker, &AiWorker::resultReady, m_thread, &QThread::quit);
    connect(worker, &AiWorker::resultReady, worker, &AiWorker::deleteLater);
    connect(m_thread, &QThread::finished, m_thread, &QThread::deleteLater);
    m_thread->start();
}

void TaskChatDialog::onStop()
{
    if (!m_running) return;
    m_aborted = true;
    appendHtml(ChatStyle::formatSystem(tr("Stopping... (current request will be ignored when it completes)")));
}

void TaskChatDialog::onResult(const QString &reply, int rc)
{
    m_running = false;
    m_btnSend->setText(tr("Send"));
    disconnect(m_btnSend, &QPushButton::clicked, this, &TaskChatDialog::onStop);
    connect(m_btnSend, &QPushButton::clicked, this, &TaskChatDialog::onSend);

    if (m_aborted) {
        m_aborted = false;
        return;
    }

    if (rc > 0 && !reply.isEmpty()) {
        appendMessage("AI", reply);
        m_historyBuffer += "[AI] " + reply + "\n";
        saveHistory();
    } else {
        appendHtml(ChatStyle::formatSystem(tr("Failed (code %1): %2").arg(rc).arg(reply)));
    }
}

void TaskChatDialog::closeEvent(QCloseEvent *event)
{
    saveHistory();
    event->accept();
}
