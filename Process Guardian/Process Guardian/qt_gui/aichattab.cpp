#include "aichattab.h"
#include "aiworker.h"
#include "mainwindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QListWidget>
#include <QTextBrowser>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QScrollBar>
#include <QFile>
#include <QDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QSettings>
#include <QMessageBox>
#include <QDesktopServices>
#include <QRegularExpression>
#include <QRegularExpressionMatch>
#include <QRegularExpressionMatchIterator>
#include <QUuid>
#include <QDataStream>
#include <QCoreApplication>
#include <QTimer>
#include <QMetaType>
#include <algorithm>
#include <tlhelp32.h>
#include <windows.h>

static QList<ChatSession> loadChatsFromFile(const QString &path) {
    QList<ChatSession> sessions;
    QFile f(path);
    if (f.open(QIODevice::ReadOnly)) {
        QByteArray data = f.readAll();
        QJsonDocument doc = QJsonDocument::fromJson(data);
        if (doc.isArray()) {
            QJsonArray arr = doc.array();
            for (const QJsonValue &v : arr) {
                QJsonObject o = v.toObject();
                ChatSession s;
                s.id = o.value("id").toString();
                s.title = o.value("title").toString();
                s.createdAt = QDateTime::fromString(o.value("createdAt").toString(), Qt::ISODate);
                QJsonArray msgs = o.value("messages").toArray();
                for (const QJsonValue &mv : msgs) {
                    QJsonObject mo = mv.toObject();
                    ChatMessage m;
                    m.role = mo.value("role").toString();
                    m.text = mo.value("text").toString();
                    s.messages.append(m);
                }
                if (!s.id.isEmpty()) sessions.append(s);
            }
        }
    }
    return sessions;
}

struct ChatLoadData {
    QString path;
    QList<ChatSession> sessions;
    AichatTab *tab;
};

static DWORD WINAPI LoadChatsThread(LPVOID param) {
    ChatLoadData *data = (ChatLoadData*)param;
    data->sessions = loadChatsFromFile(data->path);
    PostMessage((HWND)data->tab->winId(), WM_USER + 100, 0, (LPARAM)data);
    return 0;
}

static QString moduleDir()
{
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    QString qpath = QString::fromWCharArray(path);
    int idx = qpath.lastIndexOf('\\');
    if (idx < 0) idx = qpath.lastIndexOf('/');
    return idx >= 0 ? qpath.left(idx) : qpath;
}

static void guiDebugLog(const QString &msg)
{
    QString path = QDir(moduleDir()).filePath("data/ai_gui_debug.log");
    QDir(QFileInfo(path).path()).mkpath(".");
    QFile f(path);
    if (f.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
        f.write(QString("[%1] %2\n").arg(QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"), msg).toUtf8());
    }
}

static QString sendPipeCommand(const QString &json)
{
    HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\GuardianAIAction",
                               GENERIC_READ | GENERIC_WRITE,
                               0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        return QObject::tr("Failed to connect to daemon action pipe");
    }
    QByteArray data = json.toUtf8();
    DWORD written = 0;
    WriteFile(hPipe, data.constData(), (DWORD)data.size(), &written, NULL);
    FlushFileBuffers(hPipe);
    char resp[4096] = {0};
    DWORD read = 0;
    ReadFile(hPipe, resp, sizeof(resp) - 1, &read, NULL);
    CloseHandle(hPipe);
    return QString::fromUtf8(resp, read);
}

static BOOL KillProcessByName(const wchar_t* name, BOOL tree)
{
    if (!name || !name[0]) return FALSE;
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return FALSE;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    if (!pid) return FALSE;
    if (tree) {
        hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    if (pe.th32ParentProcessID == pid) {
                        HANDLE hChild = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                        if (hChild) { TerminateProcess(hChild, 1); CloseHandle(hChild); }
                    }
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
    }
    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProc) return FALSE;
    BOOL ok = TerminateProcess(hProc, 1);
    CloseHandle(hProc);
    return ok;
}

static QStringList getProcessList()
{
    QStringList list;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return list;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            list.append(QString::fromWCharArray(pe.szExeFile));
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    list.removeDuplicates();
    return list;
}

static QStringList getManagedList()
{
    QStringList list;
    QString path = QDir(moduleDir()).filePath("data/protected_procs.bin");
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return list;
    QDataStream in(&f);
    int count = 0;
    in >> count;
    for (int i = 0; i < count; ++i) {
        QString name;
        int tree;
        in >> name >> tree;
        if (!name.isEmpty()) list.append(name);
    }
    return list;
}

static QString executeAiCommand(const QString &cmd)
{
    QStringList parts = cmd.split(':');
    if (parts.isEmpty()) return QString();
    QString action = parts[0].trimmed().toLower();

    if (action == "killprocess" && parts.size() >= 2) {
        QString name = parts[1].trimmed();
        bool tree = (parts.size() >= 3 && parts[2].trimmed().toInt() != 0);
        if (KillProcessByName(name.toStdWString().c_str(), tree ? TRUE : FALSE)) {
            MainWindow::appLog(QCoreApplication::translate("AichatTab", "AI executed: killed %1%2")
                .arg(name).arg(tree ? " (tree)" : ""));
            return QString("Executed: killed %1%2").arg(name).arg(tree ? " (tree)" : "");
        }
        return QString("Failed to kill %1").arg(name);
    }
    if (action == "getprocesslist") return "Processes:\n" + getProcessList().join("\n");
    if (action == "getmanagedlist") return "Managed list:\n" + getManagedList().join("\n");
    return QString();
}

static QString processAiCommands(const QString &reply)
{
    QRegularExpression re("\\[(\\w+):([^\\]]+)\\]");
    QString result = reply;
    QRegularExpressionMatchIterator it = re.globalMatch(reply);
    while (it.hasNext()) {
        QRegularExpressionMatch m = it.next();
        QString cmdResult = executeAiCommand(m.captured(0));
        if (!cmdResult.isEmpty()) result += "\n\n[Action result]\n" + cmdResult;
    }
    return result;
}

AichatTab::AichatTab(QWidget *parent)
    : QWidget(parent)
{
    setupUi();
    
    m_injectTimer = new QTimer(this);
    connect(m_injectTimer, &QTimer::timeout, this, &AichatTab::onCheckInjectedPrompts);
    m_injectTimer->start(3000);

    QTimer::singleShot(0, this, &AichatTab::delayedInitialization);
}

AichatTab::~AichatTab()
{
    if (m_thread) {
        if (m_thread->isRunning()) {
            if (m_worker) m_worker->abort();
            m_thread->quit();
            m_thread->wait(2000);
        }
        m_thread->deleteLater();
    }
    if (m_worker) {
        m_worker->deleteLater();
    }
    if (m_logSearcherDll) {
        FreeLibrary(m_logSearcherDll);
        m_logSearcherDll = nullptr;
    }
    if (m_webSearcherDll) {
        FreeLibrary(m_webSearcherDll);
        m_webSearcherDll = nullptr;
    }
}

void AichatTab::setupUi()
{
    QHBoxLayout *mainLayout = new QHBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);

    QSplitter *splitter = new QSplitter(Qt::Horizontal, this);

    QWidget *leftPanel = new QWidget(this);
    QVBoxLayout *leftLayout = new QVBoxLayout(leftPanel);
    leftLayout->setContentsMargins(8, 8, 8, 8);

    m_btnNew = new QPushButton(tr("New Chat"), leftPanel);
    m_btnDelete = new QPushButton(tr("Delete"), leftPanel);
    m_chatList = new QListWidget(leftPanel);
    leftLayout->addWidget(m_btnNew);
    leftLayout->addWidget(m_btnDelete);
    leftLayout->addWidget(m_chatList, 1);

    QWidget *rightPanel = new QWidget(this);
    QVBoxLayout *rightLayout = new QVBoxLayout(rightPanel);
    rightLayout->setContentsMargins(8, 8, 8, 8);

    m_titleLabel = new QLabel(tr("AI Chat"), rightPanel);
    QFont f = m_titleLabel->font();
    f.setPointSize(12);
    f.setBold(true);
    m_titleLabel->setFont(f);

    m_chat = new QTextBrowser(rightPanel);
    m_chat->setOpenExternalLinks(true);

    QHBoxLayout *inputLayout = new QHBoxLayout();
    m_input = new QLineEdit(rightPanel);
    m_input->setPlaceholderText(tr("Type a message..."));
    m_btnSend = new QPushButton(tr("Send"), rightPanel);
    m_btnClear = new QPushButton(tr("Clear"), rightPanel);
    m_btnStop = new QPushButton(tr("Stop"), rightPanel);
    inputLayout->addWidget(m_input, 1);
    inputLayout->addWidget(m_btnSend);
    inputLayout->addWidget(m_btnStop);
    inputLayout->addWidget(m_btnClear);

    rightLayout->addWidget(m_titleLabel);
    rightLayout->addWidget(m_chat, 1);
    rightLayout->addLayout(inputLayout);

    splitter->addWidget(leftPanel);
    splitter->addWidget(rightPanel);
    splitter->setStretchFactor(1, 1);
    mainLayout->addWidget(splitter);

    connect(m_btnNew, &QPushButton::clicked, this, &AichatTab::onNewChat);
    connect(m_btnDelete, &QPushButton::clicked, this, &AichatTab::onDeleteChat);
    connect(m_chatList, &QListWidget::currentRowChanged, this, &AichatTab::onChatSelected);
    connect(m_btnSend, &QPushButton::clicked, this, &AichatTab::onSend);
    connect(m_btnStop, &QPushButton::clicked, this, &AichatTab::onStop);
    connect(m_btnClear, &QPushButton::clicked, this, &AichatTab::onClear);
    connect(m_input, &QLineEdit::returnPressed, this, &AichatTab::onSend);
    connect(m_chat, &QTextBrowser::anchorClicked, this, &AichatTab::onAnchorClicked);

    m_btnStop->setEnabled(false);
}

void AichatTab::loadSettings()
{
    m_apiKey.clear();
    m_provider = "api.siliconflow.cn";
    m_endpoint = "/v1/chat/completions";
    m_model = "Qwen/Qwen2.5-72B-Instruct";
    m_inputContextLimit = 8192;
    m_outputContextLimit = 4096;
    m_temperature = 0.7f;

    QString path = QDir(moduleDir()).filePath("data/ai_config.txt");
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return;

    while (!f.atEnd()) {
        QString line = QString::fromUtf8(f.readLine()).trimmed();
        if (line.isEmpty() || line.startsWith('#')) continue;
        int idx = line.indexOf('=');
        if (idx < 0) continue;
        QString key = line.left(idx).trimmed();
        QString val = line.mid(idx + 1).trimmed();
        if (key.compare("api_key", Qt::CaseInsensitive) == 0) m_apiKey = val;
        else if (key.compare("provider", Qt::CaseInsensitive) == 0) m_provider = val;
        else if (key.compare("endpoint", Qt::CaseInsensitive) == 0) m_endpoint = val;
        else if (key.compare("model", Qt::CaseInsensitive) == 0) m_model = val;
        else if (key.compare("input_context_limit", Qt::CaseInsensitive) == 0) m_inputContextLimit = qMax(0, val.toInt());
        else if (key.compare("output_context_limit", Qt::CaseInsensitive) == 0) m_outputContextLimit = qMax(0, val.toInt());
        else if (key.compare("temperature", Qt::CaseInsensitive) == 0) m_temperature = qBound(0.0f, val.toFloat(), 2.0f);
    }
}

void AichatTab::onAnchorClicked(const QUrl &url)
{
    if (url.scheme() == "loadmore") {
        m_loadAllMessages = true;
        renderMessages();
    } else {
        QDesktopServices::openUrl(url);
    }
}

void AichatTab::delayedInitialization()
{
    QThread *initThread = new QThread(this);
    QObject *initializer = new QObject();

    connect(initThread, &QThread::started, [this, initializer, initThread]() {
        loadSettings();
        loadLogSearcher();
        loadWebSearcher();

        QString path = QDir(moduleDir()).filePath("data/ai_memory/ai_global_chats.json");
        QList<ChatSession> sessions = loadChatsFromFile(path);
        
        QMetaObject::invokeMethod(this, "onInitializationComplete", Qt::QueuedConnection,
                                  Q_ARG(QList<ChatSession>, sessions));
        
        initializer->deleteLater();
        initThread->quit();
        initThread->wait();
        initThread->deleteLater();
    });

    initializer->moveToThread(initThread);
    initThread->start();
}

void AichatTab::onInitializationComplete(const QList<ChatSession> &sessions)
{
    m_sessions = sessions;
    if (m_sessions.isEmpty()) createNewChat();
    else m_activeChatId = m_sessions.first().id;
    updateChatList();
    renderMessages();
}

void AichatTab::delayedLoadChats()
{
    QThread *loaderThread = new QThread(this);
    QObject *loader = new QObject();

    connect(loaderThread, &QThread::started, [this, loader, loaderThread]() {
        QString path = QDir(moduleDir()).filePath("data/ai_memory/ai_global_chats.json");
        QList<ChatSession> sessions = loadChatsFromFile(path);
        QMetaObject::invokeMethod(this, "onChatsLoaded", Qt::QueuedConnection,
                                  Q_ARG(QList<ChatSession>, sessions));
        loader->deleteLater();
        loaderThread->quit();
        loaderThread->wait();
        loaderThread->deleteLater();
    });

    loader->moveToThread(loaderThread);
    loaderThread->start();
}

void AichatTab::loadChats()
{
    QString path = QDir(moduleDir()).filePath("data/ai_memory/ai_global_chats.json");
    m_sessions = loadChatsFromFile(path);
    if (m_sessions.isEmpty()) createNewChat();
    else m_activeChatId = m_sessions.first().id;
    updateChatList();
    renderMessages();
}

void AichatTab::onChatsLoaded(const QList<ChatSession> &sessions)
{
    m_sessions = sessions;
    if (m_sessions.isEmpty()) createNewChat();
    else m_activeChatId = m_sessions.first().id;
    updateChatList();
    renderMessages();
}

bool AichatTab::nativeEvent(const QByteArray &eventType, void *message, qintptr *result)
{
    Q_UNUSED(eventType);
    MSG *msg = (MSG*)message;
    if (msg->message == WM_USER + 100) {
        ChatLoadData *data = (ChatLoadData*)msg->lParam;
        if (data && data->tab == this) {
            m_sessions = data->sessions;
            if (m_sessions.isEmpty()) createNewChat();
            else m_activeChatId = m_sessions.first().id;
            updateChatList();
            renderMessages();
        }
        delete data;
        *result = 0;
        return true;
    }
    return false;
}

void AichatTab::saveChats()
{
    QString path = QDir(moduleDir()).filePath("data/ai_memory/ai_global_chats.json");
    QDir(QFileInfo(path).path()).mkpath(".");
    QJsonArray arr;
    for (const ChatSession &s : m_sessions) {
        QJsonObject o;
        o["id"] = s.id;
        o["title"] = s.title;
        o["createdAt"] = s.createdAt.toString(Qt::ISODate);
        QJsonArray msgs;
        for (const ChatMessage &m : s.messages) {
            QJsonObject mo;
            mo["role"] = m.role;
            mo["text"] = m.text;
            msgs.append(mo);
        }
        o["messages"] = msgs;
        arr.append(o);
    }
    QJsonDocument doc(arr);
    QFile f(path);
    if (f.open(QIODevice::WriteOnly)) {
        f.write(doc.toJson(QJsonDocument::Indented));
    }
}

void AichatTab::createNewChat()
{
    ChatSession s;
    s.id = makeId();
    s.title = tr("New Chat");
    s.createdAt = QDateTime::currentDateTime();
    m_sessions.prepend(s);
    m_activeChatId = s.id;
    updateChatList();
    renderMessages();
    saveChats();
}

void AichatTab::switchToChat(const QString &id)
{
    m_activeChatId = id;
    m_loadAllMessages = false;
    renderMessages();
}

void AichatTab::updateChatList()
{
    m_chatList->clear();
    for (const ChatSession &s : m_sessions) {
        QString title = s.title.isEmpty() ? tr("New Chat") : s.title;
        QListWidgetItem *item = new QListWidgetItem(title, m_chatList);
        item->setData(Qt::UserRole, s.id);
    }
    for (int i = 0; i < m_chatList->count(); i++) {
        if (m_chatList->item(i)->data(Qt::UserRole).toString() == m_activeChatId) {
            m_chatList->setCurrentRow(i);
            break;
        }
    }
}

void AichatTab::onNewChat()
{
    createNewChat();
}

void AichatTab::onDeleteChat()
{
    int row = m_chatList->currentRow();
    if (row < 0 || row >= m_sessions.size()) return;
    m_sessions.removeAt(row);
    if (m_sessions.isEmpty()) createNewChat();
    else m_activeChatId = m_sessions.first().id;
    updateChatList();
    renderMessages();
    saveChats();
}

void AichatTab::onChatSelected()
{
    int row = m_chatList->currentRow();
    if (row < 0 || row >= m_sessions.size()) return;
    switchToChat(m_sessions.at(row).id);
}

void AichatTab::onClear()
{
    auto it = std::find_if(m_sessions.begin(), m_sessions.end(),
        [&](const ChatSession &s) { return s.id == m_activeChatId; });
    if (it == m_sessions.end()) return;
    it->messages.clear();
    renderMessages();
    saveChats();
}

void AichatTab::appendSystemMessage(const QString &message)
{
    auto it = std::find_if(m_sessions.begin(), m_sessions.end(),
        [&](const ChatSession &s) { return s.id == m_activeChatId; });
    if (it == m_sessions.end()) return;
    ChatMessage m;
    m.role = "system";
    m.text = message;
    it->messages.append(m);
    renderMessages();
    saveChats();
}

void AichatTab::addUserMessage(const QString &text)
{
    auto it = std::find_if(m_sessions.begin(), m_sessions.end(),
        [&](const ChatSession &s) { return s.id == m_activeChatId; });
    if (it == m_sessions.end()) return;
    ChatMessage m;
    m.role = "user";
    m.text = text;
    it->messages.append(m);
    if (it->title == tr("New Chat") && !text.isEmpty()) {
        it->title = text.left(20);
        updateChatList();
    }
    renderMessages();
    saveChats();
}

void AichatTab::addAssistantMessage(const QString &text)
{
    auto it = std::find_if(m_sessions.begin(), m_sessions.end(),
        [&](const ChatSession &s) { return s.id == m_activeChatId; });
    if (it == m_sessions.end()) return;
    ChatMessage m;
    m.role = "assistant";
    m.text = processAiCommands(text);
    it->messages.append(m);
    renderMessages();
    saveChats();
}

void AichatTab::appendStreamingChunk(const QString &chunk)
{
    m_currentAiText += chunk;
    renderMessages();
}

void AichatTab::finalizeStreamingMessage()
{
    if (m_currentAiText.isEmpty()) return;
    auto it = std::find_if(m_sessions.begin(), m_sessions.end(),
        [&](const ChatSession &s) { return s.id == m_activeChatId; });
    if (it == m_sessions.end()) return;

    ChatMessage m;
    m.role = "assistant";
    m.text = processAiCommands(m_currentAiText);
    it->messages.append(m);
    m_currentAiText.clear();
    renderMessages();
    saveChats();
}

void AichatTab::renderMessages()
{
    auto it = std::find_if(m_sessions.begin(), m_sessions.end(),
        [&](const ChatSession &s) { return s.id == m_activeChatId; });
    if (it == m_sessions.end()) return;

    const int visibleWindow = 20;
    const int totalMessages = it->messages.size();
    
    int startIdx = m_loadAllMessages ? 0 : qMax(0, totalMessages - visibleWindow);
    int endIdx = totalMessages;

    QString html;
    html.reserve(32768);
    
    html += "<html><head><style>"
            "body { background: #1c1c1e; font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif; font-size: 14px; "
            "margin: 0; padding: 12px; color: #f2f2f7; }"
            "table { border-collapse: collapse; }"
            "code { background: rgba(0,0,0,0.25); padding: 2px 5px; border-radius: 4px; font-family: Consolas, monospace; font-size: 13px; }"
            "pre { background: rgba(0,0,0,0.25); padding: 10px; border-radius: 8px; overflow-x: auto; margin: 8px 0; }"
            "pre code { padding: 0; background: transparent; }"
            "ul, ol { margin: 6px 0; padding-left: 20px; }"
            "li { margin: 3px 0; }"
            "h1, h2, h3 { margin: 8px 0; font-weight: 600; }"
            "p { margin: 4px 0; }"
            "a { color: #0a84ff; }"
            ".load-more { text-align: center; color: #666; font-size: 12px; padding: 8px; cursor: pointer; }"
            ".load-more:hover { color: #0a84ff; }"
            "</style></head><body>";

    static const QString userBubbleStyle = 
        "display: inline-block; width: auto; min-width: 40px; max-width: 520px; "
        "background-color: #0a84ff; color: #ffffff; border-radius: 16px; "
        "border-bottom-right-radius: 4px; padding: 10px 14px; "
        "line-height: 1.55; word-wrap: break-word; "
        "box-shadow: 0 1px 3px rgba(0,0,0,0.3);";
    
    static const QString aiBubbleStyle = 
        "display: inline-block; width: auto; min-width: 40px; max-width: 520px; "
        "background-color: #3a3a3c; color: #f2f2f7; border-radius: 16px; "
        "border-bottom-left-radius: 4px; padding: 10px 14px; "
        "line-height: 1.55; word-wrap: break-word; "
        "border: 1px solid #48484a; box-shadow: 0 1px 3px rgba(0,0,0,0.3);";

    static const QString userAvatarStyle = 
        "width: 30px; height: 30px; border-radius: 50%; background-color: #0066d4; "
        "text-align: center; vertical-align: middle; line-height: 30px; "
        "font-size: 12px; font-weight: bold; color: white;";
    
    static const QString aiAvatarStyle = 
        "width: 30px; height: 30px; border-radius: 50%; background-color: #3634a3; "
        "text-align: center; vertical-align: middle; line-height: 30px; "
        "font-size: 12px; font-weight: bold; color: white;";

    static const QString userTriStyle = 
        "<div style='width: 0; height: 0; border-top: 7px solid transparent; "
        "border-bottom: 7px solid transparent; border-left: 9px solid #0a84ff;'></div>";
    
    static const QString aiTriStyle = 
        "<div style='width: 0; height: 0; border-top: 7px solid transparent; "
        "border-bottom: 7px solid transparent; border-right: 9px solid #3a3a3c;'></div>";

    static const QString userTemplate = 
        "<table width='100%' style='margin: 10px 0;'><tr>"
        "<td align='right' valign='bottom'>%1</td>"
        "<td width='9' valign='bottom' style='padding-bottom: 10px;'>%2</td>"
        "<td width='30' valign='top'>%3</td>"
        "</tr></table>";
    
    static const QString aiTemplate = 
        "<table width='100%' style='margin: 10px 0;'><tr>"
        "<td width='30' valign='top'>%1</td>"
        "<td width='9' valign='bottom' style='padding-bottom: 10px;'>%2</td>"
        "<td align='left' valign='bottom'>%3</td>"
        "</tr></table>";

    if (startIdx > 0) {
        html += QString("<div class='load-more' onclick=\"window.location.href='loadmore://top'\">[Click to load %1 older messages]</div>")
                    .arg(startIdx);
    }

    for (int i = startIdx; i < endIdx; ++i) {
        const ChatMessage &m = it->messages[i];
        
        if (m.role == "system") {
            QString text;
            if (m.cachedHtml.isEmpty()) {
                text = mdToHtml(m.text);
                const_cast<ChatMessage&>(m).cachedHtml = text;
            } else {
                text = m.cachedHtml;
            }
            html += QString("<div style='text-align: center; color: #8e8e93; font-size: 12px; margin: 8px 0; white-space: pre-wrap;'>%1</div>").arg(text);
            continue;
        }
        
        bool user = (m.role == "user");
        QString text;
        if (m.cachedHtml.isEmpty()) {
            text = mdToHtml(m.text);
            const_cast<ChatMessage&>(m).cachedHtml = text;
        } else {
            text = m.cachedHtml;
        }
        
        QString bubble = QString("<div style='%1'>%2</div>").arg(user ? userBubbleStyle : aiBubbleStyle, text);
        
        if (user) {
            html += userTemplate.arg(bubble, userTriStyle, QString("<div style='%1'>U</div>").arg(userAvatarStyle));
        } else {
            html += aiTemplate.arg(QString("<div style='%1'>AI</div>").arg(aiAvatarStyle), aiTriStyle, bubble);
        }
    }

    if (!m_currentAiText.isEmpty()) {
        QString text = mdToHtml(m_currentAiText);
        QString bubble = QString("<div style='%1'>%2</div>").arg(aiBubbleStyle, text);
        html += aiTemplate.arg(QString("<div style='%1'>AI</div>").arg(aiAvatarStyle), aiTriStyle, bubble);
    }

    html += "</body></html>";
    m_chat->setHtml(html);

    QTimer::singleShot(50, [this]() {
        if (m_chat->isVisible()) {
            QScrollBar *sb = m_chat->verticalScrollBar();
            if (sb) sb->setValue(sb->maximum());
        }
    });
}

QString AichatTab::mdToHtml(const QString &markdown)
{
    QString html = markdown;

    html.remove(QRegularExpression("(?:^|[\\s\\(\\[])\\$\\d+\\b"));
    html.replace("\\u0024", "$");
    html.replace("&#36;", "$");

    html.replace("\\\\n", "\n");
    html.replace("\\\\t", "\t");
    html.replace("\\\\r", "\r");
    html.replace("\\\\\"", "\"");
    html.replace("\\\\'", "'");
    html.replace("\\\\\\", "\\");

    static const QRegularExpression uRe("\\\\u([0-9a-fA-F]{4})");
    QRegularExpressionMatchIterator uIt = uRe.globalMatch(html);
    QStringList uChunks;
    int uLast = 0;
    while (uIt.hasNext()) {
        QRegularExpressionMatch m = uIt.next();
        uChunks.append(html.mid(uLast, m.capturedStart() - uLast));
        bool ok = false;
        ushort code = m.captured(1).toUShort(&ok, 16);
        uChunks.append(ok ? QString(QChar(code)) : m.captured(0));
        uLast = m.capturedEnd();
    }
    uChunks.append(html.mid(uLast));
    html = uChunks.join(QString());

    html.replace("\r\n", "\n");
    html.replace('\r', "\n");

    html.replace("&", "&amp;");
    html.replace("<", "&lt;");
    html.replace(">", "&gt;");

    static const QRegularExpression codeBlockRe("```(?:([\\w+#-]+)\\n)?([\\s\\S]*?)```");
    QRegularExpressionMatchIterator codeIt = codeBlockRe.globalMatch(html);
    QStringList codeChunks;
    int codeLast = 0;
    while (codeIt.hasNext()) {
        QRegularExpressionMatch m = codeIt.next();
        codeChunks.append(html.mid(codeLast, m.capturedStart() - codeLast));
        QString code = m.captured(2);
        code.replace("&", "&amp;");
        code.replace("<", "&lt;");
        code.replace(">", "&gt;");
        code.replace("\n", "<br>");
        codeChunks.append(QString("<pre style='background:rgba(0,0,0,0.35);padding:10px;border-radius:8px;overflow-x:auto;'><code>%1</code></pre>").arg(code));
        codeLast = m.capturedEnd();
    }
    codeChunks.append(html.mid(codeLast));
    html = codeChunks.join(QString());

    html.replace(QRegularExpression("`([^`]+)`"), "<code style='background:rgba(0,0,0,0.25);padding:2px 5px;border-radius:4px;font-family:Consolas,monospace;'>$1</code>");
    html.replace(QRegularExpression("\\*\\*(.+?)\\*\\*"), "<b>$1</b>");
    html.replace(QRegularExpression("\\*(.+?)\\*"), "<i>$1</i>");
    html.replace(QRegularExpression("\\[([^\\]]+)\\]\\(([^)]+)\\)"), "<a href=\"$2\" style='color:#0a84ff;'>$1</a>");

    static const QRegularExpression headingRe("^(#{1,6})\\s+(.*)$", QRegularExpression::MultilineOption);
    QRegularExpressionMatchIterator headingIt = headingRe.globalMatch(html);
    QStringList headingChunks;
    int headingLast = 0;
    while (headingIt.hasNext()) {
        QRegularExpressionMatch m = headingIt.next();
        headingChunks.append(html.mid(headingLast, m.capturedStart() - headingLast));
        int level = m.captured(1).length();
        QString content = m.captured(2);
        headingChunks.append(QString("<h%1 style='margin:8px 0;font-weight:600;'>%2</h%1>").arg(level).arg(content));
        headingLast = m.capturedEnd();
    }
    headingChunks.append(html.mid(headingLast));
    html = headingChunks.join(QString());

    static const QRegularExpression ulRe("(?:^\\s*[-*]\\s+.+\\n?)+", QRegularExpression::MultilineOption);
    QRegularExpressionMatchIterator ulIt = ulRe.globalMatch(html);
    QStringList ulChunks;
    int ulLast = 0;
    while (ulIt.hasNext()) {
        QRegularExpressionMatch m = ulIt.next();
        ulChunks.append(html.mid(ulLast, m.capturedStart() - ulLast));
        QString ul = m.captured(0);
        ul.replace(QRegularExpression("^\\s*[-*]\\s+(.+)$", QRegularExpression::MultilineOption), "<li style='margin:3px 0;'>$1</li>");
        ul.replace("\n", "");
        ulChunks.append(QString("<ul style='margin:6px 0;padding-left:20px;'>%1</ul>").arg(ul));
        ulLast = m.capturedEnd();
    }
    ulChunks.append(html.mid(ulLast));
    html = ulChunks.join(QString());

    static const QRegularExpression olRe("(?:^\\s*\\d+\\.\\s+.+\\n?)+", QRegularExpression::MultilineOption);
    QRegularExpressionMatchIterator olIt = olRe.globalMatch(html);
    QStringList olChunks;
    int olLast = 0;
    while (olIt.hasNext()) {
        QRegularExpressionMatch m = olIt.next();
        olChunks.append(html.mid(olLast, m.capturedStart() - olLast));
        QString ol = m.captured(0);
        ol.replace(QRegularExpression("^\\s*\\d+\\.\\s+(.+)$", QRegularExpression::MultilineOption), "<li style='margin:3px 0;'>$1</li>");
        ol.replace("\n", "");
        olChunks.append(QString("<ol style='margin:6px 0;padding-left:20px;'>%1</ol>").arg(ol));
        olLast = m.capturedEnd();
    }
    olChunks.append(html.mid(olLast));
    html = olChunks.join(QString());

    static const QRegularExpression tableRe("(?:^\\|.*\\|\\n?)+", QRegularExpression::MultilineOption);
    QRegularExpressionMatchIterator tableIt = tableRe.globalMatch(html);
    QStringList tableChunks;
    int tableLast = 0;
    while (tableIt.hasNext()) {
        QRegularExpressionMatch m = tableIt.next();
        tableChunks.append(html.mid(tableLast, m.capturedStart() - tableLast));
        QStringList rows = m.captured(0).split('\n', Qt::SkipEmptyParts);
        QString tableHtml = "<table style='border-collapse:collapse;margin:8px 0;width:100%;'>";
        int rowIdx = 0;
        for (QString r : rows) {
            r = r.trimmed();
            if (r.startsWith('|')) r = r.mid(1);
            if (r.endsWith('|')) r.chop(1);
            QStringList cells = r.split('|');
            bool allDashes = true;
            for (const QString &c : cells) {
                QString t = c.trimmed();
                if (!t.isEmpty() && t != QString(t.length(), '-')) { allDashes = false; break; }
            }
            if (allDashes) continue;
            tableHtml += "<tr>";
            for (QString c : cells) {
                c = c.trimmed();
                if (rowIdx == 0)
                    tableHtml += QString("<th style='border:1px solid #48484a;padding:6px 10px;background:#2c2c2e;text-align:left;'>%1</th>").arg(c);
                else
                    tableHtml += QString("<td style='border:1px solid #48484a;padding:6px 10px;'>%1</td>").arg(c);
            }
            tableHtml += "</tr>";
            rowIdx++;
        }
        tableHtml += "</table>";
        tableChunks.append(tableHtml);
        tableLast = m.capturedEnd();
    }
    tableChunks.append(html.mid(tableLast));
    html = tableChunks.join(QString());

    html.replace(QRegularExpression("\\n{2,}"), "</p><p style='margin:4px 0;'>");
    html = "<p style='margin:4px 0;'>" + html + "</p>";
    html.replace(QRegularExpression("<p style='margin:4px 0;'>\\s*<p style='margin:4px 0;'>"), "<p style='margin:4px 0;'>");
    html.replace(QRegularExpression("</p>\\s*</p>"), "</p>");

    return html;
}

QString AichatTab::buildSystemPrompt(bool forToolAnswer, bool allowMoreTools) const
{
    QString prompt;
    QString customPath = QDir(moduleDir()).filePath("data/ai_memory/system_prompt.txt");
    QFile f(customPath);
    if (f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QByteArray data = f.readAll();
        QString custom = QString::fromUtf8(data).trimmed();
        if (!custom.isEmpty()) prompt = custom + "\n\n";
    }
    if (prompt.isEmpty()) {
        prompt = "You are TRAE Guardian, a Windows security analyst. Answer in Markdown.\n\n";
    }

    prompt += "Available tools (return ONLY JSON, no explanation):\n"
              "{\"tool\":\"search_logs\",\"arguments\":{\"keyword\":\"...\"}} — search daemon.log and ai_notifications.log\n"
              "{\"tool\":\"search_knowledge\",\"arguments\":{\"keyword\":\"...\"}} — search behavior knowledge base\n"
              "{\"tool\":\"web_search\",\"arguments\":{\"keyword\":\"...\"}} — search internet for reputation\n"
              "{\"tool\":\"search_history\",\"arguments\":{\"keyword\":\"...\"}} — search chat history\n"
              "If enough information is already available, reply with ONLY the literal text NO_TOOL.\n\n";

    if (forToolAnswer) {
        if (allowMoreTools) {
            prompt += "The previous tool returned no useful data. Call another tool with JSON, or reply NO_TOOL.\n\n";
        } else {
            prompt += "You already have the tool result. Do NOT call more tools. Answer the user directly.\n\n";
        }
    }
    return prompt;
}

QString AichatTab::buildHistoryContext() const
{
    auto it = std::find_if(m_sessions.begin(), m_sessions.end(),
        [&](const ChatSession &s) { return s.id == m_activeChatId; });
    if (it == m_sessions.end()) return QString();
    QString ctx = "Conversation history:\n";
    for (const ChatMessage &m : it->messages) {
        if (m.role == "user") ctx += "user: " + m.text + "\n";
        else if (m.role == "assistant") ctx += "assistant: " + m.text + "\n";
        else if (m.role == "system") ctx += "system: " + m.text + "\n";
    }
    return ctx;
}

QString AichatTab::buildToolPrompt(const QString &userText, const QString &preloadedContext) const
{
    QString prompt = buildSystemPrompt(false);
    prompt += buildHistoryContext();
    bool hasRealLogs = !preloadedContext.isEmpty() &&
                       !preloadedContext.contains("No matching", Qt::CaseInsensitive) &&
                       !preloadedContext.contains("not loaded", Qt::CaseInsensitive);
    if (hasRealLogs) {
        QString ctx = preloadedContext;
        if (ctx.length() > 6000) ctx = ctx.left(6000) + "\n... (truncated)";
        prompt += "The system has already searched the logs for you. Here are the relevant entries:\n";
        prompt += ctx + "\n\n";
        prompt += "First, state how many events you see above. Then based ONLY on the above log entries, "
                  "answer the user's question directly. "
                  "List specific processes, threat levels, reasons, and your recommendations. "
                  "Use Markdown: ## headings, **bold**, bullet lists, and a table if multiple events. "
                  "Do NOT invent any process name, PID, path, or date. "
                  "Do NOT say you need more information. Do NOT ask the user to run a search.\n";
    } else if (!preloadedContext.isEmpty()) {
        prompt += "The system searched the logs but found no matching HIGH/CONFIRMED events. "
                  "Answer the user with '未找到相关事件' and a brief note that no suspicious activity was recorded. "
                  "Do NOT invent any process name, PID, path, or date.\n";
    }
    prompt += "User question: " + userText + "\n";
    return prompt;
}

QString AichatTab::buildFinalPrompt(const QString &userText, const QString &toolCall,
                                    const QString &toolResult) const
{
    bool emptyResult = toolResult.isEmpty() ||
                       toolResult.contains("No matching", Qt::CaseInsensitive) ||
                       toolResult.contains("not found", Qt::CaseInsensitive) ||
                       toolResult.contains("not loaded", Qt::CaseInsensitive);
    QString prompt = buildSystemPrompt(true, emptyResult);
    prompt += buildHistoryContext();
    prompt += "User question: " + userText + "\n";
    prompt += "Tool you called: " + toolCall + "\n";
    prompt += "Tool result:\n" + toolResult + "\n";

    if (emptyResult) {
        prompt += "The tool returned no useful data. Decide whether to call another tool or answer with what you know. "
                  "For named software/reputation questions, you should now call web_search.\n";
    } else {
        prompt += "You have received the tool result. THIS IS YOUR FINAL CHANCE TO RESPOND. "
                  "DO NOT CALL ANY MORE TOOLS. DO NOT RETURN JSON tool calls. "
                  "Answer the user's question directly and completely based on the tool result above. "
                  "Provide a comprehensive analysis with specific findings and recommendations. "
                  "Use Markdown format for better readability.\n";
    }
    return prompt;
}

bool AichatTab::loadLogSearcher()
{
    QString dllPath = QDir(moduleDir()).filePath("log_searcher.dll");
    m_logSearcherDll = LoadLibraryW(dllPath.toStdWString().c_str());
    if (!m_logSearcherDll) return false;
    m_pfnLogSearch = (PFN_LogSrch_Search)GetProcAddress(m_logSearcherDll, "SearchLogByKeyword");
    if (!m_pfnLogSearch) {
        FreeLibrary(m_logSearcherDll);
        m_logSearcherDll = nullptr;
        return false;
    }
    return true;
}

static QString searchOneLog(PFN_LogSrch_Search pfn, const QString &path, const QString &keyword, int maxHits)
{
    if (!pfn) return QString();
    AiLogSearchHit *hits = new AiLogSearchHit[maxHits];
    int count = pfn(path.toUtf8().constData(), keyword.toUtf8().constData(), hits, maxHits);
    QStringList lines;
    if (count > 0) {
        for (int i = 0; i < count && i < maxHits; i++) {
            lines.append(QString::fromUtf8(hits[i].line));
        }
    }
    delete[] hits;
    return lines.join("\n");
}

QString AichatTab::searchLogs(const QString &keyword)
{
    if (!m_pfnLogSearch) return tr("Log search DLL not loaded.");
    QString daemonPath = QDir(moduleDir()).filePath("data/daemon.log");
    QString notifyPath = QDir(moduleDir()).filePath("data/ai_notifications.log");

    QStringList all;
    QString daemonResult = searchOneLog(m_pfnLogSearch, daemonPath, keyword, 64);
    QString notifyResult = searchOneLog(m_pfnLogSearch, notifyPath, keyword, 64);

    if (!daemonResult.isEmpty()) {
        all.append(tr("=== daemon.log ==="));
        all.append(daemonResult);
    }
    if (!notifyResult.isEmpty()) {
        all.append(tr("=== AI analysis log (ai_notifications.log) ==="));
        all.append(notifyResult);
    }

    if (all.isEmpty()) return tr("No matching log entries found.");
    return all.join("\n");
}

QString AichatTab::searchKnowledge(const QString &keyword)
{
    QString path = QDir(moduleDir()).filePath("data/ai_memory/ai_knowledge.md");
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return tr("Knowledge base not found.");
    QByteArray data = f.readAll();
    QString text = QString::fromUtf8(data);
    QStringList all = text.split('\n', Qt::SkipEmptyParts);
    QStringList results;
    for (const QString &line : all) {
        if (line.contains(keyword, Qt::CaseInsensitive)) results.append(line);
    }
    if (results.isEmpty()) return tr("No matching knowledge base entries found.");
    return results.join("\n");
}

bool AichatTab::loadWebSearcher()
{
    QString dllPath = QDir(moduleDir()).filePath("AI/ai_web_search.dll");
    m_webSearcherDll = LoadLibraryW(dllPath.toStdWString().c_str());
    if (!m_webSearcherDll) return false;
    m_pfnWebSearch = (PFN_WebSearch)GetProcAddress(m_webSearcherDll, "WebSearch");
    if (!m_pfnWebSearch) {
        FreeLibrary(m_webSearcherDll);
        m_webSearcherDll = nullptr;
        return false;
    }
    return true;
}

QString AichatTab::searchWeb(const QString &keyword)
{
    if (!m_pfnWebSearch) return tr("Web search DLL not loaded.");
    QByteArray utf8 = keyword.toUtf8();
    char buf[32768] = {0};
    int count = m_pfnWebSearch(utf8.constData(), buf, sizeof(buf));
    if (count <= 0) return tr("No web search results found.");
    return QString::fromUtf8(buf);
}

QString AichatTab::searchHistory(const QString &keyword)
{
    if (keyword.isEmpty()) return tr("No keyword provided.");
    QStringList results;
    int totalMatches = 0;
    for (const ChatSession &s : m_sessions) {
        for (const ChatMessage &m : s.messages) {
            if (m.text.contains(keyword, Qt::CaseInsensitive)) {
                if (++totalMatches <= 30) {
                    QString role = m.role == "user" ? tr("User") : tr("AI");
                    QString text = m.text;
                    if (text.length() > 300) text = text.left(300) + "...";
                    results.append(QString("[%1] %2").arg(role, text));
                }
            }
        }
    }
    if (results.isEmpty()) return tr("No matching history found.");
    QString header = tr("Found %1 matching message(s). Showing first %2:").arg(totalMatches).arg(results.size());
    return header + "\n\n" + results.join("\n\n");
}

bool AichatTab::parseToolCall(const QString &reply, QString &outTool, QString &outArgs)
{
    QJsonDocument doc = QJsonDocument::fromJson(reply.toUtf8());
    if (!doc.isObject()) return false;
    QJsonObject obj = doc.object();
    if (!obj.contains("tool")) return false;
    outTool = obj.value("tool").toString();
    outArgs = QJsonDocument(obj.value("arguments").toObject()).toJson(QJsonDocument::Compact);
    return !outTool.isEmpty();
}

QString AichatTab::executeTool(const QString &toolName, const QString &argsJson)
{
    QJsonDocument doc = QJsonDocument::fromJson(argsJson.toUtf8());
    QJsonObject obj = doc.object();
    if (toolName == "search_logs") {
        QString kw = obj.value("keyword").toString();
        if (kw.isEmpty()) return tr("No keyword provided.");
        return searchLogs(kw);
    }
    if (toolName == "search_knowledge") {
        QString kw = obj.value("keyword").toString();
        if (kw.isEmpty()) return tr("No keyword provided.");
        return searchKnowledge(kw);
    }
    if (toolName == "web_search") {
        QString kw = obj.value("keyword").toString();
        if (kw.isEmpty()) return tr("No keyword provided.");
        return searchWeb(kw);
    }
    if (toolName == "search_history") {
        QString kw = obj.value("keyword").toString();
        if (kw.isEmpty()) return tr("No keyword provided.");
        return searchHistory(kw);
    }
    return tr("Unknown tool: %1").arg(toolName);
}

void AichatTab::startWorker(const QString &systemPrompt, const QString &userPrompt, bool stream)
{
    /* Clean up any previous worker/thread without double-deleting */
    if (m_thread) {
        if (m_thread->isRunning()) {
            if (m_worker) m_worker->abort();
            m_thread->quit();
            m_thread->wait(1500);
        }
        m_thread->deleteLater();
        m_thread = nullptr;
    }
    if (m_worker) {
        m_worker->deleteLater();
        m_worker = nullptr;
    }

    m_thread = new QThread(this);
    m_worker = new AiWorker(systemPrompt, userPrompt,
                            m_apiKey, m_provider, m_endpoint, m_model,
                            stream,
                            m_inputContextLimit, m_outputContextLimit,
                            m_temperature);
    m_worker->moveToThread(m_thread);
    connect(m_thread, &QThread::started, m_worker, &AiWorker::process);
    connect(m_worker, &AiWorker::chunkReady, this, &AichatTab::onChunk);
    connect(m_worker, &AiWorker::resultReady, this, &AichatTab::onResult);
    connect(m_worker, &AiWorker::resultReady, m_thread, &QThread::quit);
    m_thread->start();

    QString keyHint = m_apiKey.isEmpty() ? "empty" : QString("%1...").arg(m_apiKey.left(4));
    guiDebugLog(QString("[startWorker] stream=%1 provider=%2 endpoint=%3 model=%4 keyHint=%5")
                .arg(stream).arg(m_provider).arg(m_endpoint).arg(m_model).arg(keyHint));
}

void AichatTab::resetSendButton()
{
    m_running = false;
    m_btnSend->setEnabled(true);
    m_btnStop->setEnabled(false);
}

void AichatTab::onStop()
{
    if (m_worker) m_worker->abort();
    m_running = false;
    m_streaming = false;
    m_btnSend->setEnabled(true);
    m_btnStop->setEnabled(false);
}

void AichatTab::onChunk(const QString &chunk)
{
    if (!m_streaming) {
        m_streaming = true;
        m_currentAiText.clear();
    }
    appendStreamingChunk(chunk);
}

void AichatTab::onResult(const QString &reply, int rc)
{
    m_input->clear();
    m_running = false;
    m_btnSend->setEnabled(true);
    m_btnStop->setEnabled(false);

    guiDebugLog(QString("[onResult] rc=%1 streaming=%2 replyLen=%3").arg(rc).arg(m_streaming).arg(reply.length()));

    if (m_streaming) {
        m_streaming = false;
        if (rc <= 0 && m_currentAiText.isEmpty()) {
            appendSystemMessage(tr("Failed (code %1): AI returned no content").arg(rc));
        } else {
            finalizeStreamingMessage();
        }
        return;
    }

    if (rc <= 0 || reply.isEmpty()) {
        QString errorMsg;
        if (rc == -401) {
            errorMsg = tr("API Key invalid or expired. Please check your API Key in settings.");
        } else if (rc == -1) {
            errorMsg = tr("Connection failed. Please check network connectivity or try again later.");
        } else {
            errorMsg = tr("Failed (code %1): %2").arg(rc).arg(reply.isEmpty() ? tr("empty reply") : reply);
        }
        appendSystemMessage(errorMsg);
        return;
    }

    QString text = processAiCommands(reply).trimmed();
    QString tool, args;
    if (parseToolCall(text, tool, args)) {
        guiDebugLog(QString("[tool] %1 %2").arg(tool, args));
        if (m_preloadedContext) {
            guiDebugLog("[tool] ignored because logs were already pre-loaded");
            QString directPrompt = buildSystemPrompt(true);
            directPrompt += buildHistoryContext();
            directPrompt += "The system already provided log entries above. Answer the user's question directly based on those entries. "
                            "Do NOT call any tool. Do NOT invent data.\n";
            directPrompt += "User question: " + m_currentUserText + "\n";
            m_lastSystemPrompt = buildSystemPrompt(true);
            m_lastUserPrompt = directPrompt;
            startWorker(m_lastSystemPrompt, m_lastUserPrompt, true);
            m_btnSend->setEnabled(false);
            m_btnStop->setEnabled(true);
            m_running = true;
            return;
        }
        if (m_toolRound >= 3) {
            addAssistantMessage(tr("I needed to use a tool but reached the maximum number of tool rounds. Please simplify your question."));
            return;
        }
        m_toolRound++;
        QString result = executeTool(tool, args);
        appendSystemMessage(QString("[Tool] %1(%2)\nResult:\n%3").arg(tool, args, result));
        QString finalPrompt = buildFinalPrompt(m_currentUserText, tool + " " + args, result);
        m_lastSystemPrompt = buildSystemPrompt(true);
        m_lastUserPrompt = finalPrompt;
        startWorker(m_lastSystemPrompt, m_lastUserPrompt, true);
        m_btnSend->setEnabled(false);
        m_btnStop->setEnabled(true);
        m_running = true;
        return;
    }

    /* AI decided it does not need a tool */
    if (text.compare("NO_TOOL", Qt::CaseInsensitive) == 0) {
        guiDebugLog("[onResult] AI returned NO_TOOL, asking for direct answer");
        QString directPrompt = buildSystemPrompt(true);
        directPrompt += buildHistoryContext();
        directPrompt += "User question: " + m_currentUserText + "\n";
        directPrompt += "Answer directly.";
        m_lastSystemPrompt = buildSystemPrompt(true);
        m_lastUserPrompt = directPrompt;
        startWorker(m_lastSystemPrompt, m_lastUserPrompt, true);
        m_btnSend->setEnabled(false);
        m_btnStop->setEnabled(true);
        m_running = true;
        return;
    }

    addAssistantMessage(text);
}

void AichatTab::onSend()
{
    if (m_running) return;
    QString text = m_input->text().trimmed();
    if (text.isEmpty()) return;

    guiDebugLog(QString("[onSend] userText=%1").arg(text));

    if (text.startsWith("/clean", Qt::CaseInsensitive)) {
        QString arg = text.mid(6).trimmed().toLower();
        if (arg == "2345" || arg == "residue" || arg == "2345residue") {
            addUserMessage(text);
            appendSystemMessage(tr("Requesting daemon to clean 2345 numeric extension residue..."));
            QString resp = sendPipeCommand("{\"cmd\":\"clean_residue\"}");
            appendSystemMessage(tr("Cleanup result: %1").arg(resp));
        } else {
            appendSystemMessage(tr("Unknown /clean target. Use: /clean 2345"));
        }
        return;
    }

    addUserMessage(text);
    m_currentUserText = text;
    m_currentAiText.clear();
    m_toolRound = 0;
    m_preloadedContext = false;
    m_running = true;
    m_streaming = false;
    m_btnSend->setEnabled(false);
    m_btnStop->setEnabled(true);

    /* Pre-fetch logs for broad security questions so the AI answers with real data,
       without requiring the model to voluntarily call a tool. */
    QString lower = text.toLower();
    bool broadSecurity = lower.contains("有没有") || lower.contains("分析一下") ||
                         lower.contains("可疑") || lower.contains("异常") ||
                         lower.contains("流氓") || lower.contains("病毒") ||
                         lower.contains("木马") || lower.contains("威胁") ||
                         lower.contains("安全状况") || lower.contains("电脑里") ||
                         lower.contains("系统里");
    QString preloaded;
    if (broadSecurity) {
        preloaded = searchLogs("HIGH");
        if (preloaded.isEmpty() || preloaded.contains("No matching", Qt::CaseInsensitive)) {
            preloaded = searchLogs("CONFIRMED");
        }
        if (preloaded.isEmpty() || preloaded.contains("No matching", Qt::CaseInsensitive)) {
            preloaded = searchLogs("Daily Report");
        }
        bool hasRealLogs = !preloaded.isEmpty() &&
                           !preloaded.contains("No matching", Qt::CaseInsensitive) &&
                           !preloaded.contains("not loaded", Qt::CaseInsensitive);
        m_preloadedContext = hasRealLogs;
    }

    m_lastSystemPrompt = buildSystemPrompt(false);
    m_lastUserPrompt = buildToolPrompt(text, preloaded);
    startWorker(m_lastSystemPrompt, m_lastUserPrompt, true);
}

QString AichatTab::makeId()
{
    return QUuid::createUuid().toString(QUuid::WithoutBraces);
}

void AichatTab::refresh()
{
    QThread *loaderThread = new QThread(this);
    QObject *loader = new QObject();

    connect(loaderThread, &QThread::started, [this, loader, loaderThread]() {
        QString path = QDir(moduleDir()).filePath("data/ai_memory/ai_global_chats.json");
        QList<ChatSession> sessions = loadChatsFromFile(path);
        QMetaObject::invokeMethod(this, "onChatsLoaded", Qt::QueuedConnection,
                                  Q_ARG(QList<ChatSession>, sessions));
        loader->deleteLater();
        loaderThread->quit();
        loaderThread->wait();
        loaderThread->deleteLater();
    });

    loader->moveToThread(loaderThread);
    loaderThread->start();
}

void AichatTab::onCheckInjectedPrompts()
{
    QString path = QDir(moduleDir()).filePath("data/ai_memory/ai_chat_inject.jsonl");
    if (!QFile::exists(path)) return;
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return;
    QByteArray data = f.readAll();
    f.close();
    if (data.isEmpty()) return;
    QFile::remove(path);

    auto it = std::find_if(m_sessions.begin(), m_sessions.end(),
        [&](const ChatSession &s) { return s.id == m_activeChatId; });
    if (it == m_sessions.end()) return;

    for (const QByteArray &line : data.split('\n')) {
        if (line.isEmpty()) continue;
        QJsonDocument doc = QJsonDocument::fromJson(line);
        if (!doc.isObject()) continue;
        QJsonObject obj = doc.object();
        QString time = obj.value("time").toString();
        QString proc = obj.value("proc").toString();
        QString objectType = obj.value("objectType").toString();
        QString object = obj.value("object").toString();
        QString system = obj.value("system").toString();
        QString user = obj.value("user").toString();
        if (system.isEmpty() && user.isEmpty()) continue;

        QString msg = tr("[Daemon AI analysis request %1]\nProcess: %2\nObject: %3 (%4)\n\n[System prompt]\n%5\n\n[User prompt]\n%6")
                          .arg(time, proc, object, objectType, system, user);
        ChatMessage m;
        m.role = "system";
        m.text = msg;
        it->messages.append(m);
    }
    renderMessages();
    saveChats();
}
