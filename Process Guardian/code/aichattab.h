#pragma once

#include <QWidget>
#include <QListWidget>
#include <QTextBrowser>
#include <QLineEdit>
#include <QPushButton>
#include <QSplitter>
#include <QLabel>
#include <QThread>
#include <QDateTime>
#include <QJsonObject>
#include <QTimer>
#include <QList>
#include <windows.h>

struct ChatMessage {
    QString role;
    QString text;
    QString cachedHtml;
};

struct ChatSession {
    QString id;
    QString title;
    QDateTime createdAt;
    QList<ChatMessage> messages;
};

/* Match log_searcher.dll interface */
#pragma pack(push, 1)
typedef struct {
    int  lineNo;
    char line[1024];
} AiLogSearchHit;
#pragma pack(pop)

typedef int (*PFN_LogSrch_Search)(const char *logPath, const char *keyword,
                                  AiLogSearchHit *outHits, int maxHits);

typedef int (*PFN_WebSearch)(const char *query, char *outBuffer, int outBufferSize);

class AiWorker;

class AichatTab : public QWidget
{
    Q_OBJECT

public:
    explicit AichatTab(QWidget *parent = nullptr);
    ~AichatTab();

    void appendSystemMessage(const QString &message);

public slots:
    void refresh();

private slots:
    void onNewChat();
    void onDeleteChat();
    void onChatSelected();
    void onSend();
    void onStop();
    void onChunk(const QString &chunk);
    void onResult(const QString &reply, int rc);
    void onClear();
    void onCheckInjectedPrompts();
    void onChatsLoaded(const QList<ChatSession> &sessions);
    void onInitializationComplete(const QList<ChatSession> &sessions);
    void onAnchorClicked(const QUrl &url);

protected:
    bool nativeEvent(const QByteArray &eventType, void *message, qintptr *result) override;

private:
    void setupUi();
    void loadSettings();
    void loadChats();
    void delayedLoadChats();
    void delayedInitialization();
    void saveChats();
    void createNewChat();
    void switchToChat(const QString &id);
    void updateChatList();
    void renderMessages();
    void addUserMessage(const QString &text);
    void addAssistantMessage(const QString &text);
    void appendStreamingChunk(const QString &chunk);
    void finalizeStreamingMessage();

    QString buildSystemPrompt(bool forToolAnswer = false, bool allowMoreTools = false) const;
    QString buildHistoryContext() const;
    QString buildToolPrompt(const QString &userText, const QString &preloadedContext = QString()) const;
    QString buildFinalPrompt(const QString &userText, const QString &toolCall,
                             const QString &toolResult) const;

    bool loadLogSearcher();
    bool loadWebSearcher();
    QString searchLogs(const QString &keyword);
    QString searchKnowledge(const QString &keyword);
    QString searchWeb(const QString &keyword);
    QString searchHistory(const QString &keyword);
    QString executeTool(const QString &toolName, const QString &argsJson);
    bool parseToolCall(const QString &reply, QString &outTool, QString &outArgs);

    void startWorker(const QString &systemPrompt, const QString &userPrompt, bool stream);
    void resetSendButton();
    static QString mdToHtml(const QString &markdown);
    static QString makeId();

    /* UI */
    QListWidget *m_chatList = nullptr;
    QTextBrowser *m_chat = nullptr;
    QLineEdit *m_input = nullptr;
    QPushButton *m_btnSend = nullptr;
    QPushButton *m_btnStop = nullptr;
    QPushButton *m_btnNew = nullptr;
    QPushButton *m_btnDelete = nullptr;
    QPushButton *m_btnClear = nullptr;
    QLabel *m_titleLabel = nullptr;

    /* State */
    QList<ChatSession> m_sessions;
    QString m_activeChatId;
    bool m_running = false;
    bool m_streaming = false;
    QString m_currentUserText;
    QString m_currentAiText;
    QString m_lastSystemPrompt;
    QString m_lastUserPrompt;
    int m_toolRound = 0;
    bool m_preloadedContext = false;
    bool m_loadAllMessages = false;

    /* AI config */
    QString m_apiKey;
    QString m_provider;
    QString m_endpoint;
    QString m_model;
    int m_inputContextLimit = 8192;
    int m_outputContextLimit = 4096;
    float m_temperature = 0.7f;

    /* Log search DLL */
    HMODULE m_logSearcherDll = nullptr;
    PFN_LogSrch_Search m_pfnLogSearch = nullptr;

    /* Web search DLL */
    HMODULE m_webSearcherDll = nullptr;
    PFN_WebSearch m_pfnWebSearch = nullptr;

    /* Worker / thread */
    QThread *m_thread = nullptr;
    AiWorker *m_worker = nullptr;

    /* Daemon prompt injection */
    QTimer *m_injectTimer = nullptr;
};
