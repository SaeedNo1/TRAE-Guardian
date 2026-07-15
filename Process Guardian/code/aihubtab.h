#pragma once

#include <QWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QPushButton>
#include <QTreeWidget>
#include <QLabel>
#include <QList>
#include <QTextEdit>
#include <QDateTime>

struct AiHubTask {
    QString id;
    QString name;
    bool enabled = true;
    int readIntervalSec = 300;
    int readBytes = 4096;
    QStringList targets;
    QDateTime startTime;
    QDateTime endTime;
    QString provider;
    QString apiKey;
    QString model;
    QString endpoint;
};

class AiHubTab : public QWidget
{
    Q_OBJECT

public:
    explicit AiHubTab(QWidget *parent = nullptr);

public slots:
    void refresh();
    void createTaskWithProcess(const QString &processName);

private slots:
    void onSaveSettings();
    void onTaskSelectionChanged();
    void onAddTask();
    void onEditTask();
    void onDeleteTask();
    void onTalkToAi();
    void onGlobalChat();
    void onTestConnection();
    void onSaveSoul();
    void onSaveKnowledge();
    void onSaveSystemPrompt();
    void onShowAiAnalysisLog();

private:
    void setupUi();
    void loadSettings();
    void saveSettings();
    void loadKnowledgeFiles();
    void loadSystemPromptFile();
    void saveTextFile(const QString &path, const QString &text);
    void updateApiUrlPreview();
    QString cleanProvider(const QString &input);
    QString cleanEndpoint(const QString &input);
    void loadTasks();
    void saveTasks();
    QString taskFilePath() const;
    AiHubTask currentTask() const;

    QComboBox *m_providerEdit = nullptr;
    QLineEdit *m_endpointEdit = nullptr;
    QLineEdit *m_modelEdit = nullptr;
    QLineEdit *m_apiKeyEdit = nullptr;
    QLineEdit *m_inputLimitEdit = nullptr;
    QLineEdit *m_outputLimitEdit = nullptr;
    QLineEdit *m_temperatureEdit = nullptr;
    QLabel *m_apiUrlLabel = nullptr;
    QPushButton *m_btnSaveSettings = nullptr;
    QPushButton *m_btnTest = nullptr;

    QTreeWidget *m_taskTree = nullptr;
    QPushButton *m_btnAdd = nullptr;
    QPushButton *m_btnTalk = nullptr;
    QPushButton *m_btnEdit = nullptr;
    QPushButton *m_btnDelete = nullptr;
    QPushButton *m_btnRefresh = nullptr;
    QPushButton *m_btnGlobalChat = nullptr;

    QTextEdit *m_soulEdit = nullptr;
    QTextEdit *m_knowledgeEdit = nullptr;
    QTextEdit *m_systemPromptEdit = nullptr;
    QPushButton *m_btnSaveSoul = nullptr;
    QPushButton *m_btnSaveKnowledge = nullptr;
    QPushButton *m_btnSaveSystemPrompt = nullptr;
    QPushButton *m_btnShowAiAnalysisLog = nullptr;

    QList<AiHubTask> m_tasks;
};
