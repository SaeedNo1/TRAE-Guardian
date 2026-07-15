#include "aihubtab.h"
#include "mainwindow.h"
#include "ai_task_dialog.h"
#include "taskchatdialog.h"
#include "aiworker.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QLabel>
#include <QTreeWidget>
#include <QTableWidget>
#include <QHeaderView>
#include <QMessageBox>
#include <QFile>
#include <QThread>
#include <QTextStream>
#include <QDir>
#include <QUuid>
#include <QRegularExpression>
#include <QDialog>
#include <QTextEdit>
#include <windows.h>

static QString moduleDir()
{
    wchar_t buf[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, buf, MAX_PATH);
    QString path = QString::fromWCharArray(buf);
    int idx = path.lastIndexOf('\\');
    return idx >= 0 ? path.left(idx) : QDir::currentPath();
}

AiHubTab::AiHubTab(QWidget *parent)
    : QWidget(parent)
{
    setupUi();
    loadSettings();
    loadTasks();
}

void AiHubTab::setupUi()
{
    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setContentsMargins(8, 8, 8, 8);

    /* AI settings */
    QGroupBox *settingsGroup = new QGroupBox(tr("AI Settings"), this);
    QGridLayout *settingsGrid = new QGridLayout(settingsGroup);

    settingsGrid->addWidget(new QLabel(tr("Provider:"), this), 0, 0);
    m_providerEdit = new QComboBox(this);
    m_providerEdit->setEditable(true);
    m_providerEdit->addItems(QStringList()
        << "api.siliconflow.cn"
        << "api.openai.com"
        << "api.deepseek.com"
        << "api.anthropic.com"
        << "api.groq.com");
    settingsGrid->addWidget(m_providerEdit, 0, 1);

    settingsGrid->addWidget(new QLabel(tr("Endpoint:"), this), 1, 0);
    m_endpointEdit = new QLineEdit(this);
    m_endpointEdit->setPlaceholderText("/v1/chat/completions");
    settingsGrid->addWidget(m_endpointEdit, 1, 1);

    settingsGrid->addWidget(new QLabel(tr("Model:"), this), 2, 0);
    m_modelEdit = new QLineEdit(this);
    m_modelEdit->setPlaceholderText("qwen-plus");
    settingsGrid->addWidget(m_modelEdit, 2, 1);

    settingsGrid->addWidget(new QLabel(tr("API Key:"), this), 3, 0);
    QHBoxLayout *keyLayout = new QHBoxLayout();
    keyLayout->setSpacing(4);
    m_apiKeyEdit = new QLineEdit(this);
    m_apiKeyEdit->setEchoMode(QLineEdit::Password);
    QPushButton *btnEye = new QPushButton(this);
    btnEye->setCheckable(true);
    btnEye->setText(tr("Show"));
    btnEye->setToolTip(tr("Toggle API key visibility"));
    btnEye->setStyleSheet(
        "QPushButton { background: transparent; color: #007aff; border: 1px solid #c7c7cc; "
        "border-radius: 6px; padding: 2px 10px; font-size: 12px; }"
        "QPushButton:checked { background: #007aff; color: white; border-color: #007aff; }");
    connect(btnEye, &QPushButton::toggled, this, [this, btnEye](bool checked) {
        m_apiKeyEdit->setEchoMode(checked ? QLineEdit::Normal : QLineEdit::Password);
        btnEye->setText(checked ? tr("Hide") : tr("Show"));
    });
    keyLayout->addWidget(m_apiKeyEdit, 1);
    keyLayout->addWidget(btnEye);
    settingsGrid->addLayout(keyLayout, 3, 1);

    settingsGrid->addWidget(new QLabel(tr("API URL:"), this), 4, 0);
    m_apiUrlLabel = new QLabel("https://", this);
    m_apiUrlLabel->setWordWrap(true);
    m_apiUrlLabel->setStyleSheet("color: #8e8e93; font-size: 12px;");
    settingsGrid->addWidget(m_apiUrlLabel, 4, 1);

    settingsGrid->addWidget(new QLabel(tr("Input context limit:"), this), 5, 0);
    m_inputLimitEdit = new QLineEdit(this);
    m_inputLimitEdit->setPlaceholderText("8192");
    settingsGrid->addWidget(m_inputLimitEdit, 5, 1);

    settingsGrid->addWidget(new QLabel(tr("Output context limit:"), this), 6, 0);
    m_outputLimitEdit = new QLineEdit(this);
    m_outputLimitEdit->setPlaceholderText("4096");
    settingsGrid->addWidget(m_outputLimitEdit, 6, 1);

    settingsGrid->addWidget(new QLabel(tr("Temperature:"), this), 7, 0);
    m_temperatureEdit = new QLineEdit(this);
    m_temperatureEdit->setPlaceholderText("0.70");
    settingsGrid->addWidget(m_temperatureEdit, 7, 1);

    QHBoxLayout *settingsBtnLayout = new QHBoxLayout();
    settingsBtnLayout->addStretch();
    m_btnTest = new QPushButton(tr("Test connection"), this);
    m_btnSaveSettings = new QPushButton(tr("Save settings"), this);
    settingsBtnLayout->addWidget(m_btnTest);
    settingsBtnLayout->addWidget(m_btnSaveSettings);
    settingsGrid->addLayout(settingsBtnLayout, 8, 0, 1, 2);
    layout->addWidget(settingsGroup);

    /* AI Analysis Log viewer */
    QGroupBox *analysisGroup = new QGroupBox(tr("AI Analysis Log"), this);
    QVBoxLayout *analysisLayout = new QVBoxLayout(analysisGroup);
    QLabel *analysisLabel = new QLabel(tr("Recent AI-evaluated suspicious events from the daemon."), this);
    analysisLabel->setWordWrap(true);
    analysisLabel->setStyleSheet("color: #8e8e93; font-size: 12px;");
    analysisLayout->addWidget(analysisLabel);
    QHBoxLayout *analysisBtnLayout = new QHBoxLayout();
    analysisBtnLayout->addStretch();
    m_btnShowAiAnalysisLog = new QPushButton(tr("View AI Analysis Log"), this);
    analysisBtnLayout->addWidget(m_btnShowAiAnalysisLog);
    analysisLayout->addLayout(analysisBtnLayout);
    layout->addWidget(analysisGroup);
    connect(m_btnShowAiAnalysisLog, &QPushButton::clicked, this, &AiHubTab::onShowAiAnalysisLog);

    /* Task list */
    QLabel *taskLabel = new QLabel(tr("Active AI tasks: select a task to enable chat / edit / delete"), this);
    layout->addWidget(taskLabel);

    QHBoxLayout *contentLayout = new QHBoxLayout();
    m_taskTree = new QTreeWidget(this);
    m_taskTree->setColumnCount(4);
    m_taskTree->setHeaderLabels(QStringList() << tr("ID") << tr("Name") << tr("Targets") << tr("Status"));
    m_taskTree->header()->setStretchLastSection(true);
    contentLayout->addWidget(m_taskTree, 3);

    QVBoxLayout *btnLayout = new QVBoxLayout();
    m_btnAdd = new QPushButton(tr("Add Task"), this);
    m_btnTalk = new QPushButton(tr("Talk to AI"), this);
    m_btnEdit = new QPushButton(tr("Edit"), this);
    m_btnDelete = new QPushButton(tr("Delete"), this);
    m_btnRefresh = new QPushButton(tr("Refresh"), this);
    m_btnGlobalChat = new QPushButton(tr("Global Chat"), this);

    m_btnTalk->setEnabled(false);
    m_btnEdit->setEnabled(false);
    m_btnDelete->setEnabled(false);

    btnLayout->addWidget(m_btnAdd);
    btnLayout->addWidget(m_btnTalk);
    btnLayout->addLayout([this]() {
        QHBoxLayout *l = new QHBoxLayout();
        l->addWidget(m_btnEdit);
        l->addWidget(m_btnDelete);
        return l;
    }());
    btnLayout->addWidget(m_btnRefresh);
    btnLayout->addStretch();
    btnLayout->addWidget(m_btnGlobalChat);
    contentLayout->addLayout(btnLayout, 1);
    layout->addLayout(contentLayout, 1);

    connect(m_btnSaveSettings, &QPushButton::clicked, this, &AiHubTab::onSaveSettings);
    connect(m_btnTest, &QPushButton::clicked, this, &AiHubTab::onTestConnection);
    connect(m_taskTree, &QTreeWidget::itemSelectionChanged, this, &AiHubTab::onTaskSelectionChanged);
    connect(m_btnAdd, &QPushButton::clicked, this, &AiHubTab::onAddTask);
    connect(m_btnTalk, &QPushButton::clicked, this, &AiHubTab::onTalkToAi);
    connect(m_btnEdit, &QPushButton::clicked, this, &AiHubTab::onEditTask);
    connect(m_btnDelete, &QPushButton::clicked, this, &AiHubTab::onDeleteTask);
    connect(m_btnRefresh, &QPushButton::clicked, this, &AiHubTab::refresh);
    connect(m_btnGlobalChat, &QPushButton::clicked, this, &AiHubTab::onGlobalChat);
    connect(m_taskTree, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem*, int) { onEditTask(); });

    auto updatePreview = [this]() { updateApiUrlPreview(); };
    connect(m_providerEdit->lineEdit(), &QLineEdit::textEdited, this, updatePreview);
    connect(m_endpointEdit, &QLineEdit::textEdited, this, updatePreview);

    /* Knowledge base editors */
    QGroupBox *knowledgeGroup = new QGroupBox(tr("AI Knowledge Base"), this);
    QVBoxLayout *knowledgeLayout = new QVBoxLayout(knowledgeGroup);
    QTabWidget *knowledgeTabs = new QTabWidget(this);

    m_soulEdit = new QTextEdit(this);
    m_soulEdit->setAcceptRichText(false);
    m_soulEdit->setPlaceholderText(tr("Edit SOUL.md (AI personality, role, permissions, operating rules)..."));
    knowledgeTabs->addTab(m_soulEdit, tr("SOUL.md"));

    m_knowledgeEdit = new QTextEdit(this);
    m_knowledgeEdit->setAcceptRichText(false);
    m_knowledgeEdit->setPlaceholderText(tr("Edit ai_knowledge.md (rogue software signatures, behavior patterns, reputation data)..."));
    knowledgeTabs->addTab(m_knowledgeEdit, tr("ai_knowledge.md"));

    m_systemPromptEdit = new QTextEdit(this);
    m_systemPromptEdit->setAcceptRichText(false);
    m_systemPromptEdit->setPlaceholderText(tr("Edit system_prompt.txt (AI role, permissions, personality). The app will append tool instructions and threat-rating rules automatically."));
    knowledgeTabs->addTab(m_systemPromptEdit, tr("System Prompt"));

    knowledgeLayout->addWidget(knowledgeTabs);
    QHBoxLayout *knowledgeBtnLayout = new QHBoxLayout();
    knowledgeBtnLayout->addStretch();
    m_btnSaveSoul = new QPushButton(tr("Save SOUL.md"), this);
    m_btnSaveKnowledge = new QPushButton(tr("Save ai_knowledge.md"), this);
    m_btnSaveSystemPrompt = new QPushButton(tr("Save System Prompt"), this);
    knowledgeBtnLayout->addWidget(m_btnSaveSoul);
    knowledgeBtnLayout->addWidget(m_btnSaveKnowledge);
    knowledgeBtnLayout->addWidget(m_btnSaveSystemPrompt);
    knowledgeLayout->addLayout(knowledgeBtnLayout);
    layout->addWidget(knowledgeGroup);

    connect(m_btnSaveSoul, &QPushButton::clicked, this, &AiHubTab::onSaveSoul);
    connect(m_btnSaveKnowledge, &QPushButton::clicked, this, &AiHubTab::onSaveKnowledge);
    connect(m_btnSaveSystemPrompt, &QPushButton::clicked, this, &AiHubTab::onSaveSystemPrompt);

    loadKnowledgeFiles();
    loadSystemPromptFile();
}

void AiHubTab::updateApiUrlPreview()
{
    QString provider = cleanProvider(m_providerEdit->currentText());
    QString endpoint = cleanEndpoint(m_endpointEdit->text());
    m_apiUrlLabel->setText("https://" + provider + endpoint);
}

QString AiHubTab::cleanProvider(const QString &input)
{
    QString p = input.trimmed();
    if (p.startsWith("http://", Qt::CaseInsensitive)) p = p.mid(7);
    if (p.startsWith("https://", Qt::CaseInsensitive)) p = p.mid(8);
    int slash = p.indexOf('/');
    if (slash >= 0) p = p.left(slash);
    return p;
}

QString AiHubTab::cleanEndpoint(const QString &input)
{
    QString e = input.trimmed();
    if (e.startsWith("http://", Qt::CaseInsensitive) || e.startsWith("https://", Qt::CaseInsensitive)) {
        int slash3 = e.indexOf('/', 8);
        if (slash3 >= 0) e = e.mid(slash3);
    }
    if (!e.isEmpty() && !e.startsWith('/')) e = "/" + e;
    return e;
}

QString AiHubTab::taskFilePath() const
{
    return QDir(moduleDir()).filePath("data/ai_tasks.json");
}

void AiHubTab::loadSettings()
{
    QString path = QDir(moduleDir()).filePath("data/ai_config.txt");
    QFile f(path);
    QString provider = "api.siliconflow.cn";
    QString endpoint = "/v1/chat/completions";
    QString model = "qwen-plus";
    QString key;
    int inputLimit = 8192;
    int outputLimit = 4096;
    float temperature = 0.7f;
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
            if (k == "provider") provider = v;
            else if (k == "endpoint") endpoint = v;
            else if (k == "model") model = v;
            else if (k == "api_key") key = v;
            else if (k == "input_context_limit") inputLimit = qMax(0, v.toInt());
            else if (k == "output_context_limit") outputLimit = qMax(0, v.toInt());
            else if (k == "temperature") temperature = qBound(0.0f, v.toFloat(), 2.0f);
        }
    }
    m_providerEdit->setCurrentText(provider);
    m_endpointEdit->setText(endpoint);
    m_modelEdit->setText(model);
    m_apiKeyEdit->setText(key);
    m_inputLimitEdit->setText(QString::number(inputLimit));
    m_outputLimitEdit->setText(QString::number(outputLimit));
    m_temperatureEdit->setText(QString::number(temperature, 'f', 2));
    updateApiUrlPreview();
}

void AiHubTab::saveSettings()
{
    QString path = QDir(moduleDir()).filePath("data/ai_config.txt");
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Error"), tr("Failed to save AI settings."));
        return;
    }
    QString provider = cleanProvider(m_providerEdit->currentText());
    QString endpoint = cleanEndpoint(m_endpointEdit->text());
    QString model = m_modelEdit->text().trimmed();
    QString key = m_apiKeyEdit->text().trimmed();
    /* Remove common invisible characters that can sneak in from copy/paste */
    key.remove('\n').remove('\r').remove('\t').remove(' ');

    int inputLimit = m_inputLimitEdit->text().toInt();
    if (inputLimit <= 0) inputLimit = 8192;
    int outputLimit = m_outputLimitEdit->text().toInt();
    if (outputLimit <= 0) outputLimit = 4096;
    float temperature = m_temperatureEdit->text().toFloat();
    temperature = qBound(0.0f, temperature, 2.0f);

    QTextStream out(&f);
    out.setEncoding(QStringConverter::Utf8);
    out << "# AI provider configuration\n";
    out << "provider=" << provider << "\n";
    out << "endpoint=" << endpoint << "\n";
    out << "model=" << model << "\n";
    out << "api_key=" << key << "\n";
    out << "input_context_limit=" << inputLimit << "\n";
    out << "output_context_limit=" << outputLimit << "\n";
    out << "temperature=" << QString::number(temperature, 'f', 2) << "\n";

    m_providerEdit->setCurrentText(provider);
    m_endpointEdit->setText(endpoint);
    m_apiKeyEdit->setText(key);
    m_inputLimitEdit->setText(QString::number(inputLimit));
    m_outputLimitEdit->setText(QString::number(outputLimit));
    m_temperatureEdit->setText(QString::number(temperature, 'f', 2));
    updateApiUrlPreview();
    MainWindow::appLog(tr("AI settings saved from AI Hub"));
}

void AiHubTab::onSaveSettings()
{
    saveSettings();
    QMessageBox::information(this, tr("Settings"), tr("AI settings saved."));
}

void AiHubTab::onTestConnection()
{
    saveSettings();
    QString provider = cleanProvider(m_providerEdit->currentText());
    QString endpoint = cleanEndpoint(m_endpointEdit->text());
    QString model = m_modelEdit->text().trimmed();
    QString key = m_apiKeyEdit->text().trimmed();
    key.remove('\n').remove('\r').remove('\t').remove(' ');

    if (provider.isEmpty() || endpoint.isEmpty() || model.isEmpty() || key.isEmpty()) {
        QMessageBox::warning(this, tr("Test connection"), tr("Please fill in provider, endpoint, model and API key first."));
        return;
    }

    m_btnTest->setEnabled(false);
    m_btnTest->setText(tr("Testing..."));

    int inputLimit = m_inputLimitEdit->text().toInt();
    if (inputLimit <= 0) inputLimit = 8192;
    int outputLimit = m_outputLimitEdit->text().toInt();
    if (outputLimit <= 0) outputLimit = 4096;
    float temperature = m_temperatureEdit->text().toFloat();
    temperature = qBound(0.0f, temperature, 2.0f);

    QThread *thread = new QThread(this);
    AiWorker *worker = new AiWorker("", "hi", key, provider, endpoint, model, false,
                                     inputLimit, outputLimit, temperature);
    worker->moveToThread(thread);
    connect(thread, &QThread::started, worker, &AiWorker::process);
    connect(worker, &AiWorker::resultReady, this, [this](const QString &reply, int rc) {
        m_btnTest->setEnabled(true);
        m_btnTest->setText(tr("Test connection"));
        if (rc > 0) {
            QMessageBox::information(this, tr("Test connection"), tr("Connection successful. Model replied:\n%1").arg(reply.left(200)));
        } else {
            QMessageBox::warning(this, tr("Test connection"), tr("Connection failed (code %1):\n%2").arg(rc).arg(reply));
        }
    });
    connect(worker, &AiWorker::resultReady, thread, &QThread::quit);
    connect(worker, &AiWorker::resultReady, worker, &AiWorker::deleteLater);
    connect(thread, &QThread::finished, thread, &QThread::deleteLater);
    thread->start();
}

void AiHubTab::refresh()
{
    loadTasks();
}

void AiHubTab::loadTasks()
{
    m_tasks.clear();
    m_taskTree->clear();

    QFile f(taskFilePath());
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return;
    QString text = QString::fromUtf8(f.readAll());
    f.close();

    int idx = text.indexOf("\"tasks\"");
    if (idx < 0) return;
    idx = text.indexOf('[', idx);
    if (idx < 0) return;

    bool hasExpired = false;

    int depth = 0;
    bool inString = false;
    bool escape = false;
    int objStart = -1;
    for (int i = idx; i < text.size(); ++i) {
        QChar c = text[i];
        if (escape) { escape = false; continue; }
        if (c == '\\') { escape = true; continue; }
        if (c == '"') { inString = !inString; continue; }
        if (inString) continue;
        if (c == '[') { depth++; continue; }
        if (c == ']') { depth--; if (depth == 0) break; continue; }
        if (c == '{' && depth == 1) { objStart = i; continue; }
        if (c == '}' && depth == 1 && objStart >= 0) {
            QString obj = text.mid(objStart, i - objStart + 1);
            AiHubTask t;
            QRegularExpression reId("\"id\"\\s*:\\s*\"([^\"]*)\"");
            QRegularExpression reName("\"name\"\\s*:\\s*\"([^\"]*)\"");
            QRegularExpression reEnabled("\"enabled\"\\s*:\\s*(true|false)");
            QRegularExpression reInterval("\"readIntervalSec\"\\s*:\\s*(\\d+)");
            QRegularExpression reBytes("\"readBytes\"\\s*:\\s*(\\d+)");
            QRegularExpression reStartTime("\"startTime\"\\s*:\\s*\"([^\"]*)\"");
            QRegularExpression reEndTime("\"endTime\"\\s*:\\s*\"([^\"]*)\"");
            QRegularExpression reProvider("\"provider\"\\s*:\\s*\"([^\"]*)\"");
            QRegularExpression reApiKey("\"apiKey\"\\s*:\\s*\"([^\"]*)\"");
            QRegularExpression reModel("\"model\"\\s*:\\s*\"([^\"]*)\"");
            QRegularExpression reEndpoint("\"endpoint\"\\s*:\\s*\"([^\"]*)\"");
            auto m = reId.match(obj);
            if (m.hasMatch()) t.id = m.captured(1);
            m = reName.match(obj);
            if (m.hasMatch()) t.name = m.captured(1);
            m = reEnabled.match(obj);
            if (m.hasMatch()) t.enabled = m.captured(1).compare("true", Qt::CaseInsensitive) == 0;
            m = reInterval.match(obj);
            if (m.hasMatch()) t.readIntervalSec = m.captured(1).toInt();
            m = reBytes.match(obj);
            if (m.hasMatch()) t.readBytes = m.captured(1).toInt();
            m = reStartTime.match(obj);
            if (m.hasMatch()) t.startTime = QDateTime::fromString(m.captured(1), "yyyy-MM-dd HH:mm:ss");
            m = reEndTime.match(obj);
            if (m.hasMatch()) t.endTime = QDateTime::fromString(m.captured(1), "yyyy-MM-dd HH:mm:ss");
            m = reProvider.match(obj);
            if (m.hasMatch()) t.provider = m.captured(1);
            m = reApiKey.match(obj);
            if (m.hasMatch()) t.apiKey = m.captured(1);
            m = reModel.match(obj);
            if (m.hasMatch()) t.model = m.captured(1);
            m = reEndpoint.match(obj);
            if (m.hasMatch()) t.endpoint = m.captured(1);

            QRegularExpression reTargets("\"targets\"\\s*:\\s*\\[(.*?)\\]", QRegularExpression::DotMatchesEverythingOption);
            auto tm = reTargets.match(obj);
            if (tm.hasMatch()) {
                QRegularExpression reTname("\"name\"\\s*:\\s*\"([^\"]*)\"");
                auto it = reTname.globalMatch(tm.captured(1));
                while (it.hasNext()) { t.targets.append(it.next().captured(1)); }
            }

            if (t.endTime.isValid() && t.endTime < QDateTime::currentDateTime()) {
                hasExpired = true;
                objStart = -1;
                continue;
            }

            m_tasks.append(t);
            QTreeWidgetItem *item = new QTreeWidgetItem(m_taskTree);
            item->setText(0, t.id);
            item->setText(1, t.name);
            item->setText(2, t.targets.join(", "));
            QString status = t.enabled ? tr("Active") : tr("Disabled");
            item->setText(3, status);
            objStart = -1;
        }
    }

    if (hasExpired) {
        saveTasks();
    }

    onTaskSelectionChanged();
}

void AiHubTab::saveTasks()
{
    QString json = "{\n  \"tasks\": [\n";
    for (int i = 0; i < m_tasks.size(); ++i) {
        const AiHubTask &t = m_tasks[i];
        json += "    {\n";
        json += QString("      \"id\": \"%1\",\n").arg(t.id);
        json += QString("      \"name\": \"%1\",\n").arg(t.name);
        json += QString("      \"enabled\": %1,\n").arg(t.enabled ? "true" : "false");
        json += QString("      \"readIntervalSec\": %1,\n").arg(t.readIntervalSec);
        json += QString("      \"readBytes\": %1,\n").arg(t.readBytes);
        json += QString("      \"startTime\": \"%1\",\n").arg(t.startTime.toString("yyyy-MM-dd HH:mm:ss"));
        json += QString("      \"endTime\": \"%1\",\n").arg(t.endTime.toString("yyyy-MM-dd HH:mm:ss"));
        json += QString("      \"provider\": \"%1\",\n").arg(t.provider);
        json += QString("      \"apiKey\": \"%1\",\n").arg(t.apiKey);
        json += QString("      \"model\": \"%1\",\n").arg(t.model);
        json += QString("      \"endpoint\": \"%1\",\n").arg(t.endpoint);
        json += "      \"memoryFile\": \"\",\n";
        json += "      \"soulFile\": \"\",\n";
        json += "      \"targets\": [\n";
        for (int j = 0; j < t.targets.size(); ++j) {
            json += QString("        {\"name\":\"%1\",\"type\":\"process\",\"pid\":0,\"tree\":false}").arg(t.targets[j]);
            if (j < t.targets.size() - 1) json += ",";
            json += "\n";
        }
        json += "      ]\n";
        json += "    }";
        if (i < m_tasks.size() - 1) json += ",";
        json += "\n";
    }
    json += "  ]\n}\n";

    QFile f(taskFilePath());
    if (f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&f);
        out.setEncoding(QStringConverter::Utf8);
        out << json;
    }
    loadTasks();
}

AiHubTask AiHubTab::currentTask() const
{
    int idx = m_taskTree->currentIndex().row();
    if (idx < 0 || idx >= m_tasks.size()) return AiHubTask();
    return m_tasks[idx];
}

void AiHubTab::onTaskSelectionChanged()
{
    bool hasSelection = m_taskTree->currentIndex().row() >= 0;
    m_btnTalk->setEnabled(hasSelection);
    m_btnEdit->setEnabled(hasSelection);
    m_btnDelete->setEnabled(hasSelection);
}

void AiHubTab::onAddTask()
{
    AiTaskDialog::TaskData data;
    data.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
    data.provider = m_providerEdit->currentText();
    data.endpoint = m_endpointEdit->text();
    data.model = m_modelEdit->text();
    data.apiKey = m_apiKeyEdit->text();
    data.startTime = QDateTime::currentDateTime();
    data.endTime = QDateTime::currentDateTime().addDays(7);
    AiTaskDialog dlg(data, this);
    if (dlg.exec() != QDialog::Accepted) return;
    auto r = dlg.result();
    AiHubTask t;
    t.name = r.name;
    t.id = r.id;
    t.enabled = r.enabled;
    t.readIntervalSec = r.readIntervalSec;
    t.readBytes = r.readBytes;
    t.targets = r.targets;
    t.startTime = r.startTime;
    t.endTime = r.endTime;
    t.provider = r.provider;
    t.apiKey = r.apiKey;
    t.model = r.model;
    t.endpoint = r.endpoint;
    m_tasks.append(t);
    saveTasks();
    MainWindow::appLog(tr("Added AI task: %1").arg(t.name));
}

void AiHubTab::createTaskWithProcess(const QString &processName)
{
    AiTaskDialog::TaskData data;
    data.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
    data.provider = m_providerEdit->currentText();
    data.endpoint = m_endpointEdit->text();
    data.model = m_modelEdit->text();
    data.apiKey = m_apiKeyEdit->text();
    data.startTime = QDateTime::currentDateTime();
    data.endTime = QDateTime::currentDateTime().addDays(7);
    data.targets = QStringList() << processName;
    data.name = tr("Monitor %1").arg(processName);
    AiTaskDialog dlg(data, this);
    if (dlg.exec() != QDialog::Accepted) return;
    auto r = dlg.result();
    AiHubTask t;
    t.name = r.name;
    t.id = r.id;
    t.enabled = r.enabled;
    t.readIntervalSec = r.readIntervalSec;
    t.readBytes = r.readBytes;
    t.targets = r.targets;
    t.startTime = r.startTime;
    t.endTime = r.endTime;
    t.provider = r.provider;
    t.apiKey = r.apiKey;
    t.model = r.model;
    t.endpoint = r.endpoint;
    m_tasks.append(t);
    saveTasks();
    MainWindow::appLog(tr("Added AI task for process: %1").arg(processName));
}

void AiHubTab::onEditTask()
{
    int idx = m_taskTree->currentIndex().row();
    if (idx < 0 || idx >= m_tasks.size()) return;
    AiTaskDialog::TaskData data;
    data.name = m_tasks[idx].name;
    data.id = m_tasks[idx].id;
    data.enabled = m_tasks[idx].enabled;
    data.readIntervalSec = m_tasks[idx].readIntervalSec;
    data.readBytes = m_tasks[idx].readBytes;
    data.targets = m_tasks[idx].targets;
    data.startTime = m_tasks[idx].startTime;
    data.endTime = m_tasks[idx].endTime;
    data.provider = m_tasks[idx].provider;
    data.apiKey = m_tasks[idx].apiKey;
    data.model = m_tasks[idx].model;
    data.endpoint = m_tasks[idx].endpoint;
    AiTaskDialog dlg(data, this);
    if (dlg.exec() != QDialog::Accepted) return;
    auto r = dlg.result();
    m_tasks[idx].name = r.name;
    m_tasks[idx].id = r.id;
    m_tasks[idx].enabled = r.enabled;
    m_tasks[idx].readIntervalSec = r.readIntervalSec;
    m_tasks[idx].readBytes = r.readBytes;
    m_tasks[idx].targets = r.targets;
    m_tasks[idx].startTime = r.startTime;
    m_tasks[idx].endTime = r.endTime;
    m_tasks[idx].provider = r.provider;
    m_tasks[idx].apiKey = r.apiKey;
    m_tasks[idx].model = r.model;
    m_tasks[idx].endpoint = r.endpoint;
    saveTasks();
    MainWindow::appLog(tr("Updated AI task: %1").arg(r.name));
}

void AiHubTab::onDeleteTask()
{
    int idx = m_taskTree->currentIndex().row();
    if (idx < 0 || idx >= m_tasks.size()) return;
    if (QMessageBox::question(this, tr("Confirm"), tr("Delete task %1? Its chat memory will also be removed.").arg(m_tasks[idx].name)) != QMessageBox::Yes) return;
    QString name = m_tasks[idx].name;
    QString id = m_tasks[idx].id;
    m_tasks.removeAt(idx);
    saveTasks();
    /* Delete task memory file if exists */
    QString memPath = QDir(moduleDir()).filePath(QString("data/ai_memory/task_%1.log").arg(id));
    QFile::remove(memPath);
    MainWindow::appLog(tr("Deleted AI task: %1").arg(name));
}

void AiHubTab::onTalkToAi()
{
    AiHubTask t = currentTask();
    if (t.id.isEmpty()) return;
    TaskChatDialog dlg(t.id, t.name, t.targets, this);
    dlg.exec();
}

void AiHubTab::onGlobalChat()
{
    MainWindow::appLog(tr("Opened global AI chat from AI Hub"));
    /* Signal main window to switch to global chat tab */
    QWidget *w = this->parentWidget();
    while (w) {
        if (auto *mw = qobject_cast<class MainWindow*>(w)) {
            mw->openGlobalChat();
            return;
        }
        w = w->parentWidget();
    }
}

struct AiAnalysisEntry {
    QString timestamp;
    QString level;
    QString task;
    QString taskId;
    QString proc;
    QString path;
    QString reason;
    QString raw;
};

static QList<AiAnalysisEntry> parseAiAnalysisLog(const QString &text)
{
    QList<AiAnalysisEntry> list;
    QRegularExpression lineRe("^\\[([^\\]]+)\\]\\s+(.*)$");
    for (const QString &rawLine : text.split('\n')) {
        QString line = rawLine.trimmed();
        if (line.isEmpty()) continue;
        QRegularExpressionMatch m = lineRe.match(line);
        if (!m.hasMatch()) continue;
        AiAnalysisEntry e;
        e.timestamp = m.captured(1);
        e.raw = line;
        QString rest = m.captured(2);
        QRegularExpression kvRe("(\\w+)=(.*?)(?=\\s{2,}\\w+=|\\s*$)");
        QRegularExpressionMatchIterator it = kvRe.globalMatch(rest);
        while (it.hasNext()) {
            QRegularExpressionMatch km = it.next();
            QString k = km.captured(1);
            QString v = km.captured(2).trimmed();
            if (k == "level") e.level = v;
            else if (k == "task") e.task = v;
            else if (k == "task_id") e.taskId = v;
            else if (k == "proc") e.proc = v;
            else if (k == "path") e.path = v;
            else if (k == "reason") e.reason = v;
            else if (k == "type") e.level = v;
            else if (k == "name") e.proc = v;
            else if (k == "message") e.reason = v;
        }
        if (e.level.isEmpty()) e.level = "-";
        if (e.proc.isEmpty()) e.proc = "-";
        list.append(e);
    }
    return list;
}

void AiHubTab::onShowAiAnalysisLog()
{
    QString path = QDir(moduleDir()).filePath("data/ai_notifications.log");
    QFile f(path);
    QString text;
    if (f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream in(&f);
        in.setEncoding(QStringConverter::Utf8);
        text = in.readAll();
    }

    QDialog dlg(this);
    dlg.setWindowTitle(tr("AI Analysis Log"));
    dlg.setMinimumSize(900, 600);
    dlg.resize(1200, 800);

    QVBoxLayout *layout = new QVBoxLayout(&dlg);

    QTableWidget *table = new QTableWidget(&dlg);
    table->setColumnCount(7);
    table->setHorizontalHeaderLabels(QStringList()
        << tr("Timestamp") << tr("Level") << tr("Task") << tr("Task ID")
        << tr("Process") << tr("Path") << tr("Reason"));
    table->horizontalHeader()->setStretchLastSection(true);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setAlternatingRowColors(true);

    QList<AiAnalysisEntry> entries = parseAiAnalysisLog(text);
    table->setRowCount(entries.size());
    for (int i = 0; i < entries.size(); ++i) {
        const AiAnalysisEntry &e = entries[i];
        table->setItem(i, 0, new QTableWidgetItem(e.timestamp));
        table->setItem(i, 1, new QTableWidgetItem(e.level));
        table->setItem(i, 2, new QTableWidgetItem(e.task));
        table->setItem(i, 3, new QTableWidgetItem(e.taskId));
        table->setItem(i, 4, new QTableWidgetItem(e.proc));
        table->setItem(i, 5, new QTableWidgetItem(e.path));
        QTableWidgetItem *reasonItem = new QTableWidgetItem(e.reason.left(120));
        reasonItem->setToolTip(e.reason);
        reasonItem->setData(Qt::UserRole, e.raw);
        table->setItem(i, 6, reasonItem);
    }
    table->resizeColumnsToContents();
    layout->addWidget(table);

    QTextEdit *detailEdit = new QTextEdit(&dlg);
    detailEdit->setReadOnly(true);
    detailEdit->setPlainText(tr("Select a row to view the full raw entry."));
    detailEdit->setMaximumHeight(160);
    layout->addWidget(detailEdit);

    connect(table, &QTableWidget::itemSelectionChanged, [&]() {
        auto items = table->selectedItems();
        if (items.isEmpty()) return;
        QTableWidgetItem *reasonItem = table->item(items.first()->row(), 6);
        if (reasonItem) detailEdit->setPlainText(reasonItem->data(Qt::UserRole).toString());
    });

    QHBoxLayout *btnLayout = new QHBoxLayout();
    btnLayout->addStretch();
    QPushButton *btnOk = new QPushButton(tr("OK"), &dlg);
    connect(btnOk, &QPushButton::clicked, &dlg, &QDialog::accept);
    btnLayout->addWidget(btnOk);
    layout->addLayout(btnLayout);

    dlg.exec();
}

static QString soulFilePath()
{
    return QDir(moduleDir()).filePath("data/ai_memory/SOUL.md");
}

static QString knowledgeFilePath()
{
    return QDir(moduleDir()).filePath("data/ai_memory/ai_knowledge.md");
}

static QString systemPromptFilePath()
{
    return QDir(moduleDir()).filePath("data/ai_memory/system_prompt.txt");
}

void AiHubTab::loadKnowledgeFiles()
{
    auto load = [](const QString &path) -> QString {
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return QString();
        QTextStream in(&f);
        in.setEncoding(QStringConverter::Utf8);
        return in.readAll();
    };
    m_soulEdit->setPlainText(load(soulFilePath()));
    m_knowledgeEdit->setPlainText(load(knowledgeFilePath()));
}

void AiHubTab::saveTextFile(const QString &path, const QString &text)
{
    QDir().mkpath(QFileInfo(path).absolutePath());
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Error"), tr("Failed to write %1.").arg(path));
        return;
    }
    QTextStream out(&f);
    out.setEncoding(QStringConverter::Utf8);
    out << text;
    MainWindow::appLog(tr("Saved %1").arg(path));
}

void AiHubTab::onSaveSoul()
{
    saveTextFile(soulFilePath(), m_soulEdit->toPlainText());
    QMessageBox::information(this, tr("Saved"), tr("SOUL.md saved."));
}

void AiHubTab::onSaveKnowledge()
{
    saveTextFile(knowledgeFilePath(), m_knowledgeEdit->toPlainText());
    QMessageBox::information(this, tr("Saved"), tr("ai_knowledge.md saved."));
}

void AiHubTab::loadSystemPromptFile()
{
    QFile f(systemPromptFilePath());
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return;
    QTextStream in(&f);
    in.setEncoding(QStringConverter::Utf8);
    m_systemPromptEdit->setPlainText(in.readAll());
}

void AiHubTab::onSaveSystemPrompt()
{
    saveTextFile(systemPromptFilePath(), m_systemPromptEdit->toPlainText());
    QMessageBox::information(this, tr("Saved"), tr("System prompt saved. It will take effect on the next AI chat message."));
}
