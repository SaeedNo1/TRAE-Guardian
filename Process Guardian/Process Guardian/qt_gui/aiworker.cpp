#include "aiworker.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>
#include <QVariant>
#include <QByteArray>
#include <QDateTime>
#include <QCoreApplication>
#include <QFile>
#include <windows.h>

AiWorker::AiWorker(const QString &systemPrompt, const QString &userPrompt,
                   const QString &apiKey, const QString &provider,
                   const QString &endpoint, const QString &model,
                   bool stream,
                   int inputContextLimit, int outputContextLimit,
                   float temperature, QObject *parent)
    : QObject(parent), m_systemPrompt(systemPrompt), m_userPrompt(userPrompt),
      m_apiKey(apiKey), m_provider(provider), m_endpoint(endpoint),
      m_model(model), m_stream(stream),
      m_inputContextLimit(inputContextLimit), m_outputContextLimit(outputContextLimit),
      m_temperature(temperature), m_aborted(0)
{
    setProperty("aborted", QVariant(false));
}

void AiWorker::abort()
{
    m_aborted.storeRelease(1);
    setProperty("aborted", QVariant(true));
}

void AiWorker::appendChunk(const QString &chunk)
{
    m_streamBuffer += chunk;
}

static QString jsonEscape(const QString &s)
{
    QString out;
    out.reserve(s.length() + 16);
    for (QChar c : s) {
        if (c == '\\') out += "\\\\";
        else if (c == '"') out += "\\\"";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else out += c;
    }
    return out;
}

void AiWorker::process()
{
    if (m_aborted.loadAcquire()) {
        emit resultReady(QString(), -1);
        return;
    }

    /* Apply input context limit locally */
    QString sysPrompt = m_systemPrompt;
    QString usrPrompt = m_userPrompt;
    int totalLen = sysPrompt.length() + usrPrompt.length();
    if (m_inputContextLimit > 0 && totalLen > m_inputContextLimit) {
        int sysTarget = qMin(sysPrompt.length(), m_inputContextLimit / 4);
        int usrTarget = m_inputContextLimit - sysTarget;
        if (sysPrompt.length() > sysTarget) sysPrompt = sysPrompt.left(sysTarget) + "\n...";
        if (usrPrompt.length() > usrTarget) usrPrompt = usrPrompt.left(usrTarget) + "\n...";
    }

    /* Send the request to the SYSTEM daemon through the action pipe.
     * The daemon loads the API key and calls the AI service, so the GUI
     * itself has no network/API access. */
    QString json = QString("{\"cmd\":\"ai_ask\",\"apiKey\":\"%1\",\"systemPrompt\":\"%2\",\"userPrompt\":\"%3\","
                           "\"temperature\":%4,\"maxTokens\":%5}")
                   .arg(jsonEscape(m_apiKey), jsonEscape(sysPrompt), jsonEscape(usrPrompt))
                   .arg(m_temperature, 0, 'f', 2)
                   .arg(m_outputContextLimit > 0 ? m_outputContextLimit : 32768);
    QByteArray data = json.toUtf8();

    QFile debugLog(QString("%1/data/ai_worker_debug.log").arg(QCoreApplication::applicationDirPath()));
    if (debugLog.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
        debugLog.write(QString("[%1] send len=%2\n%3\n")
                       .arg(QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"))
                       .arg(data.size())
                       .arg(QString::fromUtf8(data)).toUtf8());
        debugLog.close();
    }

    HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\GuardianAIAction",
                               GENERIC_READ | GENERIC_WRITE,
                               0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        emit resultReady(tr("Failed to connect to daemon action pipe"), -1);
        return;
    }

    DWORD written = 0;
    WriteFile(hPipe, data.constData(), (DWORD)data.size(), &written, NULL);
    FlushFileBuffers(hPipe);

    char resp[262144] = {0};
    DWORD read = 0;
    
    HANDLE hEvents[2] = {hPipe, NULL};
    hEvents[1] = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (hEvents[1]) {
        SetWaitableTimer(hEvents[1], (LARGE_INTEGER*)-50000000LL, 0, NULL, NULL, FALSE);
    }
    
    DWORD waitResult = WaitForMultipleObjects(2, hEvents, FALSE, 60000);
    if (waitResult == WAIT_OBJECT_0) {
        ReadFile(hPipe, resp, sizeof(resp) - 1, &read, NULL);
    }
    
    if (hEvents[1]) {
        CancelWaitableTimer(hEvents[1]);
        CloseHandle(hEvents[1]);
    }
    
    CloseHandle(hPipe);
    
    if (waitResult != WAIT_OBJECT_0) {
        emit resultReady(tr("AI request timed out"), -2);
        return;
    }

    QString reply = QString::fromUtf8(resp, read);
    if (debugLog.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
        debugLog.write(QString("[%1] recv len=%2\n%3\n")
                       .arg(QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"))
                       .arg(reply.length())
                       .arg(reply).toUtf8());
        debugLog.close();
    }
    QJsonDocument doc = QJsonDocument::fromJson(reply.toUtf8());
    if (!doc.isObject()) {
        emit resultReady(reply.isEmpty() ? tr("Daemon returned empty response") : reply, -1);
        return;
    }
    QJsonObject obj = doc.object();
    bool ok = obj.value("ok").toBool();
    int httpStatus = obj.value("httpStatus").toInt();
    QString content = obj.value("content").toString();
    if (ok) {
        if (m_stream && !content.isEmpty()) {
            /* Simulate streaming: emit the reply in small chunks so the UI
             * shows the assistant message appearing character by character. */
            const int chunkSize = 4;
            for (int i = 0; i < content.length(); i += chunkSize) {
                if (m_aborted.loadAcquire()) break;
                QString chunk = content.mid(i, chunkSize);
                emit chunkReady(chunk);
                /* tiny delay to keep the UI responsive and visible */
                if (i + chunkSize < content.length())
                    Sleep(8);
            }
        }
        emit resultReady(content, httpStatus);
    } else {
        emit resultReady(content, httpStatus > 0 ? -httpStatus : -1);
    }
}
