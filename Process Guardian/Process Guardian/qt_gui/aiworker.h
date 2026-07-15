#pragma once

#include <QObject>
#include <QString>
#include <QAtomicInt>

class AiWorker : public QObject
{
    Q_OBJECT

public:
    explicit AiWorker(const QString &systemPrompt, const QString &userPrompt,
                      const QString &apiKey, const QString &provider,
                      const QString &endpoint, const QString &model,
                      bool stream,
                      int inputContextLimit, int outputContextLimit,
                      float temperature, QObject *parent = nullptr);

    void abort();
    void appendChunk(const QString &chunk);

signals:
    void chunkReady(const QString &chunk);
    void resultReady(const QString &reply, int rc);

public slots:
    void process();

private:
    QString m_systemPrompt;
    QString m_userPrompt;
    QString m_apiKey;
    QString m_provider;
    QString m_endpoint;
    QString m_model;
    bool m_stream;
    int m_inputContextLimit;
    int m_outputContextLimit;
    float m_temperature;
    QAtomicInt m_aborted;
    QString m_streamBuffer;
};
