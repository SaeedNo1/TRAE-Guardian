#pragma once

#include <QDialog>
#include <QString>
#include <QStringList>
#include <QDateTime>

class AiTaskDialog : public QDialog
{
    Q_OBJECT
public:
    struct TaskData {
        QString name;
        QString id;
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

    explicit AiTaskDialog(const TaskData &data, QWidget *parent = nullptr);
    TaskData result() const;

private:
    void setupUi();

    TaskData m_data;
    class QLineEdit *m_nameEdit = nullptr;
    class QLineEdit *m_idEdit = nullptr;
    class QCheckBox *m_enabledBox = nullptr;
    class QSpinBox *m_intervalEdit = nullptr;
    class QSpinBox *m_bytesEdit = nullptr;
    class QTextEdit *m_targetsEdit = nullptr;
    class QDateTimeEdit *m_startTimeEdit = nullptr;
    class QDateTimeEdit *m_endTimeEdit = nullptr;
    class QLineEdit *m_providerEdit = nullptr;
    class QLineEdit *m_apiKeyEdit = nullptr;
    class QLineEdit *m_modelEdit = nullptr;
    class QLineEdit *m_endpointEdit = nullptr;
};
