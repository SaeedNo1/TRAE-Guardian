#include "ai_task_dialog.h"
#include "process_select_dialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLineEdit>
#include <QCheckBox>
#include <QSpinBox>
#include <QTextEdit>
#include <QLabel>
#include <QDialogButtonBox>
#include <QPushButton>
#include <QUuid>
#include <QDateTimeEdit>
#include <QGroupBox>

AiTaskDialog::AiTaskDialog(const TaskData &data, QWidget *parent)
    : QDialog(parent), m_data(data)
{
    setupUi();
    if (m_data.id.isEmpty()) m_data.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
}

void AiTaskDialog::setupUi()
{
    setWindowTitle(tr("AI Task"));
    resize(520, 580);
    QVBoxLayout *layout = new QVBoxLayout(this);

    QGroupBox *basicGroup = new QGroupBox(tr("Basic Settings"), this);
    QFormLayout *basicForm = new QFormLayout(basicGroup);

    m_nameEdit = new QLineEdit(m_data.name, this);
    basicForm->addRow(tr("Name:"), m_nameEdit);

    m_idEdit = new QLineEdit(m_data.id, this);
    m_idEdit->setReadOnly(true);
    basicForm->addRow(tr("ID:"), m_idEdit);

    m_enabledBox = new QCheckBox(tr("Enabled"), this);
    m_enabledBox->setChecked(m_data.enabled);
    basicForm->addRow(m_enabledBox);

    m_intervalEdit = new QSpinBox(this);
    m_intervalEdit->setRange(10, 86400);
    m_intervalEdit->setSuffix(" s");
    m_intervalEdit->setValue(m_data.readIntervalSec);
    basicForm->addRow(tr("Read interval:"), m_intervalEdit);

    m_bytesEdit = new QSpinBox(this);
    m_bytesEdit->setRange(256, 65536);
    m_bytesEdit->setSingleStep(256);
    m_bytesEdit->setValue(m_data.readBytes);
    basicForm->addRow(tr("Read bytes:"), m_bytesEdit);

    layout->addWidget(basicGroup);

    QGroupBox *timeGroup = new QGroupBox(tr("Time Settings"), this);
    QFormLayout *timeForm = new QFormLayout(timeGroup);

    m_startTimeEdit = new QDateTimeEdit(this);
    m_startTimeEdit->setDateTime(m_data.startTime.isValid() ? m_data.startTime : QDateTime::currentDateTime());
    m_startTimeEdit->setDisplayFormat("yyyy-MM-dd HH:mm:ss");
    m_startTimeEdit->setCalendarPopup(true);
    timeForm->addRow(tr("Start time:"), m_startTimeEdit);

    m_endTimeEdit = new QDateTimeEdit(this);
    m_endTimeEdit->setDateTime(m_data.endTime.isValid() ? m_data.endTime : QDateTime::currentDateTime().addDays(7));
    m_endTimeEdit->setDisplayFormat("yyyy-MM-dd HH:mm:ss");
    m_endTimeEdit->setCalendarPopup(true);
    timeForm->addRow(tr("End time:"), m_endTimeEdit);

    layout->addWidget(timeGroup);

    QGroupBox *aiGroup = new QGroupBox(tr("AI Settings"), this);
    QFormLayout *aiForm = new QFormLayout(aiGroup);

    m_providerEdit = new QLineEdit(m_data.provider, this);
    m_providerEdit->setPlaceholderText("api.siliconflow.cn");
    aiForm->addRow(tr("Provider:"), m_providerEdit);

    m_endpointEdit = new QLineEdit(m_data.endpoint, this);
    m_endpointEdit->setPlaceholderText("/v1/chat/completions");
    aiForm->addRow(tr("Endpoint:"), m_endpointEdit);

    m_modelEdit = new QLineEdit(m_data.model, this);
    m_modelEdit->setPlaceholderText("qwen-plus");
    aiForm->addRow(tr("Model:"), m_modelEdit);

    m_apiKeyEdit = new QLineEdit(m_data.apiKey, this);
    m_apiKeyEdit->setEchoMode(QLineEdit::Password);
    aiForm->addRow(tr("API Key:"), m_apiKeyEdit);

    layout->addWidget(aiGroup);

    QGroupBox *targetGroup = new QGroupBox(tr("Target Processes"), this);
    QVBoxLayout *targetLayout = new QVBoxLayout(targetGroup);
    QHBoxLayout *targetBtnLayout = new QHBoxLayout();
    QLabel *tzLabel = new QLabel(tr("Target process names (one per line):"), this);
    targetBtnLayout->addWidget(tzLabel);
    QPushButton *btnAddProcess = new QPushButton(tr("Add Process"), this);
    targetBtnLayout->addWidget(btnAddProcess);
    targetBtnLayout->addStretch();
    targetLayout->addLayout(targetBtnLayout);
    m_targetsEdit = new QTextEdit(this);
    m_targetsEdit->setPlainText(m_data.targets.join("\n"));
    targetLayout->addWidget(m_targetsEdit);
    layout->addWidget(targetGroup);

    connect(btnAddProcess, &QPushButton::clicked, this, [this]() {
        ProcessSelectDialog dlg(this);
        if (dlg.exec() != QDialog::Accepted) return;
        QStringList selected = dlg.selectedProcesses();
        if (selected.isEmpty()) return;
        QString current = m_targetsEdit->toPlainText();
        for (const QString &name : selected) {
            if (!current.contains(name, Qt::CaseInsensitive)) {
                if (!current.isEmpty()) current += "\n";
                current += name;
            }
        }
        m_targetsEdit->setPlainText(current);
    });

    QDialogButtonBox *buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, this);
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    layout->addWidget(buttons);
}

AiTaskDialog::TaskData AiTaskDialog::result() const
{
    TaskData d;
    d.name = m_nameEdit->text().trimmed();
    d.id = m_idEdit->text().trimmed();
    d.enabled = m_enabledBox->isChecked();
    d.readIntervalSec = m_intervalEdit->value();
    d.readBytes = m_bytesEdit->value();
    d.targets = m_targetsEdit->toPlainText().split('\n', Qt::SkipEmptyParts);
    for (QString &t : d.targets) t = t.trimmed();
    d.startTime = m_startTimeEdit->dateTime();
    d.endTime = m_endTimeEdit->dateTime();
    d.provider = m_providerEdit->text().trimmed();
    d.apiKey = m_apiKeyEdit->text().trimmed();
    d.model = m_modelEdit->text().trimmed();
    d.endpoint = m_endpointEdit->text().trimmed();
    return d;
}
