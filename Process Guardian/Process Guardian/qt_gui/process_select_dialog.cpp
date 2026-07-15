#include "process_select_dialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QListWidget>
#include <QPushButton>
#include <QHeaderView>
#include <windows.h>
#include <tlhelp32.h>
#include <QString>

ProcessSelectDialog::ProcessSelectDialog(QWidget *parent)
    : QDialog(parent)
{
    setupUi();
    loadProcesses();
}

void ProcessSelectDialog::setupUi()
{
    setWindowTitle(tr("Select Processes"));
    resize(480, 400);

    QVBoxLayout *layout = new QVBoxLayout(this);

    m_processList = new QListWidget(this);
    m_processList->setSelectionMode(QAbstractItemView::ExtendedSelection);
    layout->addWidget(m_processList);

    QHBoxLayout *btnLayout = new QHBoxLayout();

    m_btnSelectAll = new QPushButton(tr("Select All"), this);
    m_btnDeselectAll = new QPushButton(tr("Deselect All"), this);
    btnLayout->addWidget(m_btnSelectAll);
    btnLayout->addWidget(m_btnDeselectAll);
    btnLayout->addStretch();

    m_btnOK = new QPushButton(tr("OK"), this);
    m_btnCancel = new QPushButton(tr("Cancel"), this);
    btnLayout->addWidget(m_btnOK);
    btnLayout->addWidget(m_btnCancel);

    layout->addLayout(btnLayout);

    connect(m_btnSelectAll, &QPushButton::clicked, m_processList, &QListWidget::selectAll);
    connect(m_btnDeselectAll, &QPushButton::clicked, m_processList, &QListWidget::clearSelection);
    connect(m_btnOK, &QPushButton::clicked, this, &QDialog::accept);
    connect(m_btnCancel, &QPushButton::clicked, this, &QDialog::reject);
}

void ProcessSelectDialog::loadProcesses()
{
    m_processList->clear();

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return;
    }

    QStringList names;
    do {
        QString name = QString::fromWCharArray(pe32.szExeFile);
        if (!names.contains(name, Qt::CaseInsensitive)) {
            names.append(name);
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);

    names.sort(Qt::CaseInsensitive);
    for (const QString &name : names) {
        m_processList->addItem(name);
    }
}

QStringList ProcessSelectDialog::selectedProcesses() const
{
    QStringList result;
    for (const QListWidgetItem *item : m_processList->selectedItems()) {
        result.append(item->text());
    }
    return result;
}