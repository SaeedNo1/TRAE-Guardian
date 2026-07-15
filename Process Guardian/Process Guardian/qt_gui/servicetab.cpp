#include "servicetab.h"
#include "mainwindow.h"
#include <QVBoxLayout>
#include <QHeaderView>
#include <QMenu>
#include <QMessageBox>
#include <QDir>
#include <QProcess>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonParseError>
#include <QRegularExpression>
#include <windows.h>
#include <winsvc.h>

#pragma comment(lib, "advapi32.lib")

ServiceTab::ServiceTab(QWidget *parent)
    : QWidget(parent)
{
    setupUi();
    refresh();
}

ServiceTab::~ServiceTab()
{
}

void ServiceTab::setupUi()
{
    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setContentsMargins(8, 8, 8, 8);

    QHBoxLayout *btnLayout = new QHBoxLayout();
    m_btnRefresh = new QPushButton(tr("Refresh"), this);
    btnLayout->addWidget(m_btnRefresh);
    btnLayout->addStretch();
    layout->addLayout(btnLayout);

    m_table = new QTableWidget(this);
    m_table->setColumnCount(5);
    m_table->setHorizontalHeaderLabels(QStringList() << tr("Name") << tr("Display") << tr("Status") << tr("Start") << tr("Path"));
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->verticalHeader()->setVisible(false);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    m_table->setSortingEnabled(true);

    layout->addWidget(m_table);
    connect(m_table, &QTableWidget::customContextMenuRequested, this, &ServiceTab::onContextMenu);
    connect(m_btnRefresh, &QPushButton::clicked, this, &ServiceTab::refresh);
}

static QString sendPipeCommand(const QString &json, int maxResp = 65536)
{
    HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\GuardianAIAction",
                               GENERIC_READ | GENERIC_WRITE, 0, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) return QString();
    QByteArray data = json.toUtf8();
    DWORD written = 0;
    WriteFile(hPipe, data.constData(), (DWORD)data.size(), &written, NULL);
    FlushFileBuffers(hPipe);
    char *resp = (char*)malloc(maxResp);
    if (!resp) { CloseHandle(hPipe); return QString(); }
    memset(resp, 0, maxResp);
    DWORD read = 0;
    ReadFile(hPipe, resp, maxResp - 1, &read, NULL);
    CloseHandle(hPipe);
    QString reply = QString::fromUtf8(resp, read);
    free(resp);
    return reply;
}

void ServiceTab::refresh()
{
    m_table->setSortingEnabled(false);
    m_table->setRowCount(0);

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) {
        DWORD err = GetLastError();
        MainWindow::appLog(tr("SVC: Failed to open Service Control Manager, error=%1").arg(err));
        return;
    }

    DWORD bufSize = 0, needed = 0, count = 0, resumeHandle = 0;
    DWORD serviceType = SERVICE_WIN32 | SERVICE_DRIVER;
    
    EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, serviceType, SERVICE_STATE_ALL, NULL, 0, &bufSize, &count, &resumeHandle, NULL);
    
    LPENUM_SERVICE_STATUS_PROCESSW pServices = (LPENUM_SERVICE_STATUS_PROCESSW)malloc(bufSize);
    if (!pServices) {
        CloseServiceHandle(hSCM);
        MainWindow::appLog(tr("SVC: Failed to allocate memory, size=%1").arg(bufSize));
        return;
    }

    BOOL ok = EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, serviceType, SERVICE_STATE_ALL, (LPBYTE)pServices, bufSize, &bufSize, &count, &resumeHandle, NULL);
    DWORD err = GetLastError();
    
    if (!ok || count == 0) {
        MainWindow::appLog(tr("SVC: EnumServicesStatusEx failed, ok=%1 err=%2 count=%3").arg(ok).arg(err).arg(count));
        free(pServices);
        CloseServiceHandle(hSCM);
        return;
    }

    MainWindow::appLog(tr("SVC: Found %1 services").arg(count));

    m_table->setRowCount((int)count);
    int row = 0;
    for (DWORD i = 0; i < count; ++i) {
        QString name = QString::fromWCharArray(pServices[i].lpServiceName);
        QString display = QString::fromWCharArray(pServices[i].lpDisplayName);

        QString status = tr("Unknown");
        QString startType = tr("Unknown");
        QString path;

        SC_HANDLE hService = OpenServiceW(hSCM, pServices[i].lpServiceName, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
        if (hService) {
            SERVICE_STATUS ss = {0};
            if (QueryServiceStatus(hService, &ss)) {
                switch (ss.dwCurrentState) {
                case SERVICE_STOPPED: status = tr("Stopped"); break;
                case SERVICE_START_PENDING: status = tr("Starting"); break;
                case SERVICE_STOP_PENDING: status = tr("Stopping"); break;
                case SERVICE_RUNNING: status = tr("Running"); break;
                case SERVICE_CONTINUE_PENDING: status = tr("Continuing"); break;
                case SERVICE_PAUSE_PENDING: status = tr("Pausing"); break;
                case SERVICE_PAUSED: status = tr("Paused"); break;
                }
            }

            DWORD configBufSize = 0;
            QueryServiceConfigW(hService, NULL, 0, &configBufSize);
            LPQUERY_SERVICE_CONFIG pConfig = (LPQUERY_SERVICE_CONFIG)malloc(configBufSize);
            if (pConfig && QueryServiceConfigW(hService, pConfig, configBufSize, &configBufSize)) {
                switch (pConfig->dwStartType) {
                case SERVICE_AUTO_START: startType = tr("Automatic"); break;
                case SERVICE_BOOT_START: startType = tr("Boot"); break;
                case SERVICE_DEMAND_START: startType = tr("Manual"); break;
                case SERVICE_DISABLED: startType = tr("Disabled"); break;
                case SERVICE_SYSTEM_START: startType = tr("System"); break;
                }
                path = QString::fromWCharArray(pConfig->lpBinaryPathName);
            }
            if (pConfig) free(pConfig);
            CloseServiceHandle(hService);
        }

        m_table->setItem(row, 0, new QTableWidgetItem(name));
        m_table->setItem(row, 1, new QTableWidgetItem(display));
        m_table->setItem(row, 2, new QTableWidgetItem(status));
        m_table->setItem(row, 3, new QTableWidgetItem(startType));
        m_table->setItem(row, 4, new QTableWidgetItem(path));
        row++;
    }

    free(pServices);
    CloseServiceHandle(hSCM);
    m_table->setSortingEnabled(true);
}

QString ServiceTab::currentServiceName() const
{
    int row = m_table->currentRow();
    if (row < 0) return QString();
    QTableWidgetItem *item = m_table->item(row, 0);
    return item ? item->text() : QString();
}

static bool sendSimpleServiceCmd(const QString &cmd, const QString &name)
{
    QString escaped = name;
    escaped.replace("\\", "\\\\");
    escaped.replace("\"", "\\\"");
    QString json = QString("{\"cmd\":\"%1\",\"name\":\"%2\"}").arg(cmd, escaped);
    QString reply = sendPipeCommand(json);
    QJsonParseError err;
    QJsonDocument doc = QJsonDocument::fromJson(reply.toUtf8(), &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) return false;
    return doc.object().value("ok").toBool(false);
}

void ServiceTab::onContextMenu(const QPoint &pos)
{
    QTableWidgetItem *item = m_table->itemAt(pos);
    if (!item) return;

    QString name = currentServiceName();
    if (name.isEmpty()) return;

    QMenu menu(this);
    menu.addAction(tr("Stop service"), this, &ServiceTab::onStop);
    menu.addAction(tr("Delete service"), this, &ServiceTab::onDelete);
    menu.addSeparator();
    menu.addAction(tr("Repeat delete"), this, &ServiceTab::onRepeatDelete);
    menu.exec(m_table->viewport()->mapToGlobal(pos));
}

void ServiceTab::onStop()
{
    QString name = currentServiceName();
    if (name.isEmpty()) return;
    if (QMessageBox::question(this, tr("Confirm"), tr("Stop service %1?").arg(name)) != QMessageBox::Yes) return;
    if (sendSimpleServiceCmd("service_stop", name)) {
        MainWindow::appLog(tr("Stopped service: %1").arg(name));
    } else {
        MainWindow::appLog(tr("Failed to stop service: %1").arg(name));
        QMessageBox::warning(this, tr("Error"), tr("Failed to stop %1").arg(name));
    }
    refresh();
}

void ServiceTab::onDelete()
{
    QString name = currentServiceName();
    if (name.isEmpty()) return;
    if (QMessageBox::question(this, tr("Confirm"), tr("Delete service %1?").arg(name)) != QMessageBox::Yes) return;
    if (sendSimpleServiceCmd("service_delete", name)) {
        MainWindow::appLog(tr("Deleted service: %1").arg(name));
    } else {
        MainWindow::appLog(tr("Failed to delete service: %1").arg(name));
        QMessageBox::warning(this, tr("Error"), tr("Failed to delete %1").arg(name));
    }
    refresh();
}

void ServiceTab::onRepeatDelete()
{
    QString name = currentServiceName();
    if (name.isEmpty()) return;
    if (sendSimpleServiceCmd("service_repeated_add", name)) {
        MainWindow::appLog(tr("Added service to repeat-delete list: %1").arg(name));
    } else {
        MainWindow::appLog(tr("Failed to add service to repeat-delete list: %1").arg(name));
    }
    refresh();
}

void ServiceTab::onCancelRepeat()
{
    QString name = currentServiceName();
    if (name.isEmpty()) return;
    if (sendSimpleServiceCmd("service_repeated_remove", name)) {
        MainWindow::appLog(tr("Removed service from repeat-delete list: %1").arg(name));
    } else {
        MainWindow::appLog(tr("Failed to remove service from repeat-delete list: %1").arg(name));
    }
    refresh();
}
