#include "mainwindow.h"
#include "processtab.h"
#include "servicetab.h"
#include "registrytab.h"
#include "partitiontab.h"
#include "aichattab.h"
#include "livemonitortab.h"
#include "aihubtab.h"
#include "roguesoftwaretab.h"
#include "settingsdialog.h"
#include "gui_ai.h"
#include <QApplication>
#include <QToolBar>
#include <QPushButton>
#include <QTabWidget>
#include <QStatusBar>
#include <QStyle>
#include <QMenu>
#include <QMessageBox>
#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTextBrowser>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QPushButton>
#include <QRegularExpression>
#include <QProcess>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QDateTime>
#include <QThread>
#include <QMetaObject>
#include <windows.h>
#include <tlhelp32.h>
#include <shellapi.h>

static QString moduleDir()
{
    wchar_t buf[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, buf, MAX_PATH);
    QString path = QString::fromWCharArray(buf);
    int idx = path.lastIndexOf('\\');
    return idx >= 0 ? path.left(idx) : QDir::currentPath();
}

static QString extractKv(const QString &line, const QString &key)
{
    QRegularExpression re(QString("%1=([^\\\\s]+(?:\\s+[^\\\\s=]+)*?)(?=\\s+[a-zA-Z_]+=|$)").arg(QRegularExpression::escape(key)));
    QRegularExpressionMatch m = re.match(line);
    if (m.hasMatch()) return m.captured(1).trimmed();
    return QString();
}

static QString extractPid(const QString &text)
{
    QRegularExpression re("PID[=:]\\s*(\\d+)", QRegularExpression::CaseInsensitiveOption);
    QRegularExpressionMatch m = re.match(text);
    if (m.hasMatch()) return m.captured(1);
    return QString();
}

static QString extractSignature(const QString &text)
{
    QRegularExpression re("signed by ([^,.]+)", QRegularExpression::CaseInsensitiveOption);
    QRegularExpressionMatch m = re.match(text);
    if (m.hasMatch()) return QObject::tr("Signed by %1").arg(m.captured(1).trimmed());
    if (text.contains("no digital signature", Qt::CaseInsensitive) ||
        text.contains("unsigned", Qt::CaseInsensitive) ||
        text.contains("lacks a digital signature", Qt::CaseInsensitive)) {
        return QObject::tr("No valid digital signature");
    }
    return QObject::tr("Unknown");
}

static QString extractPrivilege(const QString &text)
{
    if (text.contains("SYSTEM", Qt::CaseInsensitive) && text.contains("privilege", Qt::CaseInsensitive))
        return QObject::tr("SYSTEM / elevated");
    if (text.contains("system-level privileges", Qt::CaseInsensitive))
        return QObject::tr("SYSTEM / elevated");
    if (text.contains("user privileges", Qt::CaseInsensitive))
        return QObject::tr("User");
    return QObject::tr("Unknown");
}

static QString inferActionResult(const QString &task)
{
    if (task.contains("terminated", Qt::CaseInsensitive)) return QObject::tr("Terminated");
    if (task.contains("deleted", Qt::CaseInsensitive)) return QObject::tr("Deleted");
    if (task.contains("report", Qt::CaseInsensitive)) return QObject::tr("Report");
    if (task.contains("created", Qt::CaseInsensitive)) return QObject::tr("Created");
    return QObject::tr("-");
}

static QList<NotificationItem> parseNotificationLog(const QString &logPath)
{
    QList<NotificationItem> items;
    QFile f(logPath);
    if (!f.open(QIODevice::ReadOnly)) return items;

    qint64 size = f.size();
    qint64 readSize = qMin(size, (qint64)524288);
    qint64 offset = size - readSize;
    if (offset < 0) offset = 0;
    f.seek(offset);

    QByteArray data = f.readAll();
    f.close();

    int startIdx = 0;
    if (offset > 0) {
        startIdx = data.indexOf('\n');
        if (startIdx >= 0) startIdx++;
    }

    QString text = QString::fromUtf8(data.mid(startIdx));
    QStringList lines = text.split('\n');

    for (const QString &line : lines) {
        QString trimmed = line.trimmed();
        if (trimmed.isEmpty() || trimmed.startsWith('\0')) continue;
        NotificationItem ni;
        ni.raw = trimmed;
        QRegularExpression tsRe("^\\[([^\\]]+)\\]");
        QRegularExpressionMatch tsM = tsRe.match(trimmed);
        QString rest;
        if (tsM.hasMatch()) {
            ni.timestamp = tsM.captured(1);
            rest = trimmed.mid(tsM.capturedEnd()).trimmed();
        } else {
            rest = trimmed;
        }

        int reasonIdx = rest.lastIndexOf(" reason=");
        if (reasonIdx >= 0) {
            ni.reason = rest.mid(reasonIdx + 8).trimmed();
            rest = rest.left(reasonIdx).trimmed();
        }

        ni.level = extractKv(rest, "level");
        if (ni.level.isEmpty()) {
            QRegularExpression typeRe("type=([^\\s]+)");
            QRegularExpressionMatch typeM = typeRe.match(rest);
            if (typeM.hasMatch()) ni.level = typeM.captured(1);
        }
        ni.task = extractKv(rest, "task");
        ni.taskId = extractKv(rest, "task_id");
        ni.proc = extractKv(rest, "proc");
        ni.path = extractKv(rest, "path");
        ni.pid = extractPid(rest + " " + ni.reason);
        if (ni.timestamp.isEmpty() && ni.proc.isEmpty() && ni.task.isEmpty() && ni.level.isEmpty())
            continue;
        items.append(ni);
    }
    return items;
}

static QString elide(const QString &s, int maxLen)
{
    if (s.length() <= maxLen) return s;
    return s.left(maxLen - 3) + "...";
}

void MainWindow::appLog(const QString &message)
{
    QString logPath = QDir(moduleDir()).filePath("data/trae_guardian.log");
    QDir().mkpath(QFileInfo(logPath).absolutePath());
    QFile f(logPath);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) return;
    QString line = QString("[%1] %2\n")
                       .arg(QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"))
                       .arg(message);
    f.write(line.toUtf8());
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setupUi();
    setupToolbar();
    resize(1100, 780);
    appLog(tr("Process Guardian Qt GUI started"));
    startPopupServer();
}

MainWindow::~MainWindow()
{
    stopPopupServer();
}

void MainWindow::setupUi()
{
    m_tabWidget = new QTabWidget(this);
    setCentralWidget(m_tabWidget);

    m_processTab = new ProcessTab(this);
    m_serviceTab = new ServiceTab(this);
    m_registryTab = new RegistryTab(this);
    m_partitionTab = new PartitionTab(this);
    m_liveMonitorTab = new LiveMonitorTab(this);
    m_aiHubTab = new AiHubTab(this);
    m_aiChatTab = new AichatTab(this);
    m_rogueSoftwareTab = new RogueSoftwareTab(this);

    m_tabWidget->addTab(m_processTab, tr("Processes"));
    m_tabWidget->addTab(m_serviceTab, tr("Services"));
    m_tabWidget->addTab(m_registryTab, tr("Registry"));
    m_tabWidget->addTab(m_partitionTab, tr("Partitions"));
    m_tabWidget->addTab(m_liveMonitorTab, tr("Live Monitor"));
    m_tabWidget->addTab(m_rogueSoftwareTab, tr("Rogue Software"));
    m_tabWidget->addTab(m_aiHubTab, tr("AI Hub"));
    m_tabWidget->addTab(m_aiChatTab, tr("AI Chat"));

    connect(m_processTab, &ProcessTab::liveMonitorRequested,
            this, &MainWindow::onLiveMonitorRequested);
    connect(m_processTab, &ProcessTab::createAiTaskRequested,
            this, &MainWindow::onCreateAiTaskRequested);

    m_statusLabel = new QLabel(tr("Ready"));
    statusBar()->addWidget(m_statusLabel);

    m_refreshTimer = new QTimer(this);
    connect(m_refreshTimer, &QTimer::timeout, this, &MainWindow::onRefresh);

    m_daemonStatusTimer = new QTimer(this);
    connect(m_daemonStatusTimer, &QTimer::timeout, this, &MainWindow::onCheckDaemonStatus);
    m_daemonStatusTimer->start(2000);

    m_dailyReportTimer = new QTimer(this);
    connect(m_dailyReportTimer, &QTimer::timeout, this, &MainWindow::onDailyReport);
    scheduleNextDailyReport();

    m_popupTimer = new QTimer(this);
    connect(m_popupTimer, &QTimer::timeout, this, &MainWindow::onCheckPopupFlag);
    m_popupTimer->start(3000);
}

static QString readLogFile(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return QString();
    QTextStream in(&f);
    in.setEncoding(QStringConverter::Utf8);
    return in.readAll();
}

static QStringList todayLogLines(const QString &logText)
{
    QString today = QDateTime::currentDateTime().toString("yyyy-MM-dd");
    QStringList result;
    for (const QString &line : logText.split('\n')) {
        if (line.startsWith("[" + today)) result.append(line);
    }
    return result;
}

static QString generateDailyReport()
{
    QString dataDir = QDir(moduleDir()).filePath("data");
    QString daemonLog = readLogFile(dataDir + "/daemon.log");
    QString guiLog = readLogFile(dataDir + "/trae_guardian.log");

    QStringList daemonToday = todayLogLines(daemonLog);
    QStringList guiToday = todayLogLines(guiLog);

    int high = 0, confirmed = 0, aiActions = 0, kills = 0, additions = 0;
    for (const QString &line : daemonToday) {
        if (line.contains("HIGH", Qt::CaseInsensitive)) high++;
        if (line.contains("CONFIRMED", Qt::CaseInsensitive)) confirmed++;
        if (line.contains("[AI-ACTION]", Qt::CaseInsensitive) || line.contains("[ACTION]", Qt::CaseInsensitive)) aiActions++;
    }
    for (const QString &line : guiToday) {
        if (line.contains("killed", Qt::CaseInsensitive)) kills++;
        if (line.contains("added", Qt::CaseInsensitive) && line.contains("repeat", Qt::CaseInsensitive)) additions++;
    }

    QString report;
    report += "=== Daily Security Report ===\n";
    report += QDateTime::currentDateTime().toString("yyyy-MM-dd") + "\n\n";
    report += QString("Daemon log entries today: %1\n").arg(daemonToday.size());
    report += QString("HIGH threats: %1\n").arg(high);
    report += QString("CONFIRMED threats: %1\n").arg(confirmed);
    report += QString("AI actions: %1\n").arg(aiActions);
    report += QString("Manual kills: %1\n").arg(kills);
    report += QString("Added to repeat-kill list: %1\n").arg(additions);
    report += "\nRecent daemon events:\n";
    int count = 0;
    for (int i = daemonToday.size() - 1; i >= 0 && count < 10; --i, ++count) {
        report += daemonToday[i] + "\n";
    }
    return report;
}

void MainWindow::scheduleNextDailyReport()
{
    QDateTime now = QDateTime::currentDateTime();
    QDateTime next = QDateTime(now.date().addDays(1), QTime(9, 0));
    int ms = now.msecsTo(next);
    if (ms <= 0) ms = 24 * 3600 * 1000;
    m_dailyReportTimer->start(ms);
}

void MainWindow::onDailyReport()
{
    QString report = generateDailyReport();
    appLog(tr("Daily security report generated"));

    QString path = QDir(moduleDir()).filePath("data/daily_report.txt");
    QFile f(path);
    if (f.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
        QTextStream out(&f);
        out.setEncoding(QStringConverter::Utf8);
        out << report << "\n\n";
    }

    if (m_aiChatTab) m_aiChatTab->appendSystemMessage(report);

    scheduleNextDailyReport();
}

void MainWindow::setupToolbar()
{
    m_toolBar = addToolBar(tr("Main"));
    m_toolBar->setMovable(false);

    m_btnRefresh = new QPushButton(style()->standardIcon(QStyle::SP_BrowserReload), tr("Refresh"), this);
    m_btnDaemon = new QToolButton(this);
    m_btnDaemon->setText(tr("Start daemon"));
    m_btnDaemon->setIcon(style()->standardIcon(QStyle::SP_ComputerIcon));
    m_btnSettings = new QPushButton(style()->standardIcon(QStyle::SP_FileDialogDetailedView), tr("Settings"), this);
    m_btnAiHub = new QPushButton(style()->standardIcon(QStyle::SP_DialogHelpButton), tr("AI Hub"), this);
    m_btnBell = new QPushButton(style()->standardIcon(QStyle::SP_MessageBoxInformation), tr("Alerts"), this);
    m_btnAutoRefresh = new QPushButton(style()->standardIcon(QStyle::SP_MediaPlay), tr("Auto refresh"), this);
    m_btnAutoRefresh->setCheckable(true);

    m_btnDaemon->setMenu(new QMenu(this));
    m_btnDaemon->menu()->addAction(tr("Normal"), this, &MainWindow::onStartDaemon);
    m_btnDaemon->menu()->addAction(tr("Administrator"), this, &MainWindow::onStartAdmin);
    m_btnDaemon->menu()->addAction(tr("SYSTEM"), this, &MainWindow::onStartSystem);
    m_btnDaemon->setPopupMode(QToolButton::MenuButtonPopup);

    m_toolBar->addWidget(m_btnRefresh);
    m_toolBar->addWidget(m_btnDaemon);
    m_toolBar->addWidget(m_btnSettings);
    m_toolBar->addWidget(m_btnAiHub);
    m_toolBar->addWidget(m_btnBell);
    m_toolBar->addWidget(m_btnAutoRefresh);

    connect(m_btnRefresh, &QPushButton::clicked, this, &MainWindow::onRefresh);
    connect(m_btnSettings, &QPushButton::clicked, this, &MainWindow::onOpenSettings);
    connect(m_btnAiHub, &QPushButton::clicked, this, &MainWindow::onOpenAiHub);
    connect(m_btnBell, &QPushButton::clicked, this, &MainWindow::onCheckNotifications);
    connect(m_btnAutoRefresh, &QPushButton::toggled, this, &MainWindow::onAutoRefreshToggled);
}

void MainWindow::onRefresh()
{
    int idx = m_tabWidget->currentIndex();
    if (idx == 0) m_processTab->refresh();
    else if (idx == 1) m_serviceTab->refresh();
    else if (idx == 2) m_registryTab->refresh();
    else if (idx == 3) m_partitionTab->refresh();
    else if (idx == 4) m_liveMonitorTab->refresh();
    else if (idx == 5) m_rogueSoftwareTab->refresh();
    else if (idx == 6) m_aiHubTab->refresh();
    else if (idx == 7) m_aiChatTab->refresh();
}

void MainWindow::onCheckDaemonStatus()
{
    bool running = false;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = {0};
        pe.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, L"trae_guardian_daemon.exe") == 0) {
                    running = true;
                    break;
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    QString text = running ? tr("Daemon running") : tr("Start daemon");
    if (m_btnDaemon->text() != text)
        m_btnDaemon->setText(text);
}

static bool callPermissionDll(int mode)
{
    const wchar_t *dllNames[] = {L"normal.dll", L"admin.dll", L"SYSTEM.dll"};
    QString dir = moduleDir();
    QString dllPath = dir + QString("\\permission\\") + QString::fromWCharArray(dllNames[mode]);
    HMODULE hDll = LoadLibraryW(dllPath.toStdWString().c_str());
    if (!hDll) return false;
    typedef BOOL (*FnRestartDaemon)(HWND);
    FnRestartDaemon fn = (FnRestartDaemon)GetProcAddress(hDll, "RestartDaemon");
    BOOL ok = FALSE;
    if (fn) ok = fn(NULL);
    FreeLibrary(hDll);
    return ok;
}

void MainWindow::onStartDaemon()
{
    m_statusLabel->setText(tr("Starting daemon..."));
    
    QThread *thread = new QThread(this);
    QObject *worker = new QObject();
    
    connect(thread, &QThread::started, [this, worker, thread]() {
        bool success = false;
        QString modeLabel;
        for (int mode = 2; mode >= 0; --mode) {
            if (callPermissionDll(mode)) {
                modeLabel = (mode == 2) ? "SYSTEM" : (mode == 1) ? "Administrator" : "Normal";
                success = true;
                break;
            }
        }
        QMetaObject::invokeMethod(this, "onDaemonStartComplete", Qt::QueuedConnection,
                                  Q_ARG(bool, success), Q_ARG(QString, modeLabel));
        worker->deleteLater();
        thread->quit();
        thread->wait();
        thread->deleteLater();
    });
    
    worker->moveToThread(thread);
    thread->start();
}

void MainWindow::onDaemonStartComplete(bool success, const QString &modeLabel)
{
    if (success) {
        appLog(tr("Daemon started (%1)").arg(modeLabel));
        m_statusLabel->setText(tr("Daemon started (%1)").arg(modeLabel));
    } else {
        appLog(tr("Failed to start daemon"));
        m_statusLabel->setText(tr("Failed to start daemon"));
        QMessageBox::warning(this, tr("Error"), tr("Failed to start daemon. Make sure the service is installed (Settings -> Install Service) and run this app as Administrator."));
    }
}

void MainWindow::onStartAdmin()
{
    m_statusLabel->setText(tr("Starting daemon..."));
    
    QThread *thread = new QThread(this);
    QObject *worker = new QObject();
    
    connect(thread, &QThread::started, [this, worker, thread]() {
        bool success = callPermissionDll(1);
        QMetaObject::invokeMethod(this, "onAdminStartComplete", Qt::QueuedConnection,
                                  Q_ARG(bool, success));
        worker->deleteLater();
        thread->quit();
        thread->wait();
        thread->deleteLater();
    });
    
    worker->moveToThread(thread);
    thread->start();
}

void MainWindow::onAdminStartComplete(bool success)
{
    if (success) {
        appLog(tr("Daemon started (Administrator)"));
        m_statusLabel->setText(tr("Daemon started (Administrator)"));
    } else {
        appLog(tr("Failed to start daemon in Administrator mode"));
        m_statusLabel->setText(tr("Failed to start daemon"));
        QMessageBox::warning(this, tr("Error"), tr("Failed to start daemon in Administrator mode."));
    }
}

void MainWindow::onStartSystem()
{
    m_statusLabel->setText(tr("Starting daemon..."));
    
    QThread *thread = new QThread(this);
    QObject *worker = new QObject();
    
    connect(thread, &QThread::started, [this, worker, thread]() {
        bool success = callPermissionDll(2);
        QMetaObject::invokeMethod(this, "onSystemStartComplete", Qt::QueuedConnection,
                                  Q_ARG(bool, success));
        worker->deleteLater();
        thread->quit();
        thread->wait();
        thread->deleteLater();
    });
    
    worker->moveToThread(thread);
    thread->start();
}

void MainWindow::onSystemStartComplete(bool success)
{
    if (success) {
        appLog(tr("Daemon started (SYSTEM service)"));
        m_statusLabel->setText(tr("Daemon started (SYSTEM service)"));
    } else {
        appLog(tr("Failed to start daemon in SYSTEM mode"));
        m_statusLabel->setText(tr("Failed to start daemon"));
        QMessageBox::warning(this, tr("Error"), tr("Failed to start daemon in SYSTEM mode."));
    }
}

void MainWindow::onStopDaemon()
{
    HANDLE hStopEvent = OpenEventW(EVENT_ALL_ACCESS, FALSE, L"Global\\TRAE_Guardian_Stop_Event");
    if (hStopEvent) {
        SetEvent(hStopEvent);
        CloseHandle(hStopEvent);
        appLog(tr("Stop signal sent to daemon"));
        m_statusLabel->setText(tr("Stopping daemon..."));
    } else {
        DWORD err = GetLastError();
        appLog(tr("Failed to open stop event: %1").arg(err));
        
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = {0};
            pe.dwSize = sizeof(PROCESSENTRY32W);
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    if (_wcsicmp(pe.szExeFile, L"trae_guardian_daemon.exe") == 0) {
                        HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                        if (hProc) {
                            TerminateProcess(hProc, 0);
                            CloseHandle(hProc);
                            appLog(tr("Daemon terminated (PID: %1)").arg((unsigned int)pe.th32ProcessID));
                        }
                    }
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
        
        SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (hSCM) {
            SC_HANDLE hService = OpenServiceW(hSCM, L"GuardianDaemon", SERVICE_STOP);
            if (hService) {
                SERVICE_STATUS status = {0};
                ControlService(hService, SERVICE_CONTROL_STOP, &status);
                CloseHandle(hService);
                appLog(tr("Service stop command sent"));
            }
            CloseHandle(hSCM);
        }
        
        m_statusLabel->setText(tr("Daemon stopped"));
    }
}

void MainWindow::onOpenSettings()
{
    SettingsDialog dlg(this);
    if (dlg.exec() == QDialog::Accepted) {
        appLog(tr("Settings saved"));
        m_statusLabel->setText(tr("Settings saved"));
    }
}

void MainWindow::onOpenAiHub()
{
    m_tabWidget->setCurrentWidget(m_aiHubTab);
    m_aiHubTab->refresh();
}

void MainWindow::openGlobalChat()
{
    m_tabWidget->setCurrentWidget(m_aiChatTab);
    m_aiChatTab->refresh();
}

void MainWindow::onLiveMonitorRequested(const QString &processName)
{
    m_tabWidget->setCurrentWidget(m_liveMonitorTab);
    m_liveMonitorTab->setMonitoring(true);
    m_liveMonitorTab->highlightProcess(processName);
    m_statusLabel->setText(tr("Live monitor: %1").arg(processName));
}

void MainWindow::onCreateAiTaskRequested(const QString &processName)
{
    m_tabWidget->setCurrentWidget(m_aiHubTab);
    m_aiHubTab->createTaskWithProcess(processName);
}

void MainWindow::onCheckNotifications()
{
    QString aiNotify = QDir(moduleDir()).filePath("data/ai_notifications.log");
    QList<NotificationItem> items = parseNotificationLog(aiNotify);

    if (items.isEmpty()) {
        QMessageBox::information(this, tr("Notifications"), tr("No notification entries yet."));
        return;
    }

    /* Keep only recent 200 entries */
    if (items.size() > 200) items = items.mid(items.size() - 200);

    QDialog dlg(this);
    dlg.setWindowTitle(tr("Notifications / Recent Events"));
    dlg.setMinimumSize(900, 500);
    dlg.resize(1200, 700);

    QVBoxLayout *layout = new QVBoxLayout(&dlg);

    QTableWidget *table = new QTableWidget(&dlg);
    table->setColumnCount(7);
    table->setHorizontalHeaderLabels(QStringList()
        << tr("Timestamp") << tr("Process") << tr("PID")
        << tr("Action") << tr("Level") << tr("Result")
        << tr("AI Comment"));
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setAlternatingRowColors(true);
    table->verticalHeader()->setVisible(false);
    table->setSortingEnabled(true);

    QList<NotificationItem> validItems;
    for (const NotificationItem &ni : items) {
        if (ni.timestamp.isEmpty()) continue;
        if (ni.proc.isEmpty() && ni.task.isEmpty() && ni.level.isEmpty()) continue;
        validItems.append(ni);
    }

    table->setRowCount(validItems.size());
    for (int row = 0; row < validItems.size(); ++row) {
        const NotificationItem &ni = validItems[row];
        table->setItem(row, 0, new QTableWidgetItem(ni.timestamp));
        table->setItem(row, 1, new QTableWidgetItem(ni.proc));
        table->setItem(row, 2, new QTableWidgetItem(ni.pid.isEmpty() ? QObject::tr("-") : ni.pid));
        table->setItem(row, 3, new QTableWidgetItem(ni.task));
        table->setItem(row, 4, new QTableWidgetItem(ni.level));
        table->setItem(row, 5, new QTableWidgetItem(inferActionResult(ni.task)));
        table->setItem(row, 6, new QTableWidgetItem(elide(ni.reason, 80)));

        /* Store raw data for detail dialog */
        for (int col = 0; col < 7; ++col) {
            table->item(row, col)->setData(Qt::UserRole, row);
        }
    }

    table->resizeColumnsToContents();
    table->horizontalHeader()->setStretchLastSection(true);
    layout->addWidget(table);

    connect(table, &QTableWidget::cellDoubleClicked, this, [this, &validItems](int row, int) {
        if (row < 0 || row >= validItems.size()) return;
        showNotificationDetail(validItems[row]);
    });

    QPushButton *btnOk = new QPushButton(tr("OK"), &dlg);
    connect(btnOk, &QPushButton::clicked, &dlg, &QDialog::accept);
    QHBoxLayout *btnLayout = new QHBoxLayout();
    btnLayout->addStretch();
    btnLayout->addWidget(btnOk);
    layout->addLayout(btnLayout);

    dlg.exec();
}

void MainWindow::showNotificationDetail(const NotificationItem &ni)
{
    QDialog dlg(this);
    dlg.setWindowTitle(tr("Notification Detail - %1").arg(ni.proc));
    dlg.setMinimumSize(600, 450);
    dlg.resize(800, 600);

    QVBoxLayout *layout = new QVBoxLayout(&dlg);

    QTableWidget *table = new QTableWidget(&dlg);
    table->setColumnCount(2);
    table->setHorizontalHeaderLabels(QStringList() << tr("Field") << tr("Value"));
    table->verticalHeader()->setVisible(false);
    table->horizontalHeader()->setStretchLastSection(true);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionMode(QAbstractItemView::NoSelection);

    QStringList fields;
    fields << tr("Timestamp") << ni.timestamp;
    fields << tr("Process") << ni.proc;
    fields << tr("PID") << (ni.pid.isEmpty() ? tr("-") : ni.pid);
    fields << tr("Path") << (ni.path.isEmpty() || ni.path == "-" ? tr("-") : ni.path);
    fields << tr("Task / Action") << ni.task;
    fields << tr("Level") << ni.level;
    fields << tr("Result") << inferActionResult(ni.task);
    fields << tr("Signature") << extractSignature(ni.reason);
    fields << tr("Privilege") << extractPrivilege(ni.reason);
    fields << tr("AI Comment") << ni.reason;

    table->setRowCount(fields.size() / 2);
    for (int i = 0; i < fields.size() / 2; ++i) {
        table->setItem(i, 0, new QTableWidgetItem(fields[i * 2]));
        QTableWidgetItem *val = new QTableWidgetItem(fields[i * 2 + 1]);
        val->setToolTip(fields[i * 2 + 1]);
        table->setItem(i, 1, val);
    }
    table->resizeColumnsToContents();
    layout->addWidget(table);

    QPushButton *btnOk = new QPushButton(tr("OK"), &dlg);
    connect(btnOk, &QPushButton::clicked, &dlg, &QDialog::accept);
    QHBoxLayout *btnLayout = new QHBoxLayout();
    btnLayout->addStretch();
    btnLayout->addWidget(btnOk);
    layout->addLayout(btnLayout);

    dlg.exec();
}

void MainWindow::onAutoRefreshToggled(bool checked)
{
    if (checked) {
        m_refreshTimer->start(2000);
        m_btnAutoRefresh->setText(tr("Stop refresh"));
    } else {
        m_refreshTimer->stop();
        m_btnAutoRefresh->setText(tr("Auto refresh"));
    }
}

static QString popupFlagPath()
{
    return QDir(moduleDir()).filePath("data/ai_confirmed_popup.flag");
}

void MainWindow::sendPipeCommand(const QString &json)
{
    HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\GuardianAIAction",
                               GENERIC_READ | GENERIC_WRITE,
                               0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        appLog(tr("Failed to connect to daemon action pipe"));
        return;
    }
    QByteArray data = json.toUtf8();
    DWORD written = 0;
    WriteFile(hPipe, data.constData(), (DWORD)data.size(), &written, NULL);
    FlushFileBuffers(hPipe);
    char resp[4096] = {0};
    DWORD read = 0;
    ReadFile(hPipe, resp, sizeof(resp) - 1, &read, NULL);
    CloseHandle(hPipe);
    appLog(tr("Daemon response: %1").arg(QString::fromUtf8(resp, read)));
}

void MainWindow::executeCleanupFromFlag(const QString &flagContent)
{
    /* flag format: task=...\ntask_id=...\nproc=...\npath=...\nreason=... */
    QString proc, path, reason;
    for (const QString &line : flagContent.split('\n', Qt::SkipEmptyParts)) {
        int eq = line.indexOf('=');
        if (eq < 0) continue;
        QString key = line.left(eq).trimmed();
        QString value = line.mid(eq + 1).trimmed();
        if (key == "proc") proc = value;
        else if (key == "path") path = value;
        else if (key == "reason") reason = value;
    }
    if (reason.isEmpty()) reason = tr("AI requested cleanup");

    QMessageBox box(this);
    box.setWindowTitle(tr("Rogue software cleanup request"));
    box.setTextFormat(Qt::PlainText);
    box.setText(tr("AI identified a rogue/PUP process and requests cleanup.\n\n"
                   "Process: %1\n"
                   "Reason: %2\n\n"
                   "Do you authorize the cleanup?")
                    .arg(proc.isEmpty() ? tr("Unknown") : proc)
                    .arg(reason));
    box.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    box.setDefaultButton(QMessageBox::No);
    if (box.exec() != QMessageBox::Yes) {
        appLog(tr("User declined AI cleanup request for %1").arg(proc));
        return;
    }

    /* First kill the process */
    if (!proc.isEmpty()) {
        QString json = QString("{\"cmd\":\"kill_pid\",\"pid\":0}");
        /* try by name */
        json = QString("{\"cmd\":\"repeated_kill\",\"name\":\"%1\",\"tree\":true}").arg(proc);
        sendPipeCommand(json);
    }

    /* Then clean each target listed in the reason (newline separated paths/registry keys) */
    for (const QString &line : reason.split('\n', Qt::SkipEmptyParts)) {
        QString target = line.trimmed();
        if (target.isEmpty()) continue;
        QString json = QString("{\"cmd\":\"clean_path\",\"path\":\"%1\"}").arg(target);
        sendPipeCommand(json);
    }

    appLog(tr("User authorized AI cleanup for %1").arg(proc));
}

void MainWindow::onCheckPopupFlag()
{
    QString path = popupFlagPath();
    if (!QFile::exists(path)) return;
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return;
    QString content = QString::fromUtf8(f.readAll());
    f.close();
    if (content.isEmpty()) return;
    QFile::remove(path);
    executeCleanupFromFlag(content);
}

bool MainWindow::showPopupConfirmation(const QString &title, const QString &message,
                                       const QString &proc, const QString &path)
{
    Q_UNUSED(proc)
    Q_UNUSED(path)
    QMessageBox box(this);
    box.setWindowTitle(title);
    box.setText(message);
    box.setIcon(QMessageBox::Warning);
    box.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    box.setDefaultButton(QMessageBox::No);
    return box.exec() == QMessageBox::Yes;
}

static BOOL ReadNullTerminatedWString(HANDLE hPipe, wchar_t *out, DWORD outBytes)
{
    DWORD total = 0;
    while (total < outBytes) {
        DWORD got = 0;
        if (!ReadFile(hPipe, reinterpret_cast<BYTE *>(out) + total, outBytes - total, &got, NULL) || got == 0)
            return FALSE;
        total += got;
        if (total >= sizeof(wchar_t) && out[total / sizeof(wchar_t) - 1] == 0)
            break;
    }
    return TRUE;
}

static DWORD WINAPI PopupServerThreadProc(LPVOID param)
{
    MainWindow *mw = static_cast<MainWindow *>(param);
    while (!mw->m_popupStop) {
        HANDLE hPipe = CreateNamedPipeW(L"\\\\.\\pipe\\GuardianPopupServer",
                                        PIPE_ACCESS_DUPLEX,
                                        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                        PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, NULL);
        if (hPipe == INVALID_HANDLE_VALUE) {
            Sleep(1000);
            continue;
        }

        BOOL connected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!connected) {
            CloseHandle(hPipe);
            continue;
        }

        wchar_t title[256] = {0};
        wchar_t message[512] = {0};
        wchar_t proc[256] = {0};
        wchar_t path[MAX_PATH] = {0};
        if (ReadNullTerminatedWString(hPipe, title, sizeof(title)) &&
            ReadNullTerminatedWString(hPipe, message, sizeof(message)) &&
            ReadNullTerminatedWString(hPipe, proc, sizeof(proc)) &&
            ReadNullTerminatedWString(hPipe, path, sizeof(path))) {
            bool confirmed = false;
            QMetaObject::invokeMethod(mw, "showPopupConfirmation",
                                      Qt::BlockingQueuedConnection,
                                      Q_RETURN_ARG(bool, confirmed),
                                      Q_ARG(QString, QString::fromWCharArray(title)),
                                      Q_ARG(QString, QString::fromWCharArray(message)),
                                      Q_ARG(QString, QString::fromWCharArray(proc)),
                                      Q_ARG(QString, QString::fromWCharArray(path)));
            const wchar_t *resp = confirmed ? L"YES" : L"NO";
            DWORD written = 0;
            WriteFile(hPipe, resp, static_cast<DWORD>((wcslen(resp) + 1) * sizeof(wchar_t)), &written, NULL);
            FlushFileBuffers(hPipe);
        }

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
    return 0;
}

void MainWindow::startPopupServer()
{
    m_popupStop = false;
    DWORD tid = 0;
    m_popupThreadHandle = CreateThread(NULL, 0, PopupServerThreadProc, this, 0, &tid);
    if (m_popupThreadHandle) {
        appLog(tr("Popup confirmation server started (tid=%1)").arg(tid));
    } else {
        appLog(tr("Failed to start popup confirmation server"));
    }
}

void MainWindow::stopPopupServer()
{
    m_popupStop = true;
    if (m_popupThreadHandle) {
        /* Unblock ConnectNamedPipe by making a dummy connection. */
        HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\GuardianPopupServer",
                                   GENERIC_READ | GENERIC_WRITE, 0, NULL,
                                   OPEN_EXISTING, 0, NULL);
        if (hPipe != INVALID_HANDLE_VALUE) CloseHandle(hPipe);
        WaitForSingleObject(m_popupThreadHandle, 3000);
        CloseHandle(m_popupThreadHandle);
        m_popupThreadHandle = nullptr;
    }
}
