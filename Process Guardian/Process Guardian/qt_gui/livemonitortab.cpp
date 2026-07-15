#include "livemonitortab.h"
#include "mainwindow.h"
extern "C" {
#include "core.h"
}
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QMenu>
#include <QMessageBox>
#include <QDir>
#include <QFile>
#include <psapi.h>
#include <tlhelp32.h>

static QString moduleDir()
{
    wchar_t buf[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, buf, MAX_PATH);
    QString path = QString::fromWCharArray(buf);
    int idx = path.lastIndexOf('\\');
    return idx >= 0 ? path.left(idx) : QDir::currentPath();
}

struct DaemonProcEntry {
    wchar_t name[MAX_PATH_W];
    DWORD pid;
    BOOL isTree;
    BOOL isRepeated;
};

LiveMonitorTab::LiveMonitorTab(QWidget *parent)
    : QWidget(parent)
{
    setupUi();
    setMonitoring(true);
}

void LiveMonitorTab::setupUi()
{
    QVBoxLayout *layout = new QVBoxLayout(this);

    QHBoxLayout *btnLayout = new QHBoxLayout();
    m_btnToggle = new QPushButton(tr("Stop monitoring"), this);
    btnLayout->addWidget(m_btnToggle);
    btnLayout->addStretch();
    layout->addLayout(btnLayout);

    m_table = new QTableWidget(this);
    m_table->setColumnCount(5);
    m_table->setHorizontalHeaderLabels(QStringList() << tr("PID") << tr("Name") << tr("CPU %") << tr("Memory MB") << tr("Status"));
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    m_table->setSortingEnabled(true);
    layout->addWidget(m_table);

    m_timer = new QTimer(this);
    connect(m_timer, &QTimer::timeout, this, &LiveMonitorTab::onTimer);
    connect(m_btnToggle, &QPushButton::clicked, this, [this]() {
        setMonitoring(!m_timer->isActive());
    });
    connect(m_table, &QTableWidget::customContextMenuRequested, this, &LiveMonitorTab::onContextMenu);
}

void LiveMonitorTab::setMonitoring(bool enabled)
{
    if (enabled) {
        m_timer->start(1500);
        m_btnToggle->setText(tr("Stop monitoring"));
    } else {
        m_timer->stop();
        m_btnToggle->setText(tr("Start monitoring"));
    }
}

bool LiveMonitorTab::loadRepeatedList()
{
    m_repeated.clear();
    m_repeatedTree.clear();

    QString dataDir = QDir(moduleDir()).filePath("data");
    QString path = dataDir + "\\config.dat";
    FILE *f = _wfopen(path.toStdWString().c_str(), L"rb");
    if (!f) {
        path = dataDir + "\\managed.dat";
        f = _wfopen(path.toStdWString().c_str(), L"rb");
    }
    if (f) {
        int count = 0;
        if (fread(&count, sizeof(int), 1, f) == 1) {
            if (count >= 0 && count <= 4096) {
                for (int i = 0; i < count; ++i) {
                    DaemonProcEntry pe;
                    if (fread(&pe, sizeof(DaemonProcEntry), 1, f) != 1) break;
                    QString name = QString::fromWCharArray(pe.name);
                    if (pe.isRepeated) {
                        m_repeated.insert(name);
                        if (pe.isTree) m_repeatedTree.append(name);
                    }
                }
            }
        }
        fclose(f);
    }
    return true;
}

bool LiveMonitorTab::isProcessRepeated(const QString &name)
{
    return m_repeated.contains(name);
}

void LiveMonitorTab::onTimer()
{
    refresh();
}

void LiveMonitorTab::highlightProcess(const QString &name)
{
    if (name.isEmpty()) return;
    setMonitoring(true);
    for (int row = 0; row < m_table->rowCount(); ++row) {
        QTableWidgetItem *item = m_table->item(row, 1);
        if (!item) continue;
        if (item->text().compare(name, Qt::CaseInsensitive) == 0) {
            m_table->selectRow(row);
            m_table->scrollToItem(item, QAbstractItemView::PositionAtCenter);
            break;
        }
    }
}

void LiveMonitorTab::refresh()
{
    loadRepeatedList();

    m_previous = m_current;
    m_current.clear();

    ULARGE_INTEGER sysIdle, sysKernel, sysUser;
    if (!GetSystemTimes((FILETIME*)&sysIdle, (FILETIME*)&sysKernel, (FILETIME*)&sysUser)) {
        sysIdle.QuadPart = sysKernel.QuadPart = sysUser.QuadPart = 0;
    }

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            ProcessSample sample;
            sample.pid = pe.th32ProcessID;
            sample.name = QString::fromWCharArray(pe.szExeFile);

            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (hProc) {
                FILETIME createTime, exitTime, kernelTime, userTime;
                if (GetProcessTimes(hProc, &createTime, &exitTime, &kernelTime, &userTime)) {
                    sample.kernelTime.LowPart = kernelTime.dwLowDateTime;
                    sample.kernelTime.HighPart = kernelTime.dwHighDateTime;
                    sample.userTime.LowPart = userTime.dwLowDateTime;
                    sample.userTime.HighPart = userTime.dwHighDateTime;
                    sample.totalTime = sample.kernelTime.QuadPart + sample.userTime.QuadPart;
                }
                PROCESS_MEMORY_COUNTERS pmc = {0};
                if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc))) {
                    sample.workingSet = pmc.WorkingSetSize;
                }
                CloseHandle(hProc);
            }

            sample.inRepeatedList = isProcessRepeated(sample.name);

            bool wasPresent = false;
            for (const auto &prev : m_previous) {
                if (prev.pid == sample.pid) {
                    wasPresent = true;
                    break;
                }
            }
            sample.isNew = !wasPresent;

            m_current.append(sample);
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);

    updateTable(sysIdle, sysKernel, sysUser);

    m_lastSysIdle = sysIdle;
    m_lastSysKernel = sysKernel;
    m_lastSysUser = sysUser;
    m_hasPrevSample = true;
}

void LiveMonitorTab::updateTable(const ULARGE_INTEGER &sysIdle, const ULARGE_INTEGER &sysKernel, const ULARGE_INTEGER &sysUser)
{
    m_table->setSortingEnabled(false);
    m_table->setRowCount(m_current.size());

    ULONGLONG sysTotalDelta = 0;
    if (m_hasPrevSample) {
        ULONGLONG kernelDelta = m_lastSysKernel.QuadPart > 0 ? (sysKernel.QuadPart - m_lastSysKernel.QuadPart) : 0;
        ULONGLONG userDelta = m_lastSysUser.QuadPart > 0 ? (sysUser.QuadPart - m_lastSysUser.QuadPart) : 0;
        sysTotalDelta = kernelDelta + userDelta;
    }

    QSet<DWORD> prevPids;
    for (const auto &prev : m_previous) prevPids.insert(prev.pid);

    for (int row = 0; row < m_current.size(); ++row) {
        const ProcessSample &s = m_current[row];

        QTableWidgetItem *pidItem = new QTableWidgetItem(QString::number(s.pid));
        pidItem->setFlags(pidItem->flags() & ~Qt::ItemIsEditable);

        QTableWidgetItem *nameItem = new QTableWidgetItem(s.name);
        nameItem->setFlags(nameItem->flags() & ~Qt::ItemIsEditable);

        double cpu = 0.0;
        if (m_hasPrevSample && sysTotalDelta > 0) {
            for (const auto &prev : m_previous) {
                if (prev.pid == s.pid) {
                    ULONGLONG procDelta = s.totalTime - prev.totalTime;
                    cpu = (double)procDelta / (double)sysTotalDelta * 100.0;
                    if (cpu < 0) cpu = 0;
                    if (cpu > 100) cpu = 100;
                    break;
                }
            }
        }
        QTableWidgetItem *cpuItem = new QTableWidgetItem(QString::number(cpu, 'f', 1));
        cpuItem->setFlags(cpuItem->flags() & ~Qt::ItemIsEditable);

        double memMB = s.workingSet / (1024.0 * 1024.0);
        QTableWidgetItem *memItem = new QTableWidgetItem(QString::number(memMB, 'f', 1));
        memItem->setFlags(memItem->flags() & ~Qt::ItemIsEditable);

        QString status;
        if (s.inRepeatedList) status = tr("Repeated kill");
        else if (s.isNew) status = tr("New");
        QTableWidgetItem *statusItem = new QTableWidgetItem(status);
        statusItem->setFlags(statusItem->flags() & ~Qt::ItemIsEditable);

        m_table->setItem(row, 0, pidItem);
        m_table->setItem(row, 1, nameItem);
        m_table->setItem(row, 2, cpuItem);
        m_table->setItem(row, 3, memItem);
        m_table->setItem(row, 4, statusItem);

        QColor bg = Qt::transparent;
        if (s.inRepeatedList) bg = QColor(80, 30, 30);
        else if (s.isNew) bg = QColor(30, 60, 30);
        for (int c = 0; c < 5; ++c) {
            if (m_table->item(row, c)) m_table->item(row, c)->setBackground(bg);
        }
    }

    m_table->setSortingEnabled(true);
}

static QString currentProcessName(QTableWidget *table)
{
    int row = table->currentRow();
    if (row < 0) return QString();
    return table->item(row, 1)->text();
}

static int currentProcessPid(QTableWidget *table)
{
    int row = table->currentRow();
    if (row < 0) return -1;
    return table->item(row, 0)->text().toInt();
}

void LiveMonitorTab::onContextMenu(const QPoint &pos)
{
    QMenu menu(this);
    menu.addAction(tr("Kill"), this, &LiveMonitorTab::onKill);
    menu.addAction(tr("Repeat kill"), this, &LiveMonitorTab::onRepeatKill);
    menu.addAction(tr("Repeat kill tree"), this, &LiveMonitorTab::onRepeatKillTree);
    menu.addAction(tr("Protect"), this, &LiveMonitorTab::onProtect);
    menu.exec(m_table->viewport()->mapToGlobal(pos));
}

static void addProtectedEntry(const QString &name, bool repeated, bool tree)
{
    QString dataDir = QDir(moduleDir()).filePath("data");
    QDir().mkpath(dataDir);
    QString path = dataDir + "\\config.dat";

    struct DaemonProcEntry {
        wchar_t name[MAX_PATH_W];
        DWORD pid;
        BOOL isTree;
        BOOL isRepeated;
    };

    QVector<DaemonProcEntry> entries;
    FILE *f = _wfopen(path.toStdWString().c_str(), L"rb");
    if (f) {
        int count = 0;
        if (fread(&count, sizeof(int), 1, f) == 1) {
            if (count >= 0 && count <= 4096) {
                for (int i = 0; i < count; ++i) {
                    DaemonProcEntry pe;
                    if (fread(&pe, sizeof(pe), 1, f) != 1) break;
                    entries.append(pe);
                }
            }
        }
        fclose(f);
    }

    for (const auto &e : entries) {
        if (QString::fromWCharArray(e.name).compare(name, Qt::CaseInsensitive) == 0) {
            return;
        }
    }

    DaemonProcEntry ne = {0};
    wcsncpy(ne.name, name.toStdWString().c_str(), 259);
    ne.name[259] = L'\0';
    ne.pid = 0;
    ne.isTree = tree ? TRUE : FALSE;
    ne.isRepeated = repeated ? TRUE : FALSE;
    entries.append(ne);

    f = _wfopen(path.toStdWString().c_str(), L"wb");
    if (f) {
        int count = entries.size();
        fwrite(&count, sizeof(int), 1, f);
        for (const auto &e : entries) fwrite(&e, sizeof(e), 1, f);
        fclose(f);
    }
}

void LiveMonitorTab::onKill()
{
    QString name = currentProcessName(m_table);
    if (name.isEmpty()) return;
    if (QMessageBox::question(this, tr("Confirm"), tr("Kill %1?").arg(name)) != QMessageBox::Yes) return;
    if (KillProcessByName(name.toStdWString().c_str(), FALSE)) {
        MainWindow::appLog(tr("LiveMonitor killed process: %1").arg(name));
    } else {
        MainWindow::appLog(tr("LiveMonitor failed to kill process: %1").arg(name));
        QMessageBox::warning(this, tr("Error"), tr("Failed to kill %1").arg(name));
    }
}

void LiveMonitorTab::onRepeatKill()
{
    QString name = currentProcessName(m_table);
    if (name.isEmpty()) return;
    addProtectedEntry(name, true, false);
    MainWindow::appLog(tr("LiveMonitor added to repeat-kill list: %1").arg(name));
}

void LiveMonitorTab::onRepeatKillTree()
{
    QString name = currentProcessName(m_table);
    if (name.isEmpty()) return;
    addProtectedEntry(name, true, true);
    MainWindow::appLog(tr("LiveMonitor added to repeat-kill list (tree): %1").arg(name));
}

void LiveMonitorTab::onProtect()
{
    QString name = currentProcessName(m_table);
    if (name.isEmpty()) return;
    addProtectedEntry(name, false, false);
    MainWindow::appLog(tr("LiveMonitor added to protected list: %1").arg(name));
}
