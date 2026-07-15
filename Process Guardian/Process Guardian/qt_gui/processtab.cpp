#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#include "processtab.h"
#include <QApplication>
#include "mainwindow.h"
extern "C" {
#include "core.h"
}
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QMenu>
#include <QMessageBox>
#include <QFileDialog>
#include <QProcess>
#include <QDir>
#include <QSettings>
#include <cstdio>
#include <cstring>

/* Binary format shared with the guardian daemon (data/config.dat) */
#pragma pack(push, 8)
struct DaemonProcEntry {
    wchar_t name[260];
    DWORD pid;
    BOOL isTree;
    BOOL isRepeated;
};
#pragma pack(pop)

static QString moduleDir()
{
    wchar_t buf[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, buf, MAX_PATH);
    QString path = QString::fromWCharArray(buf);
    int idx = path.lastIndexOf('\\');
    return idx >= 0 ? path.left(idx) : QDir::currentPath();
}

static bool sendDaemonCommand(const QString &json)
{
    HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\GuardianAIAction",
                               GENERIC_READ | GENERIC_WRITE,
                               0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        return false;
    }
    QByteArray data = json.toUtf8();
    DWORD written = 0;
    WriteFile(hPipe, data.constData(), (DWORD)data.size(), &written, NULL);
    FlushFileBuffers(hPipe);
    char resp[4096] = {0};
    DWORD read = 0;
    ReadFile(hPipe, resp, sizeof(resp) - 1, &read, NULL);
    CloseHandle(hPipe);
    return QString::fromUtf8(resp, read).contains("\"ok\":true");
}

ProcessTab::ProcessTab(QWidget *parent)
    : QWidget(parent)
{
    setupUi();
    loadProtectedList();
    refresh();
}

void ProcessTab::setupUi()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(8, 8, 8, 8);

    QHBoxLayout *topLayout = new QHBoxLayout();
    m_searchEdit = new QLineEdit(this);
    m_searchEdit->setPlaceholderText(tr("Search process..."));
    m_btnRefresh = new QPushButton(tr("Refresh"), this);
    topLayout->addWidget(m_searchEdit);
    topLayout->addWidget(m_btnRefresh);
    mainLayout->addLayout(topLayout);

    m_splitter = new QSplitter(Qt::Horizontal, this);

    m_runningTable = new QTableWidget(this);
    m_runningTable->setColumnCount(3);
    m_runningTable->setHorizontalHeaderLabels(QStringList() << tr("Name") << tr("PID") << tr("Memory (KB)"));
    m_runningTable->horizontalHeader()->setStretchLastSection(true);
    m_runningTable->verticalHeader()->setVisible(false);
    m_runningTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_runningTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_runningTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_runningTable->setSortingEnabled(true);

    m_protectedTable = new QTableWidget(this);
    m_protectedTable->setColumnCount(3);
    m_protectedTable->setHorizontalHeaderLabels(QStringList() << tr("Name") << tr("PID") << tr("Type"));
    m_protectedTable->horizontalHeader()->setStretchLastSection(true);
    m_protectedTable->verticalHeader()->setVisible(false);
    m_protectedTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_protectedTable->setContextMenuPolicy(Qt::CustomContextMenu);

    m_splitter->addWidget(m_runningTable);
    m_splitter->addWidget(m_protectedTable);
    m_splitter->setStretchFactor(0, 2);
    m_splitter->setStretchFactor(1, 1);

    mainLayout->addWidget(m_splitter);

    connect(m_btnRefresh, &QPushButton::clicked, this, &ProcessTab::refresh);
    connect(m_runningTable, &QTableWidget::customContextMenuRequested, this, &ProcessTab::onContextMenu);
    connect(m_searchEdit, &QLineEdit::textChanged, this, &ProcessTab::onSearchTextChanged);
    connect(m_protectedTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
        QTableWidgetItem *item = m_protectedTable->itemAt(pos);
        if (!item) return;
        QMenu menu(this);
        menu.addAction(tr("Remove from list"), this, &ProcessTab::onRemoveFromProtected);
        menu.exec(m_protectedTable->viewport()->mapToGlobal(pos));
    });
}

void ProcessTab::refresh()
{
    m_runningTable->setSortingEnabled(false);
    m_runningTable->setUpdatesEnabled(false);

    QList<QString> names;
    QList<DWORD> pids;
    QHash<QString, DWORD> pidMap;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = {0};
        pe.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                QString name = QString::fromWCharArray(pe.szExeFile);
                QString nameLower = name.toLower();
                if (!pidMap.contains(nameLower)) {
                    pidMap.insert(nameLower, pe.th32ProcessID);
                }
                if (!m_searchEdit->text().isEmpty() &&
                    !name.contains(m_searchEdit->text(), Qt::CaseInsensitive)) {
                    continue;
                }
                names.append(name);
                pids.append(pe.th32ProcessID);
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }

    m_runningTable->setRowCount(names.size());
    for (int i = 0; i < names.size(); ++i) {
        m_runningTable->setItem(i, 0, new QTableWidgetItem(names[i]));
        m_runningTable->setItem(i, 1, new QTableWidgetItem(QString::number(pids[i])));
        QTableWidgetItem *memItem = new QTableWidgetItem();
        memItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        m_runningTable->setItem(i, 2, memItem);
    }

    for (int i = 0; i < names.size(); ++i) {
        DWORD pid = pids[i];
        DWORD memKB = 0;
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProc) {
            PROCESS_MEMORY_COUNTERS pmc;
            if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc)))
                memKB = (DWORD)(pmc.WorkingSetSize / 1024);
            CloseHandle(hProc);
        }
        m_runningTable->item(i, 2)->setText(QString::number(memKB));
    }

    m_runningTable->setUpdatesEnabled(true);
    m_runningTable->setSortingEnabled(true);

    for (int i = 0; i < m_protectedTable->rowCount(); ++i) {
        QString name = m_protectedTable->item(i, 0)->text();
        DWORD pid = pidMap.value(name.toLower(), 0);
        m_protectedTable->item(i, 1)->setText(pid ? QString::number(pid) : QString("-"));
    }
}

void ProcessTab::onContextMenu(const QPoint &pos)
{
    QTableWidgetItem *item = m_runningTable->itemAt(pos);
    if (!item) return;

    QMenu menu(this);
    menu.addAction(tr("Kill process"), this, &ProcessTab::onKill);
    menu.addAction(tr("Kill process tree"), this, &ProcessTab::onKillTree);
    menu.addSeparator();
    menu.addAction(tr("Repeat kill"), this, &ProcessTab::onRepeatKill);
    menu.addAction(tr("Repeat kill (tree)"), this, &ProcessTab::onRepeatKillTree);
    menu.addSeparator();
    menu.addAction(tr("Protect process"), this, &ProcessTab::onProtect);
    menu.addAction(tr("Open file location"), this, &ProcessTab::onOpenLocation);
    menu.addAction(tr("Live monitor"), this, &ProcessTab::onLiveMonitor);
    menu.addSeparator();
    menu.addAction(tr("Create AI Task"), this, &ProcessTab::onCreateAiTask);
    menu.exec(m_runningTable->viewport()->mapToGlobal(pos));
}

QString currentProcessName(QTableWidget *table)
{
    int row = table->currentRow();
    if (row < 0) return QString();
    return table->item(row, 0)->text();
}

static int currentProcessPid(QTableWidget *table)
{
    int row = table->currentRow();
    if (row < 0) return -1;
    return table->item(row, 1)->text().toInt();
}

void ProcessTab::onKill()
{
    QString name = currentProcessName(m_runningTable);
    if (name.isEmpty()) return;
    if (QMessageBox::question(this, tr("Confirm"), tr("Kill %1?").arg(name)) != QMessageBox::Yes) return;
    if (KillProcessByName(name.toStdWString().c_str(), FALSE)) {
        MainWindow::appLog(tr("Killed process: %1").arg(name));
        refresh();
    } else {
        MainWindow::appLog(tr("Failed to kill process: %1").arg(name));
        QMessageBox::warning(this, tr("Error"), tr("Failed to kill %1").arg(name));
    }
}

void ProcessTab::onKillTree()
{
    QString name = currentProcessName(m_runningTable);
    if (name.isEmpty()) return;
    if (QMessageBox::question(this, tr("Confirm"), tr("Kill process tree %1?").arg(name)) != QMessageBox::Yes) return;
    if (KillProcessByName(name.toStdWString().c_str(), TRUE)) {
        MainWindow::appLog(tr("Killed process tree: %1").arg(name));
        refresh();
    } else {
        MainWindow::appLog(tr("Failed to kill process tree: %1").arg(name));
        QMessageBox::warning(this, tr("Error"), tr("Failed to kill %1 tree").arg(name));
    }
}

void ProcessTab::onRepeatKill()
{
    QString name = currentProcessName(m_runningTable);
    if (name.isEmpty()) return;
    addProtectedEntry(name, true, false);
    MainWindow::appLog(tr("Added to repeat-kill list: %1").arg(name));
}

void ProcessTab::onRepeatKillTree()
{
    QString name = currentProcessName(m_runningTable);
    if (name.isEmpty()) return;
    addProtectedEntry(name, true, true);
    MainWindow::appLog(tr("Added to repeat-kill list (tree): %1").arg(name));
}

void ProcessTab::onProtect()
{
    QString name = currentProcessName(m_runningTable);
    if (name.isEmpty()) return;
    addProtectedEntry(name, false, false);
    MainWindow::appLog(tr("Added to protected list: %1").arg(name));
}

static QString queryImagePathViaDaemon(int pid)
{
    HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\GuardianAIAction",
                               GENERIC_READ | GENERIC_WRITE,
                               0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        return QString();
    }
    QString cmd = QString("{\"cmd\":\"query_image_path\",\"pid\":%1}").arg(pid);
    QByteArray data = cmd.toUtf8();
    DWORD written = 0;
    WriteFile(hPipe, data.constData(), (DWORD)data.size(), &written, NULL);
    FlushFileBuffers(hPipe);
    char resp[4096] = {0};
    DWORD read = 0;
    ReadFile(hPipe, resp, sizeof(resp) - 1, &read, NULL);
    CloseHandle(hPipe);
    QString r = QString::fromUtf8(resp, read);
    if (!r.contains("\"ok\":true")) return QString();
    int p = r.indexOf("\"path\":\"");
    if (p < 0) return QString();
    p += 8;
    int end = r.indexOf("\"", p);
    if (end < 0) return QString();
    QString escaped = r.mid(p, end - p);
    return escaped.replace("\\\\", "\\");
}

void ProcessTab::onOpenLocation()
{
    int pid = currentProcessPid(m_runningTable);
    if (pid <= 0) {
        MainWindow::appLog(tr("Open file location: no process selected"));
        return;
    }

    QString filePath = queryImagePathViaDaemon(pid);
    if (filePath.isEmpty()) {
        /* Fallback: try local OpenProcess */
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)pid);
        if (hProc) {
            wchar_t path[MAX_PATH] = {0};
            DWORD size = MAX_PATH;
            if (QueryFullProcessImageNameW(hProc, 0, path, &size)) {
                filePath = QString::fromWCharArray(path);
            }
            CloseHandle(hProc);
        }
    }

    if (filePath.isEmpty()) {
        QMessageBox::warning(this, tr("Error"), tr("Cannot get image path for PID %1.").arg(pid));
        MainWindow::appLog(tr("Open file location: failed to get path for PID %1").arg(pid));
        return;
    }

    QString arg = "/select," + QDir::toNativeSeparators(filePath);
    QProcess proc;
    proc.setProgram("explorer.exe");
    proc.setArguments(QStringList() << arg);
    qint64 childPid = 0;
    if (!proc.startDetached(&childPid)) {
        QMessageBox::warning(this, tr("Error"), tr("Failed to start explorer.exe"));
        MainWindow::appLog(tr("Open file location: startDetached failed"));
        return;
    }
    MainWindow::appLog(tr("Opened file location for PID %1: %2").arg(pid).arg(filePath));
}

void ProcessTab::onLiveMonitor()
{
    int pid = currentProcessPid(m_runningTable);
    if (pid <= 0) return;
    QString exe = QDir(moduleDir()).filePath("Observe/observer.exe");
    if (!QFile::exists(exe)) {
        QMessageBox::warning(this, tr("Error"), tr("observer.exe not found at %1").arg(exe));
        return;
    }
    QProcess proc;
    proc.setProgram(exe);
    proc.setArguments(QStringList() << QString::number(pid));
    proc.setWorkingDirectory(moduleDir());
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert("QT_QPA_PLATFORM_PLUGIN_PATH", moduleDir());
    proc.setProcessEnvironment(env);
    qint64 childPid = 0;
    proc.startDetached(&childPid);
    MainWindow::appLog(tr("Started live monitor for PID %1").arg(pid));
}

void ProcessTab::onRemoveFromProtected()
{
    int row = m_protectedTable->currentRow();
    if (row < 0) return;
    QString name = m_protectedTable->item(row, 0)->text();
    bool repeated = m_protected[row].repeated;
    m_protected.removeAt(row);
    m_protectedTable->removeRow(row);
    saveProtectedList();

    QString cmd = repeated ? "stop_repeated" : "unprotect";
    QString json = QString("{\"cmd\":\"%1\",\"name\":\"%2\"}").arg(cmd, name);
    sendDaemonCommand(json);

    MainWindow::appLog(tr("Removed from protected/repeat list: %1").arg(name));
}

void ProcessTab::onCreateAiTask()
{
    QString name = currentProcessName(m_runningTable);
    if (name.isEmpty()) return;
    emit createAiTaskRequested(name);
}

void ProcessTab::onSearchTextChanged(const QString &text)
{
    Q_UNUSED(text)
    refresh();
}

void ProcessTab::addProtectedEntry(const QString &name, bool repeated, bool tree)
{
    for (const auto &e : m_protected) {
        if (e.name.compare(name, Qt::CaseInsensitive) == 0) return;
    }
    ProtectedEntry e{name, repeated, tree};
    m_protected.append(e);

    int row = m_protectedTable->rowCount();
    m_protectedTable->insertRow(row);
    m_protectedTable->setItem(row, 0, new QTableWidgetItem(name));
    m_protectedTable->setItem(row, 1, new QTableWidgetItem("-"));
    QString type = repeated ? (tree ? tr("Repeat kill (tree)") : tr("Repeat kill")) : tr("Protected");
    m_protectedTable->setItem(row, 2, new QTableWidgetItem(type));
    saveProtectedList();

    QString cmd = repeated ? "repeated_kill" : "protect";
    QString json = QString("{\"cmd\":\"%1\",\"name\":\"%2\",\"tree\":%3}")
                   .arg(cmd, name, tree ? "true" : "false");
    sendDaemonCommand(json);

    refresh();
}

void ProcessTab::loadProtectedList()
{
    m_protected.clear();
    m_protectedTable->setRowCount(0);

    auto addEntry = [this](const QString &name, bool repeated, bool tree) {
        for (const auto &e : m_protected) {
            if (e.name.compare(name, Qt::CaseInsensitive) == 0) return;
        }
        ProtectedEntry e{name, repeated, tree};
        m_protected.append(e);
        int row = m_protectedTable->rowCount();
        m_protectedTable->insertRow(row);
        m_protectedTable->setItem(row, 0, new QTableWidgetItem(name));
        m_protectedTable->setItem(row, 1, new QTableWidgetItem("-"));
        QString type = repeated ? (tree ? tr("Repeat kill (tree)") : tr("Repeat kill")) : tr("Protected");
        m_protectedTable->setItem(row, 2, new QTableWidgetItem(type));
    };

    QString dataDir = QDir(moduleDir()).filePath("data");
    QDir().mkpath(dataDir);

    /* Try daemon shared config.dat first */
    QString path = dataDir + "\\config.dat";
    FILE *f = _wfopen(path.toStdWString().c_str(), L"rb");
    if (!f) {
        /* Fallback to legacy managed.dat */
        path = dataDir + "\\managed.dat";
        f = _wfopen(path.toStdWString().c_str(), L"rb");
    }
    if (f) {
        int count = 0;
        if (fread(&count, sizeof(int), 1, f) == 1) {
            if (count >= 0 && count <= 256) {
                for (int i = 0; i < count; ++i) {
                    DaemonProcEntry pe;
                    if (fread(&pe, sizeof(DaemonProcEntry), 1, f) != 1) break;
                    addEntry(QString::fromWCharArray(pe.name), pe.isRepeated ? true : false, pe.isTree ? true : false);
                }
            }
        }
        fclose(f);
        saveProtectedList(); /* migrate to config.dat */
        return;
    }

    /* Fallback to old Qt QSettings once, then migrate */
    QSettings s(QSettings::IniFormat, QSettings::UserScope, "TRAE", "ProcessGuardian");
    int count = s.beginReadArray("protected");
    for (int i = 0; i < count; ++i) {
        s.setArrayIndex(i);
        addEntry(s.value("name").toString(), s.value("repeated").toBool(), s.value("tree").toBool());
    }
    s.endArray();
    if (count > 0) saveProtectedList();
}

void ProcessTab::saveProtectedList()
{
    QString dataDir = QDir(moduleDir()).filePath("data");
    QDir().mkpath(dataDir);

    QString path = dataDir + "\\config.dat";
    QString tmp = path + ".tmp";
    FILE *f = _wfopen(tmp.toStdWString().c_str(), L"wb");
    if (!f) return;

    int count = m_protected.size();
    fwrite(&count, sizeof(int), 1, f);
    for (const auto &e : m_protected) {
        DaemonProcEntry pe;
        memset(&pe, 0, sizeof(pe));
        wcsncpy(pe.name, e.name.toStdWString().c_str(), 259);
        pe.isTree = e.tree ? TRUE : FALSE;
        pe.isRepeated = e.repeated ? TRUE : FALSE;
        fwrite(&pe, sizeof(DaemonProcEntry), 1, f);
    }
    fclose(f);
    MoveFileExW(tmp.toStdWString().c_str(), path.toStdWString().c_str(), MOVEFILE_REPLACE_EXISTING);
}
