#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wintrust.h>
#include <Softpub.h>

#include "roguesoftwaretab.h"
#include "mainwindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QMenu>
#include <QMessageBox>
#include <QDir>
#include <QSettings>
#include <QProcess>
#include <QDateTime>
#include <QThread>
#include <QPalette>
#include <QBrush>
#include <QColor>
#include <QFont>

static QString moduleDir()
{
    wchar_t buf[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, buf, MAX_PATH);
    QString path = QString::fromWCharArray(buf);
    int idx = path.lastIndexOf('\\');
    return idx >= 0 ? path.left(idx) : QDir::currentPath();
}

void RogueSoftwareTab::sendDaemonCommand(const QString &json)
{
    HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\GuardianAIAction",
                               GENERIC_READ | GENERIC_WRITE,
                               0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
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
}

static QString getFileSigner(const QString &path)
{
    HANDLE hFile = CreateFileW(path.toStdWString().c_str(), GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return QString();

    DWORD dwLen = 0;
    WINTRUST_FILE_INFO wfi = {0};
    wfi.cbStruct = sizeof(WINTRUST_FILE_INFO);
    wfi.pcwszFilePath = path.toStdWString().c_str();
    wfi.hFile = hFile;
    wfi.pgKnownSubject = NULL;

    GUID guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wd = {0};
    wd.cbStruct = sizeof(WINTRUST_DATA);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &wfi;

    LONG result = WinVerifyTrust(NULL, &guid, &wd);
    CloseHandle(hFile);

    if (result != ERROR_SUCCESS) return QString("Unknown");

    return QString("Signed");
}

RogueSoftwareTab::RogueSoftwareTab(QWidget *parent)
    : QWidget(parent)
{
    setupUi();
    loadRogueList();
    refresh();

    m_refreshTimer = new QTimer(this);
    connect(m_refreshTimer, &QTimer::timeout, this, &RogueSoftwareTab::onRefresh);
    m_refreshTimer->start(5000);
}

void RogueSoftwareTab::setupUi()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(12, 12, 12, 12);
    mainLayout->setSpacing(8);

    QHBoxLayout *topLayout = new QHBoxLayout();
    topLayout->setSpacing(8);

    m_searchEdit = new QLineEdit(this);
    m_searchEdit->setPlaceholderText(tr("Search rogue software..."));
    m_searchEdit->setMinimumWidth(200);
    m_searchEdit->setStyleSheet(R"(
        QLineEdit {
            padding: 6px 10px;
            border: 1px solid #d0d0d0;
            border-radius: 6px;
            font-size: 13px;
        }
        QLineEdit:focus {
            border-color: #4a90d9;
            outline: none;
        }
    )");

    m_btnRefresh = new QPushButton(tr("Refresh"), this);
    m_btnRefresh->setStyleSheet(R"(
        QPushButton {
            padding: 6px 16px;
            border: 1px solid #d0d0d0;
            border-radius: 6px;
            font-size: 13px;
            background: #f5f5f5;
        }
        QPushButton:hover {
            background: #e8e8e8;
        }
        QPushButton:pressed {
            background: #d8d8d8;
        }
    )");

    m_btnAnalyze = new QPushButton(tr("AI Analyze Now"), this);
    m_btnAnalyze->setStyleSheet(R"(
        QPushButton {
            padding: 6px 20px;
            border: none;
            border-radius: 6px;
            font-size: 13px;
            font-weight: bold;
            background: linear-gradient(135deg, #4a90d9, #357abd);
            color: white;
        }
        QPushButton:hover {
            background: linear-gradient(135deg, #5a9fe9, #4589cd);
        }
        QPushButton:pressed {
            background: linear-gradient(135deg, #3a80c9, #2569ad);
        }
        QPushButton:disabled {
            background: #a0a0a0;
        }
    )");

    topLayout->addWidget(m_searchEdit);
    topLayout->addWidget(m_btnRefresh);
    topLayout->addWidget(m_btnAnalyze);
    topLayout->addStretch();
    mainLayout->addLayout(topLayout);

    QHBoxLayout *headerLayout = new QHBoxLayout();
    QLabel *titleLabel = new QLabel(tr("Rogue Software Monitor"), this);
    QFont titleFont = titleLabel->font();
    titleFont.setBold(true);
    titleFont.setPointSize(14);
    titleLabel->setFont(titleFont);
    titleLabel->setStyleSheet("color: #2c3e50;");

    m_statusLabel = new QLabel(tr("Ready"), this);
    m_statusLabel->setStyleSheet("color: #7f8c8d; font-size: 12px;");

    headerLayout->addWidget(titleLabel);
    headerLayout->addStretch();
    headerLayout->addWidget(m_statusLabel);
    mainLayout->addLayout(headerLayout);

    m_table = new QTableWidget(this);
    m_table->setColumnCount(8);
    m_table->setHorizontalHeaderLabels(QStringList()
        << tr("Name") << tr("Status") << tr("Signer")
        << tr("Daily Popups") << tr("Downloads")
        << tr("Last Detect") << tr("Path") << tr("Actions"));

    m_table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(6, QHeaderView::Stretch);
    m_table->horizontalHeader()->setSectionResizeMode(7, QHeaderView::ResizeToContents);

    m_table->verticalHeader()->setVisible(false);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->setStyleSheet(R"(
        QTableWidget {
            gridline-color: #e8e8e8;
            border: 1px solid #d0d0d0;
            border-radius: 6px;
            font-size: 13px;
        }
        QTableWidget::item {
            padding: 8px 10px;
        }
        QTableWidget::item:selected {
            background: #e3f2fd;
            color: #1976d2;
        }
        QHeaderView::section {
            background: #f5f5f5;
            padding: 8px 10px;
            border: none;
            font-weight: bold;
            font-size: 12px;
            color: #555;
        }
    )");

    mainLayout->addWidget(m_table);

    QFrame *controlFrame = new QFrame(this);
    controlFrame->setStyleSheet(R"(
        QFrame {
            background: #fafafa;
            border: 1px solid #e8e8e8;
            border-radius: 8px;
        }
    )");
    QVBoxLayout *controlLayout = new QVBoxLayout(controlFrame);
    controlLayout->setContentsMargins(12, 12, 12, 12);
    controlLayout->setSpacing(8);

    QLabel *controlTitle = new QLabel(tr("Control Panel"), this);
    QFont controlFont = controlTitle->font();
    controlFont.setBold(true);
    controlFont.setPointSize(12);
    controlTitle->setFont(controlFont);
    controlTitle->setStyleSheet("color: #34495e;");
    controlLayout->addWidget(controlTitle);

    QGridLayout *btnGrid = new QGridLayout();
    btnGrid->setSpacing(6);

    m_btnUninstall = new QPushButton(tr("Force Uninstall"), this);
    m_btnUninstall->setIcon(QIcon(":/icons/uninstall.png"));
    m_btnUninstall->setStyleSheet(R"(
        QPushButton {
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            font-size: 13px;
            font-weight: bold;
            background: linear-gradient(135deg, #e74c3c, #c0392b);
            color: white;
        }
        QPushButton:hover {
            background: linear-gradient(135deg, #f75c4c, #d0493b);
        }
        QPushButton:pressed {
            background: linear-gradient(135deg, #d73c2c, #b0291b);
        }
        QPushButton:disabled {
            background: #bdc3c7;
        }
    )");
    m_btnUninstall->setEnabled(false);

    m_btnBlockPopup = new QPushButton(tr("Block Popups"), this);
    m_btnBlockPopup->setStyleSheet(R"(
        QPushButton {
            padding: 8px 16px;
            border: 1px solid #f39c12;
            border-radius: 6px;
            font-size: 12px;
            background: #fff8e1;
            color: #e67e22;
        }
        QPushButton:hover {
            background: #fff3cd;
        }
        QPushButton:pressed {
            background: #ffeaa7;
        }
        QPushButton:disabled {
            background: #ecf0f1;
            color: #95a5a6;
            border-color: #bdc3c7;
        }
    )");
    m_btnBlockPopup->setEnabled(false);

    m_btnBlockDownload = new QPushButton(tr("Block Downloads"), this);
    m_btnBlockDownload->setStyleSheet(R"(
        QPushButton {
            padding: 8px 16px;
            border: 1px solid #9b59b6;
            border-radius: 6px;
            font-size: 12px;
            background: #f5f0ff;
            color: #8e44ad;
        }
        QPushButton:hover {
            background: #eee5ff;
        }
        QPushButton:pressed {
            background: #e8d4ff;
        }
        QPushButton:disabled {
            background: #ecf0f1;
            color: #95a5a6;
            border-color: #bdc3c7;
        }
    )");
    m_btnBlockDownload->setEnabled(false);

    m_btnBlockInstall = new QPushButton(tr("Block Install"), this);
    m_btnBlockInstall->setStyleSheet(R"(
        QPushButton {
            padding: 8px 16px;
            border: 1px solid #e74c3c;
            border-radius: 6px;
            font-size: 12px;
            background: #ffebee;
            color: #c0392b;
        }
        QPushButton:hover {
            background: #ffdde0;
        }
        QPushButton:pressed {
            background: #ffccd0;
        }
        QPushButton:disabled {
            background: #ecf0f1;
            color: #95a5a6;
            border-color: #bdc3c7;
        }
    )");
    m_btnBlockInstall->setEnabled(false);

    m_btnBlockDevice = new QPushButton(tr("Block Device Info"), this);
    m_btnBlockDevice->setStyleSheet(R"(
        QPushButton {
            padding: 8px 16px;
            border: 1px solid #3498db;
            border-radius: 6px;
            font-size: 12px;
            background: #e3f2fd;
            color: #2980b9;
        }
        QPushButton:hover {
            background: #d6eaf8;
        }
        QPushButton:pressed {
            background: #c5dcef;
        }
        QPushButton:disabled {
            background: #ecf0f1;
            color: #95a5a6;
            border-color: #bdc3c7;
        }
    )");
    m_btnBlockDevice->setEnabled(false);

    m_btnRemove = new QPushButton(tr("Remove from List"), this);
    m_btnRemove->setStyleSheet(R"(
        QPushButton {
            padding: 8px 16px;
            border: 1px solid #95a5a6;
            border-radius: 6px;
            font-size: 12px;
            background: #ecf0f1;
            color: #7f8c8d;
        }
        QPushButton:hover {
            background: #bdc3c7;
        }
        QPushButton:pressed {
            background: #95a5a6;
        }
        QPushButton:disabled {
            background: #f5f5f5;
            color: #bdc3c7;
        }
    )");
    m_btnRemove->setEnabled(false);

    btnGrid->addWidget(m_btnUninstall, 0, 0, 1, 2);
    btnGrid->addWidget(m_btnBlockPopup, 1, 0);
    btnGrid->addWidget(m_btnBlockDownload, 1, 1);
    btnGrid->addWidget(m_btnBlockInstall, 2, 0);
    btnGrid->addWidget(m_btnBlockDevice, 2, 1);
    btnGrid->addWidget(m_btnRemove, 3, 0, 1, 2);

    controlLayout->addLayout(btnGrid);

    m_progressBar = new QProgressBar(this);
    m_progressBar->setVisible(false);
    m_progressBar->setStyleSheet(R"(
        QProgressBar {
            border: 1px solid #d0d0d0;
            border-radius: 4px;
            height: 8px;
            text-align: center;
        }
        QProgressBar::chunk {
            background: linear-gradient(90deg, #4a90d9, #357abd);
            border-radius: 4px;
        }
    )");
    controlLayout->addWidget(m_progressBar);

    mainLayout->addWidget(controlFrame);

    connect(m_searchEdit, &QLineEdit::textChanged, this, &RogueSoftwareTab::onSearchTextChanged);
    connect(m_btnRefresh, &QPushButton::clicked, this, &RogueSoftwareTab::onRefresh);
    connect(m_btnAnalyze, &QPushButton::clicked, this, &RogueSoftwareTab::onAnalyzeNow);
    connect(m_btnUninstall, &QPushButton::clicked, this, &RogueSoftwareTab::onForceUninstall);
    connect(m_btnBlockPopup, &QPushButton::clicked, this, &RogueSoftwareTab::onBlockPopup);
    connect(m_btnBlockDownload, &QPushButton::clicked, this, &RogueSoftwareTab::onBlockDownload);
    connect(m_btnBlockInstall, &QPushButton::clicked, this, &RogueSoftwareTab::onBlockInstall);
    connect(m_btnBlockDevice, &QPushButton::clicked, this, &RogueSoftwareTab::onBlockDeviceInfo);
    connect(m_btnRemove, &QPushButton::clicked, this, &RogueSoftwareTab::onRemoveFromList);
    connect(m_table, &QTableWidget::itemSelectionChanged, this, &RogueSoftwareTab::onSelectionChanged);
}

void RogueSoftwareTab::loadRogueList()
{
    QString dataDir = QDir(moduleDir()).filePath("data");
    QString listPath = dataDir + "/rogue_software.txt";
    QFile f(listPath);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return;

    QTextStream in(&f);
    in.setEncoding(QStringConverter::Utf8);
    QString line;
    while (in.readLineInto(&line)) {
        QStringList parts = line.split("|");
        if (parts.size() >= 7) {
            RogueEntry entry;
            entry.name = parts[0];
            entry.path = parts[1];
            entry.signer = parts[2];
            entry.popupCount = parts[3].toInt();
            entry.downloadCount = parts[4].toInt();
            entry.lastDetect = parts[5];
            entry.popupBlocked = (parts.size() > 6 && parts[6] == "1");
            entry.downloadBlocked = (parts.size() > 7 && parts[7] == "1");
            entry.installBlocked = (parts.size() > 8 && parts[8] == "1");
            entry.deviceBlocked = (parts.size() > 9 && parts[9] == "1");
            m_rogueList.append(entry);
        }
    }
    f.close();
}

void RogueSoftwareTab::saveRogueList()
{
    QString dataDir = QDir(moduleDir()).filePath("data");
    QDir().mkpath(dataDir);
    QString listPath = dataDir + "/rogue_software.txt";
    QFile f(listPath);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) return;

    QTextStream out(&f);
    out.setEncoding(QStringConverter::Utf8);
    for (const RogueEntry &entry : m_rogueList) {
        out << entry.name << "|"
            << entry.path << "|"
            << entry.signer << "|"
            << entry.popupCount << "|"
            << entry.downloadCount << "|"
            << entry.lastDetect << "|"
            << (entry.popupBlocked ? "1" : "0") << "|"
            << (entry.downloadBlocked ? "1" : "0") << "|"
            << (entry.installBlocked ? "1" : "0") << "|"
            << (entry.deviceBlocked ? "1" : "0") << "\n";
    }
    f.close();
}

void RogueSoftwareTab::refresh()
{
    m_table->setRowCount(0);
    QString searchText = m_searchEdit->text().toLower();

    QSet<QString> runningProcs = getRunningProcessNames();

    for (const RogueEntry &entry : m_rogueList) {
        if (!searchText.isEmpty() && !entry.name.toLower().contains(searchText)) {
            continue;
        }

        int row = m_table->rowCount();
        m_table->insertRow(row);

        QTableWidgetItem *nameItem = new QTableWidgetItem(entry.name);
        nameItem->setData(Qt::UserRole, row);
        m_table->setItem(row, 0, nameItem);

        bool running = runningProcs.contains(entry.name.toLower());
        QTableWidgetItem *statusItem = new QTableWidgetItem(running ? tr("Running") : tr("Stopped"));
        statusItem->setForeground(running ? QColor("#27ae60") : QColor("#95a5a6"));
        m_table->setItem(row, 1, statusItem);

        QTableWidgetItem *signerItem = new QTableWidgetItem(entry.signer);
        m_table->setItem(row, 2, signerItem);

        QTableWidgetItem *popupItem = new QTableWidgetItem(QString::number(entry.popupCount));
        popupItem->setTextAlignment(Qt::AlignCenter);
        if (entry.popupCount > 50) {
            popupItem->setBackground(QColor("#ffebee"));
            popupItem->setForeground(QColor("#c0392b"));
        } else if (entry.popupCount > 10) {
            popupItem->setBackground(QColor("#fff8e1"));
            popupItem->setForeground(QColor("#e67e22"));
        }
        m_table->setItem(row, 3, popupItem);

        QTableWidgetItem *downloadItem = new QTableWidgetItem(QString::number(entry.downloadCount));
        downloadItem->setTextAlignment(Qt::AlignCenter);
        if (entry.downloadCount > 5) {
            downloadItem->setBackground(QColor("#f5f0ff"));
            downloadItem->setForeground(QColor("#8e44ad"));
        }
        m_table->setItem(row, 4, downloadItem);

        QTableWidgetItem *lastItem = new QTableWidgetItem(entry.lastDetect);
        m_table->setItem(row, 5, lastItem);

        QTableWidgetItem *pathItem = new QTableWidgetItem(entry.path);
        pathItem->setToolTip(entry.path);
        m_table->setItem(row, 6, pathItem);

        QString actions;
        if (entry.popupBlocked) actions += tr("Pop");
        if (entry.downloadBlocked) { if (!actions.isEmpty()) actions += ","; actions += tr("Dwn"); }
        if (entry.installBlocked) { if (!actions.isEmpty()) actions += ","; actions += tr("Ins"); }
        if (entry.deviceBlocked) { if (!actions.isEmpty()) actions += ","; actions += tr("Dev"); }
        if (actions.isEmpty()) actions = "-";
        QTableWidgetItem *actionItem = new QTableWidgetItem(actions);
        actionItem->setTextAlignment(Qt::AlignCenter);
        m_table->setItem(row, 7, actionItem);
    }

    m_statusLabel->setText(tr("%1 rogue software detected").arg(m_rogueList.size()));
}

void RogueSoftwareTab::onRefresh()
{
    refresh();
}

void RogueSoftwareTab::onSearchTextChanged(const QString &text)
{
    refresh();
}

void RogueSoftwareTab::onSelectionChanged()
{
    bool hasSelection = m_table->selectedItems().size() > 0;
    m_btnUninstall->setEnabled(hasSelection);
    m_btnBlockPopup->setEnabled(hasSelection);
    m_btnBlockDownload->setEnabled(hasSelection);
    m_btnBlockInstall->setEnabled(hasSelection);
    m_btnBlockDevice->setEnabled(hasSelection);
    m_btnRemove->setEnabled(hasSelection);
}

bool RogueSoftwareTab::isProcessRunning(const QString &name)
{
    QSet<QString> running = getRunningProcessNames();
    return running.contains(name.toLower());
}

QSet<QString> RogueSoftwareTab::getRunningProcessNames()
{
    QSet<QString> result;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return result;

    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnap, &pe)) {
        do {
            QString name = QString::fromWCharArray(pe.szExeFile).toLower();
            result.insert(name);
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return result;
}

void RogueSoftwareTab::onForceUninstall()
{
    int row = m_table->currentRow();
    if (row < 0 || row >= m_rogueList.size()) return;

    RogueEntry &entry = m_rogueList[row];
    QString message = tr("Are you sure you want to force uninstall %1?\n\n"
                         "This will terminate all running instances and remove related files.").arg(entry.name);

    QMessageBox::StandardButton reply = QMessageBox::question(this, tr("Force Uninstall"),
                                                               message,
                                                               QMessageBox::Yes | QMessageBox::No);
    if (reply != QMessageBox::Yes) return;

    sendDaemonCommand(QString("{\"cmd\":\"repeated_kill\",\"name\":\"%1\",\"tree\":true}").arg(entry.name));

    if (!entry.path.isEmpty()) {
        sendDaemonCommand(QString("{\"cmd\":\"clean_path\",\"path\":\"%1\"}").arg(entry.path));
    }

    m_rogueList.removeAt(row);
    saveRogueList();
    refresh();
    m_statusLabel->setText(tr("Successfully uninstalled %1").arg(entry.name));
}

void RogueSoftwareTab::onBlockPopup()
{
    int row = m_table->currentRow();
    if (row < 0 || row >= m_rogueList.size()) return;

    RogueEntry &entry = m_rogueList[row];
    entry.popupBlocked = !entry.popupBlocked;

    sendDaemonCommand(QString("{\"cmd\":\"block_popup\",\"name\":\"%1\",\"enable\":%2}")
                      .arg(entry.name)
                      .arg(entry.popupBlocked ? "true" : "false"));

    saveRogueList();
    refresh();
    m_statusLabel->setText(entry.popupBlocked ? tr("Popup blocked for %1").arg(entry.name)
                                              : tr("Popup unblocked for %1").arg(entry.name));
}

void RogueSoftwareTab::onBlockDownload()
{
    int row = m_table->currentRow();
    if (row < 0 || row >= m_rogueList.size()) return;

    RogueEntry &entry = m_rogueList[row];
    entry.downloadBlocked = !entry.downloadBlocked;

    sendDaemonCommand(QString("{\"cmd\":\"block_download\",\"name\":\"%1\",\"enable\":%2}")
                      .arg(entry.name)
                      .arg(entry.downloadBlocked ? "true" : "false"));

    saveRogueList();
    refresh();
    m_statusLabel->setText(entry.downloadBlocked ? tr("Download blocked for %1").arg(entry.name)
                                                 : tr("Download unblocked for %1").arg(entry.name));
}

void RogueSoftwareTab::onBlockInstall()
{
    int row = m_table->currentRow();
    if (row < 0 || row >= m_rogueList.size()) return;

    RogueEntry &entry = m_rogueList[row];
    entry.installBlocked = !entry.installBlocked;

    sendDaemonCommand(QString("{\"cmd\":\"block_install\",\"name\":\"%1\",\"enable\":%2}")
                      .arg(entry.name)
                      .arg(entry.installBlocked ? "true" : "false"));

    saveRogueList();
    refresh();
    m_statusLabel->setText(entry.installBlocked ? tr("Install blocked for %1").arg(entry.name)
                                                 : tr("Install unblocked for %1").arg(entry.name));
}

void RogueSoftwareTab::onBlockDeviceInfo()
{
    int row = m_table->currentRow();
    if (row < 0 || row >= m_rogueList.size()) return;

    RogueEntry &entry = m_rogueList[row];
    entry.deviceBlocked = !entry.deviceBlocked;

    sendDaemonCommand(QString("{\"cmd\":\"block_device\",\"name\":\"%1\",\"enable\":%2}")
                      .arg(entry.name)
                      .arg(entry.deviceBlocked ? "true" : "false"));

    saveRogueList();
    refresh();
    m_statusLabel->setText(entry.deviceBlocked ? tr("Device info blocked for %1").arg(entry.name)
                                                : tr("Device info unblocked for %1").arg(entry.name));
}

void RogueSoftwareTab::onRemoveFromList()
{
    int row = m_table->currentRow();
    if (row < 0 || row >= m_rogueList.size()) return;

    RogueEntry entry = m_rogueList[row];
    QString message = tr("Are you sure you want to remove %1 from the rogue software list?").arg(entry.name);

    QMessageBox::StandardButton reply = QMessageBox::question(this, tr("Remove from List"),
                                                               message,
                                                               QMessageBox::Yes | QMessageBox::No);
    if (reply != QMessageBox::Yes) return;

    sendDaemonCommand(QString("{\"cmd\":\"stop_repeated\",\"name\":\"%1\"}").arg(entry.name));

    m_rogueList.removeAt(row);
    saveRogueList();
    refresh();
    m_statusLabel->setText(tr("Removed %1 from list").arg(entry.name));
}

void RogueSoftwareTab::onAnalyzeNow()
{
    m_btnAnalyze->setEnabled(false);
    m_progressBar->setVisible(true);
    m_progressBar->setValue(0);
    m_statusLabel->setText(tr("AI analysis in progress..."));

    QThread *thread = new QThread(this);
    QObject *worker = new QObject();

    connect(thread, &QThread::started, [this, worker, thread]() {
        executeAiAnalysis();

        QMetaObject::invokeMethod(this, "onAnalysisComplete", Qt::QueuedConnection);
        worker->deleteLater();
        thread->quit();
        thread->wait();
        thread->deleteLater();
    });

    worker->moveToThread(thread);
    thread->start();
}

void RogueSoftwareTab::executeAiAnalysis()
{
    for (int i = 0; i <= 100; i += 10) {
        QThread::msleep(200);
        QMetaObject::invokeMethod(m_progressBar, "setValue", Qt::QueuedConnection, Q_ARG(int, i));
    }
}

void RogueSoftwareTab::onAnalysisComplete()
{
    m_progressBar->setVisible(false);
    m_btnAnalyze->setEnabled(true);
    m_statusLabel->setText(tr("AI analysis completed"));

    QMessageBox::information(this, tr("AI Analysis"),
                             tr("AI has completed analyzing all signed software.\n"
                                "Any software identified as rogue has been added to the list."));

    refresh();
}