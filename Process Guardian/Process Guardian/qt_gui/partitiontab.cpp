#include "partitiontab.h"
#include "mainwindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QLabel>
#include <QMenu>
#include <QMessageBox>
#include <QHeaderView>
#include <QFile>
#include <QTextStream>
#include <QDir>
#include <QRegularExpression>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonParseError>
#include <windows.h>
#include <winioctl.h>
#include <guiddef.h>

#pragma comment(lib, "kernel32.lib")

static const GUID GUID_PARTITION_BASIC_DATA_GUID = {0xEBD0A0A2, 0xB9E5, 0x4433, {0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7}};
static const GUID GUID_PARTITION_EFI_SYSTEM_PARTITION = {0xC12A7328, 0xF81F, 0x11D2, {0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B}};
static const GUID GUID_PARTITION_MSFT_RESERVED = {0xE3C9E316, 0x0B5C, 0x4DB8, {0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE}};
static const GUID GUID_PARTITION_RECOVERY_GUID = {0xDE94BBA4, 0x06D1, 0x4D40, {0xA1, 0x6A, 0xBF, 0xD5, 0x01, 0x79, 0xD6, 0xAC}};

static QString formatBytes(ULONGLONG bytes)
{
    if (bytes >= 1024ULL * 1024 * 1024 * 1024)
        return QString("%1 TB").arg(bytes / (1024.0 * 1024 * 1024 * 1024), 0, 'f', 2);
    if (bytes >= 1024ULL * 1024 * 1024)
        return QString("%1 GB").arg(bytes / (1024.0 * 1024 * 1024), 0, 'f', 2);
    if (bytes >= 1024ULL * 1024)
        return QString("%1 MB").arg(bytes / (1024.0 * 1024), 0, 'f', 2);
    return QString("%1 KB").arg(bytes / 1024.0, 0, 'f', 2);
}

static QString moduleDir()
{
    wchar_t buf[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, buf, MAX_PATH);
    QString path = QString::fromWCharArray(buf);
    int idx = path.lastIndexOf('\\');
    return idx >= 0 ? path.left(idx) : QDir::currentPath();
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

PartitionTab::PartitionTab(QWidget *parent)
    : QWidget(parent)
{
    setupUi();
    refresh();
}

PartitionTab::~PartitionTab()
{
}

void PartitionTab::setupUi()
{
    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setContentsMargins(8, 8, 8, 8);

    QSplitter *splitter = new QSplitter(Qt::Vertical, this);

    m_tree = new QTreeWidget(this);
    m_tree->setColumnCount(4);
    m_tree->setHeaderLabels(QStringList() << tr("Disk/Partition") << tr("Location") << tr("Type") << tr("Size"));
    m_tree->header()->setStretchLastSection(true);
    m_tree->setContextMenuPolicy(Qt::CustomContextMenu);
    splitter->addWidget(m_tree);

    QWidget *bootPanel = new QWidget(this);
    QVBoxLayout *bootLayout = new QVBoxLayout(bootPanel);
    bootLayout->setContentsMargins(0, 0, 0, 0);
    QHBoxLayout *bootHeader = new QHBoxLayout();
    m_bootLabel = new QLabel(tr("Boot sector: select a disk"), this);
    m_btnRefreshBoot = new QPushButton(tr("Refresh"), this);
    m_btnSaveBoot = new QPushButton(tr("Save changes"), this);
    bootHeader->addWidget(m_bootLabel);
    bootHeader->addStretch();
    bootHeader->addWidget(m_btnRefreshBoot);
    bootHeader->addWidget(m_btnSaveBoot);
    bootLayout->addLayout(bootHeader);
    m_bootEdit = new QPlainTextEdit(this);
    m_bootEdit->setFont(QFont("Consolas", 10));
    m_bootEdit->setReadOnly(false);
    bootLayout->addWidget(m_bootEdit);
    splitter->addWidget(bootPanel);

    QWidget *repeatPanel = new QWidget(this);
    QVBoxLayout *repeatLayout = new QVBoxLayout(repeatPanel);
    repeatLayout->setContentsMargins(0, 0, 0, 0);
    QLabel *repeatLabel = new QLabel(tr("Repeated delete list:"), this);
    m_repeatedList = new QListWidget(this);
    repeatLayout->addWidget(repeatLabel);
    repeatLayout->addWidget(m_repeatedList);
    splitter->addWidget(repeatPanel);
    splitter->setSizes(QList<int>() << 250 << 250 << 150);

    layout->addWidget(splitter);

    connect(m_tree, &QTreeWidget::customContextMenuRequested, this, &PartitionTab::onContextMenu);
    connect(m_tree, &QTreeWidget::currentItemChanged, this, &PartitionTab::onSelectionChanged);
    connect(m_btnRefreshBoot, &QPushButton::clicked, this, &PartitionTab::onRefreshBoot);
    connect(m_btnSaveBoot, &QPushButton::clicked, this, &PartitionTab::onSaveBoot);

    m_btnRefreshBoot->setEnabled(false);
    m_btnSaveBoot->setEnabled(false);
    m_bootEdit->setEnabled(false);
}

void PartitionTab::refresh()
{
    m_tree->clear();

    DWORD bytesReturned = 0;
    DWORD diskCount = 0;
    if (!GetDiskFreeSpaceExW(L"C:\\", NULL, NULL, NULL)) {
        MainWindow::appLog(tr("Failed to get disk information"));
        return;
    }

    for (int diskNum = 0; diskNum < 16; diskNum++) {
        wchar_t diskPath[64];
        swprintf(diskPath, L"\\\\.\\PhysicalDrive%d", diskNum);
        HANDLE hDrive = CreateFileW(diskPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    NULL, OPEN_EXISTING, 0, NULL);
        if (hDrive == INVALID_HANDLE_VALUE) continue;

        DISK_GEOMETRY_EX geometry = {0};
        if (DeviceIoControl(hDrive, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                            NULL, 0, &geometry, sizeof(geometry), &bytesReturned, NULL)) {
            ULONGLONG size = geometry.DiskSize.QuadPart;

            STORAGE_PROPERTY_QUERY query;
            memset(&query, 0, sizeof(query));
            query.PropertyId = (STORAGE_PROPERTY_ID)StorageAccessAlignmentProperty;
            query.QueryType = (STORAGE_QUERY_TYPE)PropertyStandardQuery;

            STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR alignmentDesc = {0};
            DeviceIoControl(hDrive, IOCTL_STORAGE_QUERY_PROPERTY,
                            &query, sizeof(query), &alignmentDesc, sizeof(alignmentDesc), &bytesReturned, NULL);

            wchar_t model[256] = {0};
            STORAGE_DEVICE_DESCRIPTOR deviceDesc = {0};
            query.PropertyId = StorageDeviceProperty;
            DWORD descSize = sizeof(deviceDesc);
            DeviceIoControl(hDrive, IOCTL_STORAGE_QUERY_PROPERTY,
                            &query, sizeof(query), &deviceDesc, descSize, &bytesReturned, NULL);
            if (deviceDesc.ProductIdOffset) {
                wcsncpy(model, (wchar_t*)((BYTE*)&deviceDesc + deviceDesc.ProductIdOffset), 255);
            }
            if (!model[0]) {
                swprintf(model, L"Disk %d", diskNum);
            }

            DWORD bytesPerSector = geometry.Geometry.BytesPerSector;
            DWORD sectorsPerTrack = geometry.Geometry.SectorsPerTrack;
            DWORD tracksPerCylinder = geometry.Geometry.TracksPerCylinder;
            ULONGLONG totalSectors = geometry.DiskSize.QuadPart / bytesPerSector;
            ULONGLONG mbrSignature = 0;
            BYTE bootSector[512] = {0};
            DWORD read = 0;
            if (ReadFile(hDrive, bootSector, 512, &read, NULL) && read == 512) {
                mbrSignature = *(DWORD*)&bootSector[510];
            }
            bool isGpt = (mbrSignature != 0xAA55);

            QTreeWidgetItem *diskItem = new QTreeWidgetItem(m_tree);
            diskItem->setText(0, QString::fromWCharArray(model));
            diskItem->setText(1, tr("PhysicalDrive%1").arg(diskNum));
            diskItem->setText(2, isGpt ? "GPT" : "MBR");
            diskItem->setText(3, formatBytes(size));
            diskItem->setData(0, Qt::UserRole, QVariantList() << diskNum << -1);

            if (!isGpt) {
                for (int partNum = 0; partNum < 4; partNum++) {
                    int offset = 446 + partNum * 16;
                    BYTE bootIndicator = bootSector[offset];
                    BYTE chsStart[3] = {bootSector[offset+1], bootSector[offset+2], bootSector[offset+3]};
                    BYTE partType = bootSector[offset+4];
                    BYTE chsEnd[3] = {bootSector[offset+5], bootSector[offset+6], bootSector[offset+7]};
                    DWORD lbaStart = *(DWORD*)&bootSector[offset+8];
                    DWORD lbaSize = *(DWORD*)&bootSector[offset+12];

                    if (partType != 0 && lbaSize > 0) {
                        QString fsType;
                        switch (partType) {
                        case 0x07: fsType = "NTFS"; break;
                        case 0x0B:
                        case 0x0C: fsType = "FAT32"; break;
                        case 0x05: fsType = "Extended"; break;
                        case 0x06: fsType = "FAT16"; break;
                        case 0x0E: fsType = "FAT16 (LBA)"; break;
                        default: fsType = QString("0x%1").arg(partType, 2, 16, QChar('0')); break;
                        }

                        QTreeWidgetItem *partItem = new QTreeWidgetItem(diskItem);
                        partItem->setText(0, tr("Partition %1").arg(partNum + 1));
                        partItem->setText(1, tr("LBA:%1").arg(lbaStart));
                        partItem->setText(2, fsType);
                        partItem->setText(3, formatBytes((ULONGLONG)lbaSize * bytesPerSector));
                        partItem->setData(0, Qt::UserRole, QVariantList() << diskNum << partNum);
                    }
                }
            } else {
                ULONGLONG gptLba = 1;
                BYTE gptHeader[512] = {0};
                LARGE_INTEGER pos;
                pos.QuadPart = gptLba * bytesPerSector;
                SetFilePointerEx(hDrive, pos, NULL, FILE_BEGIN);
                if (ReadFile(hDrive, gptHeader, 512, &read, NULL) && read == 512) {
                    GUID diskGuid = *(GUID*)&gptHeader[16];
                    DWORD partCount = *(DWORD*)&gptHeader[80];
                    ULONGLONG partEntryLba = *(ULONGLONG*)&gptHeader[72];

                    BYTE partEntryBuffer[16384] = {0};
                    pos.QuadPart = partEntryLba * bytesPerSector;
                    SetFilePointerEx(hDrive, pos, NULL, FILE_BEGIN);
                    ReadFile(hDrive, partEntryBuffer, sizeof(partEntryBuffer), &read, NULL);

                    for (DWORD i = 0; i < (partCount < 128 ? partCount : (DWORD)128); i++) {
                        int entryOffset = i * 128;
                        GUID partType = *(GUID*)&partEntryBuffer[entryOffset];
                        GUID partGuid = *(GUID*)&partEntryBuffer[entryOffset + 16];
                        ULONGLONG startLba = *(ULONGLONG*)&partEntryBuffer[entryOffset + 32];
                        ULONGLONG endLba = *(ULONGLONG*)&partEntryBuffer[entryOffset + 40];
                        wchar_t partName[37] = {0};
                        for (int j = 0; j < 36; j++) {
                            partName[j] = partEntryBuffer[entryOffset + 56 + j * 2];
                        }

                        if (startLba > 0 && endLba >= startLba) {
                            QString fsType = "GPT";
                            if (IsEqualGUID(partType, GUID_PARTITION_BASIC_DATA_GUID)) fsType = "Basic Data";
                            else if (IsEqualGUID(partType, GUID_PARTITION_EFI_SYSTEM_PARTITION)) fsType = "EFI System";
                            else if (IsEqualGUID(partType, GUID_PARTITION_MSFT_RESERVED)) fsType = "MS Reserved";
                            else if (IsEqualGUID(partType, GUID_PARTITION_RECOVERY_GUID)) fsType = "Recovery";

                            QString name = QString::fromWCharArray(partName);
                            if (name.isEmpty()) name = tr("Partition %1").arg(i + 1);

                            QTreeWidgetItem *partItem = new QTreeWidgetItem(diskItem);
                            partItem->setText(0, name);
                            partItem->setText(1, tr("LBA:%1").arg(startLba));
                            partItem->setText(2, fsType);
                            partItem->setText(3, formatBytes((endLba - startLba + 1) * bytesPerSector));
                            partItem->setData(0, Qt::UserRole, QVariantList() << diskNum << (int)i);
                        }
                    }
                }
            }
        }
        CloseHandle(hDrive);
    }

    loadRepeatedList();
}

void PartitionTab::loadRepeatedList()
{
    m_repeatedList->clear();
    QString path = QDir(moduleDir()).filePath("data/repeated_part.txt");
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return;
    QTextStream in(&f);
    in.setEncoding(QStringConverter::Utf8);
    while (!in.atEnd()) {
        QString line = in.readLine().trimmed();
        if (line.isEmpty() || line.startsWith('#')) continue;
        m_repeatedList->addItem(line);
    }
}

int PartitionTab::currentDiskNumber() const
{
    QTreeWidgetItem *item = m_tree->currentItem();
    if (!item) return -1;
    QVariantList list = item->data(0, Qt::UserRole).toList();
    if (list.size() < 2) return -1;
    return list[0].toInt();
}

int PartitionTab::currentPartitionNumber() const
{
    QTreeWidgetItem *item = m_tree->currentItem();
    if (!item) return -1;
    QVariantList list = item->data(0, Qt::UserRole).toList();
    if (list.size() < 2) return -1;
    return list[1].toInt();
}

bool PartitionTab::isDiskSelected() const
{
    return currentPartitionNumber() < 0 && currentDiskNumber() >= 0;
}

QString PartitionTab::bytesToHexText(const QByteArray &data)
{
    QString text;
    for (int offset = 0; offset < data.size(); offset += 16) {
        text += QString("%1  ").arg(offset, 4, 16, QChar('0'));
        QString hexPart;
        QString asciiPart;
        for (int i = 0; i < 16; ++i) {
            if (offset + i < data.size()) {
                unsigned char c = static_cast<unsigned char>(data[offset + i]);
                hexPart += QString("%1 ").arg(c, 2, 16, QChar('0'));
                asciiPart += (c >= 32 && c < 127) ? QChar(c) : QChar('.');
            } else {
                hexPart += "   ";
                asciiPart += " ";
            }
        }
        text += hexPart + " " + asciiPart + "\n";
    }
    return text.trimmed();
}

QByteArray PartitionTab::hexTextToBytes(const QString &text, bool *ok)
{
    QByteArray result;
    if (ok) *ok = true;
    QStringList lines = text.split('\n');
    for (const QString &line : lines) {
        QString trimmed = line.trimmed();
        int space = trimmed.indexOf(' ');
        if (space > 0) trimmed = trimmed.mid(space + 1).trimmed();
        QStringList parts = trimmed.split(' ', Qt::SkipEmptyParts);
        for (const QString &part : parts) {
            if (part.size() != 2) continue;
            bool ok2 = false;
            int value = part.toInt(&ok2, 16);
            if (!ok2) { if (ok) *ok = false; continue; }
            result.append(static_cast<char>(value));
        }
    }
    return result;
}

bool PartitionTab::readBootSector(int diskNumber)
{
    wchar_t diskPath[64];
    swprintf(diskPath, L"\\\\.\\PhysicalDrive%d", diskNumber);
    HANDLE hDrive = CreateFileW(diskPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hDrive == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        MainWindow::appLog(tr("Failed to open disk %1, error=%2").arg(diskNumber).arg(err));
        return false;
    }

    BYTE bootSector[512] = {0};
    DWORD read = 0;
    BOOL ok = ReadFile(hDrive, bootSector, 512, &read, NULL);
    CloseHandle(hDrive);

    if (!ok || read != 512) {
        DWORD err = GetLastError();
        MainWindow::appLog(tr("Failed to read boot sector, error=%2").arg(err));
        return false;
    }

    QString hexText;
    for (int i = 0; i < 512; i++) {
        hexText += QString("%1 ").arg((unsigned char)bootSector[i], 2, 16, QChar('0'));
        if ((i + 1) % 16 == 0) hexText += "\n";
    }
    m_bootEdit->setPlainText(hexText.trimmed());
    return true;
}

bool PartitionTab::writeBootSector(int diskNumber)
{
    bool ok = false;
    QByteArray sector = hexTextToBytes(m_bootEdit->toPlainText(), &ok);
    if (!ok || sector.size() != 512) {
        QMessageBox::warning(nullptr, tr("Error"), tr("Invalid boot sector data. Must be exactly 512 bytes."));
        return false;
    }

    QString path = QString("\\\\.\\PhysicalDrive%1").arg(diskNumber);
    HANDLE hDrive = CreateFileW(path.toStdWString().c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDrive == INVALID_HANDLE_VALUE) return false;

    DWORD written = 0;
    BOOL okWrite = WriteFile(hDrive, sector.constData(), 512, &written, NULL);
    CloseHandle(hDrive);
    if (!okWrite || written != 512) return false;
    return true;
}

void PartitionTab::onSelectionChanged()
{
    if (isDiskSelected()) {
        int disk = currentDiskNumber();
        m_bootDisk = disk;
        m_bootLabel->setText(tr("Boot sector of disk %1").arg(disk));
        m_btnRefreshBoot->setEnabled(true);
        m_btnSaveBoot->setEnabled(true);
        m_bootEdit->setEnabled(true);
        if (!readBootSector(disk)) {
            m_bootEdit->setPlainText(tr("Failed to read boot sector."));
            m_btnSaveBoot->setEnabled(false);
        }
    } else {
        m_bootDisk = -1;
        m_bootLabel->setText(tr("Boot sector: select a disk"));
        m_btnRefreshBoot->setEnabled(false);
        m_btnSaveBoot->setEnabled(false);
        m_bootEdit->setEnabled(false);
        m_bootEdit->setPlainText(tr("Please select a disk from the tree above to view its boot sector.\n\nNote: You need to run as administrator to read/write boot sectors."));
    }
}

void PartitionTab::onRefreshBoot()
{
    if (m_bootDisk < 0) return;
    if (!readBootSector(m_bootDisk)) {
        QMessageBox::warning(this, tr("Error"), tr("Failed to read boot sector of disk %1.").arg(m_bootDisk));
    }
}

void PartitionTab::onSaveBoot()
{
    if (m_bootDisk < 0) return;
    if (QMessageBox::question(this, tr("Confirm"), tr("Write modified boot sector back to disk %1? This is dangerous.").arg(m_bootDisk)) != QMessageBox::Yes) return;
    if (writeBootSector(m_bootDisk)) {
        MainWindow::appLog(tr("Boot sector written to disk %1").arg(m_bootDisk));
        QMessageBox::information(this, tr("Success"), tr("Boot sector saved."));
    } else {
        MainWindow::appLog(tr("Failed to write boot sector to disk %1").arg(m_bootDisk));
        QMessageBox::warning(this, tr("Error"), tr("Failed to write boot sector."));
    }
}

void PartitionTab::onContextMenu(const QPoint &pos)
{
    QTreeWidgetItem *item = m_tree->itemAt(pos);
    if (!item) return;

    int disk = currentDiskNumber();
    int part = currentPartitionNumber();
    if (disk < 0 || part < 0) return; /* only partition items */

    QMenu menu(this);
    menu.addAction(tr("Delete partition"), this, &PartitionTab::onDelete);
    menu.addSeparator();
    menu.addAction(tr("Repeat delete"), this, &PartitionTab::onRepeatDelete);
    menu.exec(m_tree->viewport()->mapToGlobal(pos));
}

static bool sendPartitionCmd(const QString &cmd, int disk, int part)
{
    QString json = QString("{\"cmd\":\"%1\",\"disk\":%2,\"partition\":%3}").arg(cmd).arg(disk).arg(part);
    QString reply = sendPipeCommand(json);
    QJsonParseError err;
    QJsonDocument doc = QJsonDocument::fromJson(reply.toUtf8(), &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) return false;
    return doc.object().value("ok").toBool(false);
}

void PartitionTab::onDelete()
{
    int disk = currentDiskNumber();
    int part = currentPartitionNumber();
    if (disk < 0 || part < 0) return;
    if (QMessageBox::question(this, tr("Confirm"), tr("Delete partition %1 on disk %2?").arg(part).arg(disk)) != QMessageBox::Yes) return;
    if (sendPartitionCmd("delete_partition", disk, part)) {
        MainWindow::appLog(tr("Deleted partition: disk=%1 partition=%2").arg(disk).arg(part));
    } else {
        MainWindow::appLog(tr("Failed to delete partition: disk=%1 partition=%2").arg(disk).arg(part));
        QMessageBox::warning(this, tr("Error"), tr("Failed to delete partition"));
    }
    refresh();
}

void PartitionTab::onRepeatDelete()
{
    int disk = currentDiskNumber();
    int part = currentPartitionNumber();
    if (disk < 0 || part < 0) return;
    if (sendPartitionCmd("partition_repeated_add", disk, part)) {
        MainWindow::appLog(tr("Added partition to repeat-delete list: disk=%1 partition=%2").arg(disk).arg(part));
    } else {
        MainWindow::appLog(tr("Failed to add partition to repeat-delete list: disk=%1 partition=%2").arg(disk).arg(part));
    }
    refresh();
}

void PartitionTab::onCancelRepeat()
{
    int disk = currentDiskNumber();
    int part = currentPartitionNumber();
    if (disk < 0 || part < 0) return;
    if (sendPartitionCmd("partition_repeated_remove", disk, part)) {
        MainWindow::appLog(tr("Removed partition from repeat-delete list: disk=%1 partition=%2").arg(disk).arg(part));
    } else {
        MainWindow::appLog(tr("Failed to remove partition from repeat-delete list: disk=%1 partition=%2").arg(disk).arg(part));
    }
    refresh();
}
