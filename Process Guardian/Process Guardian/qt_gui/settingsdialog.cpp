#include "settingsdialog.h"
#include "mainwindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QDialogButtonBox>
#include <QLabel>
#include <QGroupBox>
#include <QPushButton>
#include <QSettings>
#include <QFile>
#include <QTextStream>
#include <QDir>
#include <QMessageBox>
#include <windows.h>

SettingsDialog::SettingsDialog(QWidget *parent)
    : QDialog(parent)
{
    setupUi();
    loadSettings();
    setWindowTitle(tr("Settings"));
    resize(520, 480);
}

void SettingsDialog::setupUi()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    m_tabs = new QTabWidget(this);

    /* General tab */
    QWidget *generalTab = new QWidget(this);
    QFormLayout *generalForm = new QFormLayout(generalTab);
    m_language = new QComboBox(this);
    m_language->addItem(tr("Chinese"), "zh");
    m_language->addItem(tr("English"), "en");
    generalForm->addRow(tr("Language:"), m_language);

    m_autoRefresh = new QCheckBox(tr("Enable auto refresh"), this);
    generalForm->addRow(m_autoRefresh);

    m_checkInterval = new QSpinBox(this);
    m_checkInterval->setRange(50, 60000);
    m_checkInterval->setSuffix(" ms");
    generalForm->addRow(tr("Check interval:"), m_checkInterval);

    m_reloadInterval = new QSpinBox(this);
    m_reloadInterval->setRange(1000, 600000);
    m_reloadInterval->setSuffix(" ms");
    generalForm->addRow(tr("Reload interval:"), m_reloadInterval);

    QGroupBox *svcGroup = new QGroupBox(tr("Daemon auto-start (service)"), this);
    QVBoxLayout *svcLayout = new QVBoxLayout(svcGroup);
    m_serviceStatus = new QLabel(tr("Checking..."), this);
    svcLayout->addWidget(m_serviceStatus);
    QHBoxLayout *svcBtnLayout = new QHBoxLayout();
    m_btnInstallService = new QPushButton(tr("Install & start service"), this);
    m_btnUninstallService = new QPushButton(tr("Uninstall service"), this);
    svcBtnLayout->addWidget(m_btnInstallService);
    svcBtnLayout->addWidget(m_btnUninstallService);
    svcBtnLayout->addStretch();
    svcLayout->addLayout(svcBtnLayout);
    generalForm->addRow(svcGroup);

    connect(m_btnInstallService, &QPushButton::clicked, this, &SettingsDialog::onInstallService);
    connect(m_btnUninstallService, &QPushButton::clicked, this, &SettingsDialog::onUninstallService);

    m_tabs->addTab(generalTab, tr("General"));

    /* AI tab */
    QWidget *aiTab = new QWidget(this);
    QFormLayout *aiForm = new QFormLayout(aiTab);

    m_aiAssist = new QCheckBox(tr("Enable AI assistance"), this);
    aiForm->addRow(m_aiAssist);

    m_aiThreshold = new QComboBox(this);
    m_aiThreshold->addItem("LOW", 1);
    m_aiThreshold->addItem("MEDIUM", 2);
    m_aiThreshold->addItem("HIGH", 3);
    m_aiThreshold->addItem("CONFIRMED", 4);
    aiForm->addRow(tr("AI threat threshold:"), m_aiThreshold);

    m_censusInterval = new QSpinBox(this);
    m_censusInterval->setRange(1000, 600000);
    m_censusInterval->setSuffix(" ms");
    aiForm->addRow(tr("Census interval:"), m_censusInterval);

    m_tabs->addTab(aiTab, tr("AI"));

    /* Protection tab */
    QWidget *protTab = new QWidget(this);
    QVBoxLayout *protLayout = new QVBoxLayout(protTab);
    m_regProt = new QCheckBox(tr("Registry protection"), this);
    m_partProt = new QCheckBox(tr("Partition protection"), this);
    m_sysProt = new QCheckBox(tr("System critical protection"), this);
    protLayout->addWidget(m_regProt);
    protLayout->addWidget(m_partProt);
    protLayout->addWidget(m_sysProt);
    protLayout->addStretch();
    m_tabs->addTab(protTab, tr("Protection"));

    /* Lists tab */
    QWidget *listTab = new QWidget(this);
    QVBoxLayout *listLayout = new QVBoxLayout(listTab);

    /* Trusted zones list */
    QLabel *tzLabel = new QLabel(tr("Trusted zones (absolute directory paths):"), this);
    listLayout->addWidget(tzLabel);
    QHBoxLayout *tzLayout = new QHBoxLayout();
    m_trustedZones = new QListWidget(this);
    m_trustedZones->setEditTriggers(QAbstractItemView::DoubleClicked | QAbstractItemView::EditKeyPressed);
    tzLayout->addWidget(m_trustedZones);
    QVBoxLayout *tzBtnLayout = new QVBoxLayout();
    QPushButton *btnTzAdd = new QPushButton(tr("Add"), this);
    QPushButton *btnTzRemove = new QPushButton(tr("Remove"), this);
    QPushButton *btnTzCheck = new QPushButton(tr("Check availability"), this);
    btnTzRemove->setEnabled(false);
    tzBtnLayout->addWidget(btnTzAdd);
    tzBtnLayout->addWidget(btnTzRemove);
    tzBtnLayout->addWidget(btnTzCheck);
    tzBtnLayout->addStretch();
    tzLayout->addLayout(tzBtnLayout);
    listLayout->addLayout(tzLayout);

    connect(btnTzAdd, &QPushButton::clicked, this, [this]() { addListItem(m_trustedZones); });
    connect(btnTzRemove, &QPushButton::clicked, this, [this]() { removeSelectedListItem(m_trustedZones); });
    connect(btnTzCheck, &QPushButton::clicked, this, [this]() { checkListPaths(m_trustedZones, true); });
    connect(m_trustedZones, &QListWidget::itemSelectionChanged, this, [this, btnTzRemove]() {
        btnTzRemove->setEnabled(!m_trustedZones->selectedItems().isEmpty());
    });
    connect(m_trustedZones, &QListWidget::itemChanged, this, &SettingsDialog::onListItemChanged);

    /* Manual common processes list */
    QLabel *mcLabel = new QLabel(tr("Manual common processes (process names or base names):"), this);
    listLayout->addWidget(mcLabel);
    QHBoxLayout *mcLayout = new QHBoxLayout();
    m_manualCommon = new QListWidget(this);
    m_manualCommon->setEditTriggers(QAbstractItemView::DoubleClicked | QAbstractItemView::EditKeyPressed);
    mcLayout->addWidget(m_manualCommon);
    QVBoxLayout *mcBtnLayout = new QVBoxLayout();
    QPushButton *btnMcAdd = new QPushButton(tr("Add"), this);
    QPushButton *btnMcRemove = new QPushButton(tr("Remove"), this);
    QPushButton *btnMcCheck = new QPushButton(tr("Check availability"), this);
    btnMcRemove->setEnabled(false);
    mcBtnLayout->addWidget(btnMcAdd);
    mcBtnLayout->addWidget(btnMcRemove);
    mcBtnLayout->addWidget(btnMcCheck);
    mcBtnLayout->addStretch();
    mcLayout->addLayout(mcBtnLayout);
    listLayout->addLayout(mcLayout);

    connect(btnMcAdd, &QPushButton::clicked, this, [this]() { addListItem(m_manualCommon); });
    connect(btnMcRemove, &QPushButton::clicked, this, [this]() { removeSelectedListItem(m_manualCommon); });
    connect(btnMcCheck, &QPushButton::clicked, this, [this]() { checkListPaths(m_manualCommon, false); });
    connect(m_manualCommon, &QListWidget::itemSelectionChanged, this, [this, btnMcRemove]() {
        btnMcRemove->setEnabled(!m_manualCommon->selectedItems().isEmpty());
    });
    connect(m_manualCommon, &QListWidget::itemChanged, this, &SettingsDialog::onListItemChanged);

    m_tabs->addTab(listTab, tr("Lists"));

    mainLayout->addWidget(m_tabs);

    QDialogButtonBox *buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, this);
    connect(buttons, &QDialogButtonBox::accepted, this, &SettingsDialog::onSave);
    connect(buttons, &QDialogButtonBox::rejected, this, &SettingsDialog::onCancel);
    mainLayout->addWidget(buttons);
}

QString SettingsDialog::dataPath(const QString &name)
{
    wchar_t buf[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, buf, MAX_PATH);
    QString path = QString::fromWCharArray(buf);
    int idx = path.lastIndexOf('\\');
    if (idx >= 0) path = path.left(idx);
    return path + "\\data\\" + name;
}

static bool isServiceInstalled()
{
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return false;
    SC_HANDLE hSvc = OpenServiceW(hSCM, L"GuardianDaemon", SERVICE_QUERY_CONFIG);
    bool installed = hSvc != NULL;
    if (hSvc) CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return installed;
}

static bool isServiceAutoStart()
{
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return false;
    SC_HANDLE hSvc = OpenServiceW(hSCM, L"GuardianDaemon", SERVICE_QUERY_CONFIG);
    if (!hSvc) { CloseServiceHandle(hSCM); return false; }
    QUERY_SERVICE_CONFIGW cfg = {0};
    DWORD needed = 0;
    bool autoStart = false;
    if (QueryServiceConfigW(hSvc, &cfg, sizeof(cfg), &needed)) {
        autoStart = (cfg.dwStartType == SERVICE_AUTO_START);
    }
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return autoStart;
}

static void updateServiceStatusLabel(QLabel *label)
{
    if (isServiceInstalled()) {
        if (isServiceAutoStart())
            label->setText(QObject::tr("Status: Installed (Auto-start enabled)"));
        else
            label->setText(QObject::tr("Status: Installed but not auto-start"));
    } else {
        label->setText(QObject::tr("Status: Not installed"));
    }
}

static bool runInstallService(const wchar_t *params)
{
    wchar_t dir[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, dir, MAX_PATH);
    wchar_t *p = wcsrchr(dir, L'\\');
    if (p) *p = L'\0';
    wchar_t path[MAX_PATH];
    swprintf(path, MAX_PATH, L"%s\\permission\\install_service.exe", dir);

    SHELLEXECUTEINFOW sei = {0};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";
    sei.lpFile = path;
    sei.lpParameters = params;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    sei.nShow = SW_HIDE;
    if (!ShellExecuteExW(&sei)) return false;
    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, 30000);
        CloseHandle(sei.hProcess);
    }
    return true;
}

static QString readTextFile(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return QString();
    QTextStream in(&f);
    in.setEncoding(QStringConverter::Utf8);
    return in.readAll();
}

static bool writeTextFile(const QString &path, const QString &text)
{
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) return false;
    QTextStream out(&f);
    out.setEncoding(QStringConverter::Utf8);
    out << text;
    return true;
}

void SettingsDialog::loadSettings()
{
    QSettings s(dataPath("settings.ini"), QSettings::IniFormat);

    QString lang = s.value("UI/Language", "zh").toString();
    int langIdx = m_language->findData(lang);
    if (langIdx >= 0) m_language->setCurrentIndex(langIdx);

    m_autoRefresh->setChecked(s.value("Settings/AutoRefresh", 1).toInt() != 0);
    m_checkInterval->setValue(s.value("Settings/CheckInterval", 500).toInt());
    m_reloadInterval->setValue(s.value("Settings/ReloadInterval", 30000).toInt());
    m_censusInterval->setValue(s.value("Settings/CensusInterval", 30000).toInt());

    m_aiAssist->setChecked(s.value("Protection/AiAssist", 0).toInt() != 0);
    int threshold = s.value("Protection/AiThreatThreshold", 3).toInt();
    if (threshold < 1 || threshold > 4) threshold = 3;
    m_aiThreshold->setCurrentIndex(threshold - 1);

    m_regProt->setChecked(s.value("Protection/RegProtection", 1).toInt() != 0);
    m_partProt->setChecked(s.value("Protection/PartProtection", 1).toInt() != 0);
    m_sysProt->setChecked(s.value("Protection/SysCriticalProtection", 1).toInt() != 0);

    loadListFromFile(m_trustedZones, dataPath("trusted_zones.txt"));
    loadListFromFile(m_manualCommon, dataPath("manual_common.txt"));

    updateServiceStatusLabel(m_serviceStatus);
}

void SettingsDialog::onSave()
{
    if (m_checkInterval->value() < 50 || m_reloadInterval->value() < 1000) {
        QMessageBox::warning(this, tr("Input error"), tr("Check interval >= 50ms, reload interval >= 1000ms"));
        return;
    }

    QSettings s(dataPath("settings.ini"), QSettings::IniFormat);
    s.setValue("UI/Language", m_language->currentData().toString());
    s.setValue("Settings/AutoRefresh", m_autoRefresh->isChecked() ? 1 : 0);
    s.setValue("Settings/CheckInterval", m_checkInterval->value());
    s.setValue("Settings/ReloadInterval", m_reloadInterval->value());
    s.setValue("Settings/CensusInterval", m_censusInterval->value());

    s.setValue("Protection/AiAssist", m_aiAssist->isChecked() ? 1 : 0);
    s.setValue("Protection/AiThreatThreshold", m_aiThreshold->currentData().toInt());
    s.setValue("Protection/CensusInterval", m_censusInterval->value());
    s.setValue("Protection/RegProtection", m_regProt->isChecked() ? 1 : 0);
    s.setValue("Protection/PartProtection", m_partProt->isChecked() ? 1 : 0);
    s.setValue("Protection/SysCriticalProtection", m_sysProt->isChecked() ? 1 : 0);

    saveListToFile(m_trustedZones, dataPath("trusted_zones.txt"));
    saveListToFile(m_manualCommon, dataPath("manual_common.txt"));

    accept();
}

void SettingsDialog::onCancel()
{
    reject();
}

void SettingsDialog::loadListFromFile(QListWidget *list, const QString &path)
{
    list->clear();
    QString text = readTextFile(path);
    QStringList lines = text.split('\n', Qt::SkipEmptyParts);
    for (QString line : lines) {
        line = line.trimmed();
        if (line.isEmpty() || line.startsWith('#')) continue;
        QListWidgetItem *item = new QListWidgetItem(line);
        item->setFlags(item->flags() | Qt::ItemIsEditable);
        list->addItem(item);
    }
}

void SettingsDialog::saveListToFile(QListWidget *list, const QString &path)
{
    QStringList lines;
    for (int i = 0; i < list->count(); ++i) {
        QString text = list->item(i)->text().trimmed();
        if (!text.isEmpty()) lines.append(text);
    }
    writeTextFile(path, lines.join('\n'));
}

void SettingsDialog::addListItem(QListWidget *list)
{
    QListWidgetItem *item = new QListWidgetItem("");
    item->setFlags(item->flags() | Qt::ItemIsEditable);
    list->addItem(item);
    list->setCurrentItem(item);
    list->editItem(item);
}

void SettingsDialog::removeSelectedListItem(QListWidget *list)
{
    QList<QListWidgetItem*> selected = list->selectedItems();
    for (QListWidgetItem *item : selected) {
        delete list->takeItem(list->row(item));
    }
}

void SettingsDialog::checkListPaths(QListWidget *list, bool isPath)
{
    QStringList missing;
    QStringList ok;
    for (int i = 0; i < list->count(); ++i) {
        QString text = list->item(i)->text().trimmed();
        if (text.isEmpty()) continue;
        if (isPath) {
            QDir d(text);
            if (d.exists()) ok.append(text);
            else missing.append(text);
        } else {
            /* For process names, just check it looks like a process name */
            if (text.endsWith(".exe", Qt::CaseInsensitive) || text.contains('.')) ok.append(text);
            else missing.append(text + " (should end with .exe or be a base name)");
        }
    }

    QString msg;
    if (!ok.isEmpty()) {
        msg += tr("Available (%1):\n").arg(ok.size()) + ok.join("\n");
    }
    if (!missing.isEmpty()) {
        if (!msg.isEmpty()) msg += "\n\n";
        msg += tr("Unavailable / invalid (%1):\n").arg(missing.size()) + missing.join("\n");
    }
    if (msg.isEmpty()) msg = tr("List is empty.");
    QMessageBox::information(this, tr("Availability check"), msg);
}

void SettingsDialog::onListItemChanged(QListWidgetItem *item)
{
    if (!item) return;
    if (item->text().trimmed().isEmpty()) {
        QListWidget *list = item->listWidget();
        if (list) delete list->takeItem(list->row(item));
    }
}

void SettingsDialog::onInstallService()
{
    if (runInstallService(L"install")) {
        MainWindow::appLog(tr("Installed GuardianDaemon service (auto-start)"));
        QMessageBox::information(this, tr("Service"), tr("GuardianDaemon service installed and started."));
    } else {
        MainWindow::appLog(tr("Failed to install GuardianDaemon service"));
        QMessageBox::warning(this, tr("Error"), tr("Failed to install service. Make sure you run as Administrator."));
    }
    updateServiceStatusLabel(m_serviceStatus);
}

void SettingsDialog::onUninstallService()
{
    if (runInstallService(L"uninstall")) {
        MainWindow::appLog(tr("Uninstalled GuardianDaemon service"));
        QMessageBox::information(this, tr("Service"), tr("GuardianDaemon service uninstalled."));
    } else {
        MainWindow::appLog(tr("Failed to uninstall GuardianDaemon service"));
        QMessageBox::warning(this, tr("Error"), tr("Failed to uninstall service. Make sure you run as Administrator."));
    }
    updateServiceStatusLabel(m_serviceStatus);
}
