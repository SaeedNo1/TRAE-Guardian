#include "registrytab.h"
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
#include <QProcess>
#include <shellapi.h>

struct RegistryEntry {
    wchar_t name[256];
    wchar_t path[512];
    wchar_t value[1024];
    wchar_t type[64];
    DWORD   dwType;
};

static QString moduleDir()
{
    wchar_t buf[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, buf, MAX_PATH);
    QString path = QString::fromWCharArray(buf);
    int idx = path.lastIndexOf('\\');
    return idx >= 0 ? path.left(idx) : QDir::currentPath();
}

static bool parseRegPath(const QString &fullPath, HKEY *root, QString *subPath)
{
    int slash = fullPath.indexOf('\\');
    QString rootName = slash < 0 ? fullPath : fullPath.left(slash);
    if (rootName.compare("HKEY_LOCAL_MACHINE", Qt::CaseInsensitive) == 0) *root = HKEY_LOCAL_MACHINE;
    else if (rootName.compare("HKEY_CURRENT_USER", Qt::CaseInsensitive) == 0) *root = HKEY_CURRENT_USER;
    else if (rootName.compare("HKEY_CLASSES_ROOT", Qt::CaseInsensitive) == 0) *root = HKEY_CLASSES_ROOT;
    else if (rootName.compare("HKEY_USERS", Qt::CaseInsensitive) == 0) *root = HKEY_USERS;
    else if (rootName.compare("HKEY_CURRENT_CONFIG", Qt::CaseInsensitive) == 0) *root = HKEY_CURRENT_CONFIG;
    else return false;
    *subPath = slash < 0 ? QString() : fullPath.mid(slash + 1);
    return true;
}

RegistryTab::RegistryTab(QWidget *parent)
    : QWidget(parent)
{
    setupUi();
    loadDll();
    initRootKeys();
    refresh();
}

RegistryTab::~RegistryTab()
{
    if (m_hDll) FreeLibrary(m_hDll);
}

void RegistryTab::setupUi()
{
    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setContentsMargins(8, 8, 8, 8);

    QHBoxLayout *topLayout = new QHBoxLayout();
    QLabel *rootLabel = new QLabel(tr("Root key:"), this);
    m_rootSelector = new QComboBox(this);
    topLayout->addWidget(rootLabel);
    topLayout->addWidget(m_rootSelector);
    topLayout->addStretch();
    layout->addLayout(topLayout);

    QSplitter *splitter = new QSplitter(Qt::Vertical, this);

    m_tree = new QTreeWidget(this);
    m_tree->setColumnCount(1);
    m_tree->setHeaderLabel(tr("Registry keys"));
    m_tree->header()->setStretchLastSection(true);
    m_tree->setContextMenuPolicy(Qt::CustomContextMenu);
    m_tree->setSelectionMode(QAbstractItemView::ExtendedSelection);
    splitter->addWidget(m_tree);

    QWidget *repeatPanel = new QWidget(this);
    QVBoxLayout *repeatLayout = new QVBoxLayout(repeatPanel);
    repeatLayout->setContentsMargins(0, 0, 0, 0);
    QLabel *repeatLabel = new QLabel(tr("Repeated delete list:"), this);
    m_repeatedList = new QListWidget(this);
    repeatLayout->addWidget(repeatLabel);
    repeatLayout->addWidget(m_repeatedList);
    splitter->addWidget(repeatPanel);
    splitter->setSizes(QList<int>() << 400 << 150);

    layout->addWidget(splitter);

    connect(m_rootSelector, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &RegistryTab::onRootChanged);
    connect(m_tree, &QTreeWidget::itemExpanded, this, &RegistryTab::onTreeItemExpanded);
    connect(m_tree, &QTreeWidget::customContextMenuRequested, this, &RegistryTab::onContextMenu);
}

void RegistryTab::loadDll()
{
    QString dir = moduleDir();
    QString dll = dir + "\\registry_manager.dll";
    m_hDll = LoadLibraryW(dll.toStdWString().c_str());
    if (!m_hDll) return;

    m_addRep = (FnAddRegRepeated)GetProcAddress(m_hDll, "AddToRepeatedDeleteList");
    m_remRep = (FnRemoveRegRepeated)GetProcAddress(m_hDll, "RemoveFromRepeatedDeleteList");
    m_isRep = (FnIsRegRepeated)GetProcAddress(m_hDll, "IsRegistryRepeatedDelete");
}

void RegistryTab::initRootKeys()
{
    m_roots = {
        { "HKEY_LOCAL_MACHINE", HKEY_LOCAL_MACHINE },
        { "HKEY_CURRENT_USER", HKEY_CURRENT_USER },
        { "HKEY_CLASSES_ROOT", HKEY_CLASSES_ROOT },
        { "HKEY_USERS", HKEY_USERS },
        { "HKEY_CURRENT_CONFIG", HKEY_CURRENT_CONFIG }
    };
    for (const auto &r : m_roots) m_rootSelector->addItem(r.name);
}

void RegistryTab::onRootChanged(int index)
{
    if (index < 0 || index >= m_roots.size()) return;
    m_tree->clear();
    QTreeWidgetItem *root = new QTreeWidgetItem(m_tree);
    root->setText(0, m_roots[index].name);
    root->setData(0, Qt::UserRole, m_roots[index].name);
    root->setChildIndicatorPolicy(QTreeWidgetItem::ShowIndicator);
    m_tree->addTopLevelItem(root);
    loadRepeatedList();
}

void RegistryTab::enumerateChildren(QTreeWidgetItem *parent)
{
    if (!parent) return;
    QString fullPath = parent->data(0, Qt::UserRole).toString();
    HKEY root;
    QString subPath;
    if (!parseRegPath(fullPath, &root, &subPath)) return;

    HKEY hKey = NULL;
    LONG res = RegOpenKeyExW(root, subPath.toStdWString().c_str(), 0, KEY_READ, &hKey);
    if (res != ERROR_SUCCESS) return;

    DWORD idx = 0;
    wchar_t name[256];
    DWORD nameSize;
    FILETIME ft;
    while (true) {
        nameSize = 256;
        res = RegEnumKeyExW(hKey, idx, name, &nameSize, NULL, NULL, NULL, &ft);
        if (res != ERROR_SUCCESS) break;
        QTreeWidgetItem *child = new QTreeWidgetItem(parent);
        child->setText(0, QString::fromWCharArray(name));
        QString childPath = fullPath + "\\" + QString::fromWCharArray(name);
        child->setData(0, Qt::UserRole, childPath);
        child->setChildIndicatorPolicy(QTreeWidgetItem::ShowIndicator);
        idx++;
    }
    RegCloseKey(hKey);
}

void RegistryTab::onTreeItemExpanded(QTreeWidgetItem *item)
{
    if (!item) return;
    bool loaded = item->data(0, Qt::UserRole + 1).toBool();
    if (loaded) return;
    enumerateChildren(item);
    item->setData(0, Qt::UserRole + 1, true);
}

QString RegistryTab::currentRegPath() const
{
    QTreeWidgetItem *item = m_tree->currentItem();
    if (!item) return QString();
    return item->data(0, Qt::UserRole).toString();
}

QString RegistryTab::currentRegName() const
{
    QTreeWidgetItem *item = m_tree->currentItem();
    if (!item) return QString();
    return item->text(0);
}

void RegistryTab::refresh()
{
    onRootChanged(m_rootSelector->currentIndex());
}

void RegistryTab::loadRepeatedList()
{
    m_repeatedList->clear();
    QString path = QDir(moduleDir()).filePath("data/repeated_reg.txt");
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

QString RegistryTab::getDefaultValuePath(const QString &regPath)
{
    HKEY root;
    QString subPath;
    if (!parseRegPath(regPath, &root, &subPath)) return QString();

    HKEY hKey = NULL;
    if (RegOpenKeyExW(root, subPath.toStdWString().c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return QString();

    DWORD type = 0;
    DWORD size = 0;
    LONG res = RegQueryValueExW(hKey, NULL, NULL, &type, NULL, &size);
    if (res != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) {
        RegCloseKey(hKey);
        return QString();
    }

    QByteArray buf(size, 0);
    res = RegQueryValueExW(hKey, NULL, NULL, &type, (LPBYTE)buf.data(), &size);
    RegCloseKey(hKey);
    if (res != ERROR_SUCCESS) return QString();

    QString value = QString::fromWCharArray((const wchar_t*)buf.constData());
    value = value.trimmed();

    /* Expand environment strings like %SystemRoot% */
    if (type == REG_EXPAND_SZ) {
        wchar_t expanded[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(value.toStdWString().c_str(), expanded, MAX_PATH * 2);
        value = QString::fromWCharArray(expanded);
    }

    /* Strip quotes and arguments */
    if (value.startsWith('"') && value.mid(1).contains('"')) {
        int end = value.indexOf('"', 1);
        value = value.mid(1, end - 1);
    } else {
        int space = value.indexOf(' ');
        if (space > 0) value = value.left(space);
    }

    if (QFile::exists(value)) return value;
    return QString();
}

void RegistryTab::openRegistryInRegedit(const QString &path)
{
    QProcess::startDetached("regedit.exe", QStringList());
    Q_UNUSED(path)
}

void RegistryTab::onContextMenu(const QPoint &pos)
{
    QTreeWidgetItem *item = m_tree->itemAt(pos);
    if (!item) return;
    m_tree->setCurrentItem(item);

    QList<QTreeWidgetItem*> selected = m_tree->selectedItems();
    bool multi = selected.size() > 1;

    QMenu menu(this);
    QString path = currentRegPath();
    menu.addAction(tr("Edit value"), this, &RegistryTab::onEditValue);
    
    if (!multi) {
        menu.addAction(tr("Delete key"), this, &RegistryTab::onDeleteKey);
    } else {
        menu.addAction(tr("Delete selected keys"), this, &RegistryTab::onDeleteSelectedKeys);
    }
    
    menu.addSeparator();

    bool repeated = m_isRep ? m_isRep(path.toStdWString().c_str()) : FALSE;
    if (repeated)
        menu.addAction(tr("Cancel repeat delete"), this, &RegistryTab::onRepeatDelete);
    else
        menu.addAction(tr("Repeat delete"), this, &RegistryTab::onRepeatDelete);

    if (!getDefaultValuePath(path).isEmpty())
        menu.addAction(tr("Open file location"), this, &RegistryTab::onOpenFileLocation);

    menu.exec(m_tree->viewport()->mapToGlobal(pos));
}

void RegistryTab::onRepeatDelete()
{
    if (!m_addRep || !m_remRep) return;

    QList<QTreeWidgetItem*> selected = m_tree->selectedItems();
    if (selected.isEmpty()) return;

    for (QTreeWidgetItem *item : selected) {
        QString path = item->data(0, Qt::UserRole).toString();
        if (path.isEmpty()) continue;
        bool repeated = m_isRep ? m_isRep(path.toStdWString().c_str()) : FALSE;
        if (repeated) {
            m_remRep(path.toStdWString().c_str());
            MainWindow::appLog(tr("Removed registry entry from repeat-delete list: %1").arg(path));
        } else {
            m_addRep(path.toStdWString().c_str());
            MainWindow::appLog(tr("Added registry entry to repeat-delete list: %1").arg(path));
        }
    }
    loadRepeatedList();
}

void RegistryTab::onOpenFileLocation()
{
    QString path = currentRegPath();
    QString filePath = getDefaultValuePath(path);
    if (filePath.isEmpty()) {
        QMessageBox::warning(this, tr("Error"), tr("This key does not have a valid file path in its default value."));
        return;
    }
    QFileInfo fi(filePath);
    QString dir = fi.absolutePath();
    QString arg = "/select," + filePath;
    ShellExecuteW(NULL, L"open", L"explorer.exe", arg.toStdWString().c_str(), NULL, SW_SHOWNORMAL);
    MainWindow::appLog(tr("Opened file location for registry key: %1 -> %2").arg(path).arg(filePath));
}

void RegistryTab::onEditValue()
{
    QString path = currentRegPath();
    if (path.isEmpty()) return;
    openRegistryInRegedit(path);
    MainWindow::appLog(tr("Opened registry editor for: %1").arg(path));
}

void RegistryTab::onDeleteKey()
{
    QString path = currentRegPath();
    QString name = currentRegName();
    if (path.isEmpty()) return;
    if (QMessageBox::question(this, tr("Confirm"), tr("Delete registry key %1?").arg(name)) != QMessageBox::Yes) return;

    HKEY root;
    QString subPath;
    if (!parseRegPath(path, &root, &subPath)) {
        QMessageBox::warning(this, tr("Error"), tr("Invalid registry path"));
        return;
    }

    LONG res = RegDeleteKeyW(root, subPath.toStdWString().c_str());
    if (res == ERROR_SUCCESS) {
        MainWindow::appLog(tr("Deleted registry key: %1").arg(path));
        refresh();
    } else {
        MainWindow::appLog(tr("Failed to delete registry key: %1").arg(path));
        QMessageBox::warning(this, tr("Error"), tr("Failed to delete %1").arg(name));
    }
}

void RegistryTab::onDeleteSelectedKeys()
{
    QList<QTreeWidgetItem*> selected = m_tree->selectedItems();
    if (selected.isEmpty()) return;

    int count = selected.size();
    if (QMessageBox::question(this, tr("Confirm"),
        tr("Delete %1 selected registry keys?\n\nThis action cannot be undone.").arg(count)) != QMessageBox::Yes) {
        return;
    }

    int success = 0;
    int failed = 0;

    for (QTreeWidgetItem *item : selected) {
        QString path = item->data(0, Qt::UserRole).toString();
        if (path.isEmpty()) continue;

        HKEY root;
        QString subPath;
        if (!parseRegPath(path, &root, &subPath)) {
            failed++;
            continue;
        }

        LONG res = RegDeleteKeyW(root, subPath.toStdWString().c_str());
        if (res == ERROR_SUCCESS) {
            MainWindow::appLog(tr("Deleted registry key: %1").arg(path));
            success++;
        } else {
            MainWindow::appLog(tr("Failed to delete registry key: %1").arg(path));
            failed++;
        }
    }

    refresh();

    QString msg;
    if (failed == 0) {
        msg = tr("Successfully deleted %1 registry keys.").arg(success);
    } else if (success == 0) {
        msg = tr("Failed to delete %1 registry keys.").arg(failed);
    } else {
        msg = tr("Deleted %1 registry keys successfully, %2 failed.").arg(success).arg(failed);
    }
    
    QMessageBox::information(this, tr("Result"), msg);
}

void RegistryTab::onProtect()
{
    QString path = currentRegPath();
    if (path.isEmpty()) return;
    MainWindow::appLog(tr("Protect registry key: %1 (placeholder)").arg(path));
}
