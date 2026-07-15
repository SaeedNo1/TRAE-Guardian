#pragma once

#include <windows.h>
#include <QWidget>
#include <QTreeWidget>
#include <QListWidget>
#include <QComboBox>

struct RegistryEntry;

class RegistryTab : public QWidget
{
    Q_OBJECT

public:
    explicit RegistryTab(QWidget *parent = nullptr);
    ~RegistryTab();

public slots:
    void refresh();

private slots:
    void onRootChanged(int index);
    void onTreeItemExpanded(QTreeWidgetItem *item);
    void onContextMenu(const QPoint &pos);
    void onRepeatDelete();
    void onOpenFileLocation();
    void onEditValue();
    void onDeleteKey();
    void onDeleteSelectedKeys();
    void onProtect();

private:
    void setupUi();
    void loadDll();
    void initRootKeys();
    void enumerateChildren(QTreeWidgetItem *parent);
    QString currentRegPath() const;
    QString currentRegName() const;
    void loadRepeatedList();
    void openRegistryInRegedit(const QString &path);
    QString getDefaultValuePath(const QString &regPath);

    QComboBox *m_rootSelector = nullptr;
    QTreeWidget *m_tree = nullptr;
    QListWidget *m_repeatedList = nullptr;
    HMODULE m_hDll = nullptr;

    struct RootKey {
        QString name;
        HKEY hkey;
    };
    QVector<RootKey> m_roots;

    using FnAddRegRepeated = void (*)(const wchar_t *);
    using FnRemoveRegRepeated = void (*)(const wchar_t *);
    using FnIsRegRepeated = BOOL (*)(const wchar_t *);

    FnAddRegRepeated m_addRep = nullptr;
    FnRemoveRegRepeated m_remRep = nullptr;
    FnIsRegRepeated m_isRep = nullptr;
};
