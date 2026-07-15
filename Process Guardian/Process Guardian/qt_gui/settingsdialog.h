#pragma once

#include <QDialog>
#include <QLineEdit>
#include <QComboBox>
#include <QSpinBox>
#include <QCheckBox>
#include <QTextEdit>
#include <QListWidget>
#include <QListWidgetItem>
#include <QTabWidget>
#include <QLabel>
#include <QPushButton>

class SettingsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SettingsDialog(QWidget *parent = nullptr);

private slots:
    void onSave();
    void onCancel();
    void onInstallService();
    void onUninstallService();
    void onListItemChanged(QListWidgetItem *item);

private:
    void setupUi();
    void loadSettings();
    QString dataPath(const QString &name);
    void loadListFromFile(QListWidget *list, const QString &path);
    void saveListToFile(QListWidget *list, const QString &path);
    void addListItem(QListWidget *list);
    void removeSelectedListItem(QListWidget *list);
    void checkListPaths(QListWidget *list, bool isPath);

    QTabWidget *m_tabs = nullptr;

    /* General */
    QComboBox *m_language = nullptr;
    QCheckBox *m_autoRefresh = nullptr;
    QSpinBox *m_checkInterval = nullptr;
    QSpinBox *m_reloadInterval = nullptr;
    QLabel *m_serviceStatus = nullptr;
    QPushButton *m_btnInstallService = nullptr;
    QPushButton *m_btnUninstallService = nullptr;

    /* AI */
    QCheckBox *m_aiAssist = nullptr;
    QComboBox *m_aiThreshold = nullptr;
    QSpinBox *m_censusInterval = nullptr;

    /* Protection */
    QCheckBox *m_regProt = nullptr;
    QCheckBox *m_partProt = nullptr;
    QCheckBox *m_sysProt = nullptr;

    /* Lists */
    QListWidget *m_trustedZones = nullptr;
    QListWidget *m_manualCommon = nullptr;
};
