#pragma once

#include <QWidget>
#include <QTableWidget>
#include <QPushButton>
#include <QLineEdit>
#include <QTimer>
#include <QProgressBar>
#include <QLabel>
#include <QDateTime>
#include <QSet>

class RogueSoftwareTab : public QWidget
{
    Q_OBJECT

public:
    explicit RogueSoftwareTab(QWidget *parent = nullptr);

public slots:
    void refresh();

private slots:
    void onRefresh();
    void onForceUninstall();
    void onBlockPopup();
    void onBlockDownload();
    void onBlockInstall();
    void onBlockDeviceInfo();
    void onRemoveFromList();
    void onSearchTextChanged(const QString &text);
    void onAnalyzeNow();
    void onSelectionChanged();
    void onAnalysisComplete();

private:
    void setupUi();
    void loadRogueList();
    void saveRogueList();
    void addRogueEntry(const QString &name, const QString &path, const QString &signer,
                       int popupCount, int downloadCount, const QString &lastDetect);
    void sendDaemonCommand(const QString &json);
    bool isProcessRunning(const QString &name);
    QSet<QString> getRunningProcessNames();
    void executeAiAnalysis();

    struct RogueEntry {
        QString name;
        QString path;
        QString signer;
        int popupCount;
        int downloadCount;
        QString lastDetect;
        bool popupBlocked;
        bool downloadBlocked;
        bool installBlocked;
        bool deviceBlocked;
    };

    QTableWidget *m_table = nullptr;
    QLineEdit *m_searchEdit = nullptr;
    QPushButton *m_btnRefresh = nullptr;
    QPushButton *m_btnAnalyze = nullptr;
    QPushButton *m_btnUninstall = nullptr;
    QPushButton *m_btnBlockPopup = nullptr;
    QPushButton *m_btnBlockDownload = nullptr;
    QPushButton *m_btnBlockInstall = nullptr;
    QPushButton *m_btnBlockDevice = nullptr;
    QPushButton *m_btnRemove = nullptr;
    QProgressBar *m_progressBar = nullptr;
    QLabel *m_statusLabel = nullptr;
    QTimer *m_refreshTimer = nullptr;

    QList<RogueEntry> m_rogueList;
};