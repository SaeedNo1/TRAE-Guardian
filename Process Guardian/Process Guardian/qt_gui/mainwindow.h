#pragma once

#include <QMainWindow>
#include <QTabWidget>
#include <QToolBar>
#include <QPushButton>
#include <QToolButton>
#include <QTimer>
#include <QLabel>

class ProcessTab;
class ServiceTab;
class RegistryTab;
class PartitionTab;
class AichatTab;
class LiveMonitorTab;
class AiHubTab;
class RogueSoftwareTab;

struct NotificationItem {
    QString timestamp;
    QString level;
    QString task;
    QString taskId;
    QString proc;
    QString pid;
    QString path;
    QString reason;
    QString raw;
};

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

    static void appLog(const QString &message);

public slots:
    void openGlobalChat();
    bool showPopupConfirmation(const QString &title, const QString &message,
                               const QString &proc, const QString &path);

private slots:
    void onRefresh();
    void onCheckDaemonStatus();
    void onDailyReport();
    void onStartDaemon();
    void onStartAdmin();
    void onStartSystem();
    void onStopDaemon();
    void onOpenSettings();
    void onOpenAiHub();
    void onCheckNotifications();
    void onAutoRefreshToggled(bool checked);
    void onCheckPopupFlag();
    void onLiveMonitorRequested(const QString &processName);
    void onCreateAiTaskRequested(const QString &processName);
    void onDaemonStartComplete(bool success, const QString &modeLabel);
    void onAdminStartComplete(bool success);
    void onSystemStartComplete(bool success);

private:
    void setupUi();
    void setupToolbar();
    void scheduleNextDailyReport();
    void sendPipeCommand(const QString &json);
    void executeCleanupFromFlag(const QString &flagContent);
    void startPopupServer();
    void stopPopupServer();
    void showNotificationDetail(const NotificationItem &ni);

    void *m_popupThreadHandle = nullptr;

public:
    bool m_popupStop = false;

private:
    QTabWidget *m_tabWidget = nullptr;
    QToolBar *m_toolBar = nullptr;
    QPushButton *m_btnRefresh = nullptr;
    QToolButton *m_btnDaemon = nullptr;
    QPushButton *m_btnSettings = nullptr;
    QPushButton *m_btnAiHub = nullptr;
    QPushButton *m_btnBell = nullptr;
    QPushButton *m_btnAutoRefresh = nullptr;
    QLabel *m_statusLabel = nullptr;
    QTimer *m_refreshTimer = nullptr;
    QTimer *m_daemonStatusTimer = nullptr;
    QTimer *m_dailyReportTimer = nullptr;
    QTimer *m_popupTimer = nullptr;

    ProcessTab *m_processTab = nullptr;
    ServiceTab *m_serviceTab = nullptr;
    RegistryTab *m_registryTab = nullptr;
    PartitionTab *m_partitionTab = nullptr;
    AichatTab *m_aiChatTab = nullptr;
    LiveMonitorTab *m_liveMonitorTab = nullptr;
    AiHubTab *m_aiHubTab = nullptr;
    RogueSoftwareTab *m_rogueSoftwareTab = nullptr;
};
