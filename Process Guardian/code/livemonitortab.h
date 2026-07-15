#pragma once

#include <QWidget>
#include <QTableWidget>
#include <QTimer>
#include <QPushButton>
#include <windows.h>

struct ProcessSample {
    DWORD pid = 0;
    QString name;
    ULARGE_INTEGER kernelTime;
    ULARGE_INTEGER userTime;
    DWORD64 totalTime = 0;
    SIZE_T workingSet = 0;
    bool isNew = false;
    bool inRepeatedList = false;
};

class LiveMonitorTab : public QWidget
{
    Q_OBJECT

public:
    explicit LiveMonitorTab(QWidget *parent = nullptr);

public slots:
    void refresh();
    void setMonitoring(bool enabled);
    void highlightProcess(const QString &name);

private slots:
    void onTimer();
    void onContextMenu(const QPoint &pos);
    void onKill();
    void onRepeatKill();
    void onRepeatKillTree();
    void onProtect();

private:
    void setupUi();
    void updateTable(const ULARGE_INTEGER &sysIdle, const ULARGE_INTEGER &sysKernel, const ULARGE_INTEGER &sysUser);
    void addOrUpdateProcess(const ProcessSample &sample);
    bool loadRepeatedList();
    bool isProcessRepeated(const QString &name);

    QTableWidget *m_table = nullptr;
    QPushButton *m_btnToggle = nullptr;
    QTimer *m_timer = nullptr;

    QVector<ProcessSample> m_current;
    QVector<ProcessSample> m_previous;
    QSet<QString> m_repeated;
    QVector<QString> m_repeatedTree;

    ULARGE_INTEGER m_lastSysIdle;
    ULARGE_INTEGER m_lastSysKernel;
    ULARGE_INTEGER m_lastSysUser;
    bool m_hasPrevSample = false;
};
