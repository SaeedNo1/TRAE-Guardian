#pragma once

#include <QWidget>
#include <QTableWidget>
#include <QSplitter>
#include <QPushButton>
#include <QLineEdit>
#include <QHash>

QT_BEGIN_NAMESPACE
class QTableWidgetItem;
QT_END_NAMESPACE

class ProcessTab : public QWidget
{
    Q_OBJECT

public:
    explicit ProcessTab(QWidget *parent = nullptr);

public slots:
    void refresh();

signals:
    void liveMonitorRequested(const QString &processName);
    void createAiTaskRequested(const QString &processName);

private slots:
    void onContextMenu(const QPoint &pos);
    void onKill();
    void onKillTree();
    void onRepeatKill();
    void onRepeatKillTree();
    void onProtect();
    void onOpenLocation();
    void onLiveMonitor();
    void onRemoveFromProtected();
    void onSearchTextChanged(const QString &text);
    void onCreateAiTask();

private:
    void setupUi();
    void loadProtectedList();
    void saveProtectedList();
    void addProtectedEntry(const QString &name, bool repeated, bool tree);

    QSplitter *m_splitter = nullptr;
    QTableWidget *m_runningTable = nullptr;
    QTableWidget *m_protectedTable = nullptr;
    QLineEdit *m_searchEdit = nullptr;
    QPushButton *m_btnRefresh = nullptr;

    struct ProtectedEntry {
        QString name;
        bool repeated;
        bool tree;
    };
    QList<ProtectedEntry> m_protected;
};
