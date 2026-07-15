#pragma once

#include <QWidget>
#include <QTableWidget>
#include <QPushButton>

class ServiceTab : public QWidget
{
    Q_OBJECT

public:
    explicit ServiceTab(QWidget *parent = nullptr);
    ~ServiceTab();

public slots:
    void refresh();

private slots:
    void onContextMenu(const QPoint &pos);
    void onStop();
    void onDelete();
    void onRepeatDelete();
    void onCancelRepeat();

private:
    void setupUi();
    QString currentServiceName() const;

    QTableWidget *m_table = nullptr;
    QPushButton *m_btnRefresh = nullptr;
};
