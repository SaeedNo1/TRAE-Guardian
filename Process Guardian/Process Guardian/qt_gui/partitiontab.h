#pragma once

#include <QWidget>
#include <QTreeWidget>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QLabel>

class PartitionTab : public QWidget
{
    Q_OBJECT

public:
    explicit PartitionTab(QWidget *parent = nullptr);
    ~PartitionTab();

public slots:
    void refresh();

private slots:
    void onContextMenu(const QPoint &pos);
    void onDelete();
    void onRepeatDelete();
    void onCancelRepeat();
    void onSelectionChanged();
    void onRefreshBoot();
    void onSaveBoot();

private:
    void setupUi();
    void loadRepeatedList();
    int currentDiskNumber() const;
    int currentPartitionNumber() const;
    bool isDiskSelected() const;
    bool readBootSector(int diskNumber);
    bool writeBootSector(int diskNumber);
    static QString bytesToHexText(const QByteArray &data);
    static QByteArray hexTextToBytes(const QString &text, bool *ok);

    QTreeWidget *m_tree = nullptr;
    QListWidget *m_repeatedList = nullptr;
    QLabel *m_bootLabel = nullptr;
    QPlainTextEdit *m_bootEdit = nullptr;
    QPushButton *m_btnRefreshBoot = nullptr;
    QPushButton *m_btnSaveBoot = nullptr;
    int m_bootDisk = -1;
};
