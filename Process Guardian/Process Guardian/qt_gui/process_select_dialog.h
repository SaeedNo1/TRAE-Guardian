#pragma once

#include <QDialog>
#include <QStringList>

class QListWidget;
class QPushButton;

class ProcessSelectDialog : public QDialog
{
    Q_OBJECT
public:
    explicit ProcessSelectDialog(QWidget *parent = nullptr);
    QStringList selectedProcesses() const;

private:
    void setupUi();
    void loadProcesses();

    QListWidget *m_processList = nullptr;
    QPushButton *m_btnSelectAll = nullptr;
    QPushButton *m_btnDeselectAll = nullptr;
    QPushButton *m_btnOK = nullptr;
    QPushButton *m_btnCancel = nullptr;
};