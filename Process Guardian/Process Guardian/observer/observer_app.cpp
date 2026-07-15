#include <QApplication>
#include <QMainWindow>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QComboBox>
#include <QTimer>
#include <QPainter>
#include <QPaintEvent>
#include <QPen>
#include <QBrush>
#include <QLinearGradient>
#include <QFont>
#include <QFontDatabase>
#include <QFileDialog>
#include <QMessageBox>
#include <QProcess>
#include <QDebug>
#include <windows.h>
#include <tlhelp32.h>
#include "observer_dll.h"

static QString FormatMB(double mb)
{
    if (mb >= 1024.0) return QString("%1 GB").arg(mb / 1024.0, 0, 'f', 2);
    return QString("%1 MB").arg(mb, 0, 'f', 1);
}

class MetricChart : public QWidget {
    Q_OBJECT
public:
    explicit MetricChart(const QString &title, const QString &unit, const QColor &color, double maxAuto = 0.0, QWidget *parent = nullptr)
        : QWidget(parent), m_title(title), m_unit(unit), m_color(color), m_maxAuto(maxAuto) {}

    void setData(const QVector<double> &data) {
        m_data = data;
        update();
    }

    void setValueText(const QString &text) {
        m_valueText = text;
        update();
    }

protected:
    void paintEvent(QPaintEvent *) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        QRect r = rect().adjusted(8, 8, -8, -8);

        /* Background */
        p.fillRect(r, QColor(40, 40, 42));
        p.setPen(QPen(QColor(70, 70, 72), 1));
        p.drawRoundedRect(r, 10, 10);

        /* Title */
        p.setPen(Qt::white);
        QFont f = p.font();
        f.setBold(true);
        f.setPointSize(10);
        p.setFont(f);
        p.drawText(r.adjusted(12, 10, -12, 0), Qt::AlignLeft | Qt::AlignTop, m_title);

        /* Current value */
        p.setPen(m_color);
        QFont vf = p.font();
        vf.setPointSize(16);
        vf.setBold(true);
        p.setFont(vf);
        p.drawText(r.adjusted(12, 28, -12, 0), Qt::AlignRight | Qt::AlignTop, m_valueText);

        /* Grid lines */
        QRect chartRect = r.adjusted(12, 55, -12, -12);
        p.setPen(QPen(QColor(60, 60, 62), 1, Qt::DashLine));
        for (int i = 1; i < 4; ++i) {
            int y = chartRect.top() + chartRect.height() * i / 4;
            p.drawLine(chartRect.left(), y, chartRect.right(), y);
        }

        if (m_data.isEmpty()) {
            p.setPen(QColor(120, 120, 122));
            p.setFont(QFont(p.font().family(), 9));
            p.drawText(chartRect, Qt::AlignCenter, "No data");
            return;
        }

        /* Determine max */
        double maxVal = m_maxAuto;
        for (double v : m_data) if (v > maxVal) maxVal = v;
        if (maxVal < 1e-6) maxVal = 1.0;
        if (m_unit == "%" && maxVal < 5.0) maxVal = 5.0;

        /* Draw area gradient under line */
        QLinearGradient grad(chartRect.topLeft(), chartRect.bottomLeft());
        QColor c = m_color;
        c.setAlpha(80);
        grad.setColorAt(0, c);
        c.setAlpha(10);
        grad.setColorAt(1, c);

        QPolygonF poly;
        poly.append(QPointF(chartRect.left(), chartRect.bottom()));
        int n = m_data.size();
        double dx = chartRect.width() / qMax(n - 1, 1);
        for (int i = 0; i < n; ++i) {
            double x = chartRect.left() + dx * i;
            double y = chartRect.bottom() - (m_data[i] / maxVal) * chartRect.height();
            poly.append(QPointF(x, y));
        }
        poly.append(QPointF(chartRect.right(), chartRect.bottom()));
        p.setPen(Qt::NoPen);
        p.setBrush(grad);
        p.drawPolygon(poly);

        /* Draw line */
        QPen linePen(m_color, 2);
        p.setPen(linePen);
        p.setBrush(Qt::NoBrush);
        for (int i = 1; i < n; ++i) {
            double x1 = chartRect.left() + dx * (i - 1);
            double y1 = chartRect.bottom() - (m_data[i - 1] / maxVal) * chartRect.height();
            double x2 = chartRect.left() + dx * i;
            double y2 = chartRect.bottom() - (m_data[i] / maxVal) * chartRect.height();
            p.drawLine(QPointF(x1, y1), QPointF(x2, y2));
        }
    }

private:
    QString m_title;
    QString m_unit;
    QColor m_color;
    double m_maxAuto;
    QVector<double> m_data;
    QString m_valueText;
};

class ObserverWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit ObserverWindow(QWidget *parent = nullptr)
        : QMainWindow(parent), m_pid(0)
    {
        setupUi();
        loadProcessList();
        QTimer::singleShot(0, this, [this]() { resize(1100, 820); });
    }

    ~ObserverWindow() {
        if (m_hDll) {
            auto stopAll = (decltype(&StopAllObservations))GetProcAddress(m_hDll, "StopAllObservations");
            if (stopAll) stopAll();
            FreeLibrary(m_hDll);
        }
    }

protected:
    void closeEvent(QCloseEvent *) override {
        if (m_hDll) {
            auto stopAll = (decltype(&StopAllObservations))GetProcAddress(m_hDll, "StopAllObservations");
            if (stopAll) stopAll();
        }
    }

public slots:
    void autoObserve(DWORD pid) {
        if (pid == 0 || !m_hDll) return;
        auto observe = (decltype(&ObserveProcess))GetProcAddress(m_hDll, "ObserveProcess");
        if (!observe || !observe(pid)) {
            m_procNameLabel->setText(QString("Failed to observe PID %1").arg(pid));
            return;
        }
        m_pid = pid;
        m_pidEdit->setText(QString::number(pid));
        m_procNameLabel->setText(QString("Observing PID %1").arg(pid));
        for (int i = 0; i < m_procCombo->count(); ++i) {
            if (m_procCombo->itemData(i).toUInt() == pid) {
                m_procCombo->setCurrentIndex(i);
                break;
            }
        }
        m_timer->start(1000);
        onRefresh();
    }

private slots:
    void onRefresh() {
        if (!m_hDll || m_pid == 0) return;
        auto getStats = (decltype(&GetObserverStats))GetProcAddress(m_hDll, "GetObserverStats");
        if (!getStats) return;

        ObserverStatsEx stats = {0};
        if (getStats(m_pid, &stats, sizeof(stats)) && stats.historyCount > 0) {
            updateCharts(stats);
            updateInfo(stats.info);
        } else {
            m_procNameLabel->setText(QString("PID %1: access denied or no data").arg(m_pid));
        }
    }

    void onSelectProcess() {
        int idx = m_procCombo->currentIndex();
        if (idx < 0) return;
        DWORD pid = m_procCombo->currentData().toUInt();
        if (pid == 0) return;

        auto stopAll = (decltype(&StopAllObservations))GetProcAddress(m_hDll, "StopAllObservations");
        if (stopAll) stopAll();

        auto observe = (decltype(&ObserveProcess))GetProcAddress(m_hDll, "ObserveProcess");
        if (observe && observe(pid)) {
            m_pid = pid;
            m_pidEdit->setText(QString::number(pid));
            m_procNameLabel->setText(m_procCombo->currentText());
            m_timer->start(1000);
            onRefresh();
        }
    }

    void onPidEntered() {
        DWORD pid = m_pidEdit->text().toUInt();
        if (pid == 0) return;
        auto stopAll = (decltype(&StopAllObservations))GetProcAddress(m_hDll, "StopAllObservations");
        if (stopAll) stopAll();
        auto observe = (decltype(&ObserveProcess))GetProcAddress(m_hDll, "ObserveProcess");
        if (observe && observe(pid)) {
            m_pid = pid;
            m_procNameLabel->setText(QString("PID %1").arg(pid));
            m_timer->start(1000);
            onRefresh();
        }
    }

private:
    void setupUi() {
        setWindowTitle("Process Observer");
        QWidget *central = new QWidget(this);
        setCentralWidget(central);
        QVBoxLayout *mainLayout = new QVBoxLayout(central);
        mainLayout->setSpacing(12);
        mainLayout->setContentsMargins(16, 16, 16, 16);

        /* Toolbar */
        QHBoxLayout *topLayout = new QHBoxLayout();
        m_procCombo = new QComboBox(this);
        m_procCombo->setMinimumWidth(260);
        m_procCombo->setStyleSheet("QComboBox { padding: 4px; }");
        topLayout->addWidget(new QLabel("Process:"));
        topLayout->addWidget(m_procCombo);

        QPushButton *btnSelect = new QPushButton("Observe", this);
        btnSelect->setStyleSheet("QPushButton { background: #0a84ff; color: white; padding: 6px 16px; border-radius: 6px; }");
        connect(btnSelect, &QPushButton::clicked, this, &ObserverWindow::onSelectProcess);
        topLayout->addWidget(btnSelect);

        topLayout->addSpacing(20);
        topLayout->addWidget(new QLabel("PID:"));
        m_pidEdit = new QLineEdit(this);
        m_pidEdit->setMaximumWidth(100);
        m_pidEdit->setStyleSheet("QLineEdit { padding: 4px; background: #2c2c2e; color: white; border: 1px solid #48484a; border-radius: 4px; }");
        connect(m_pidEdit, &QLineEdit::returnPressed, this, &ObserverWindow::onPidEntered);
        topLayout->addWidget(m_pidEdit);

        m_procNameLabel = new QLabel("No process selected");
        m_procNameLabel->setStyleSheet("QLabel { color: #0a84ff; font-weight: bold; font-size: 14px; }");
        topLayout->addWidget(m_procNameLabel);
        topLayout->addStretch();

        QPushButton *btnRefresh = new QPushButton("Refresh", this);
        btnRefresh->setStyleSheet("QPushButton { background: #3a3a3c; color: white; padding: 6px 16px; border-radius: 6px; }");
        connect(btnRefresh, &QPushButton::clicked, this, &ObserverWindow::onRefresh);
        topLayout->addWidget(btnRefresh);

        mainLayout->addLayout(topLayout);

        /* Charts */
        QGridLayout *grid = new QGridLayout();
        grid->setSpacing(12);
        m_cpuChart = new MetricChart("CPU Usage", "%", QColor(10, 132, 255), 100.0);
        m_gpuChart = new MetricChart("GPU Usage", "%", QColor(48, 209, 88), 100.0);
        m_memChart = new MetricChart("Memory Usage", "MB", QColor(255, 159, 10));
        m_vramChart = new MetricChart("VRAM Usage", "MB", QColor(191, 90, 242));
        grid->addWidget(m_cpuChart, 0, 0);
        grid->addWidget(m_gpuChart, 0, 1);
        grid->addWidget(m_memChart, 1, 0);
        grid->addWidget(m_vramChart, 1, 1);
        grid->setRowStretch(0, 1);
        grid->setRowStretch(1, 1);
        grid->setColumnStretch(0, 1);
        grid->setColumnStretch(1, 1);
        mainLayout->addLayout(grid, 1);

        /* Info panel */
        QVBoxLayout *infoLayout = new QVBoxLayout();
        infoLayout->setSpacing(6);
        auto addRow = [&](const QString &label, QLabel *&value) {
            QHBoxLayout *h = new QHBoxLayout();
            QLabel *l = new QLabel(label);
            l->setStyleSheet("QLabel { color: #8e8e93; min-width: 90px; }");
            h->addWidget(l);
            value = new QLabel("-");
            value->setStyleSheet("QLabel { color: white; }");
            value->setWordWrap(true);
            h->addWidget(value, 1);
            infoLayout->addLayout(h);
        };
        addRow("Path:", m_pathLabel);
        addRow("User:", m_userLabel);
        addRow("Signed:", m_signedLabel);
        addRow("Signer:", m_signerLabel);

        QWidget *infoWidget = new QWidget(this);
        infoWidget->setLayout(infoLayout);
        infoWidget->setStyleSheet("QWidget { background: #2c2c2e; border-radius: 10px; padding: 12px; }");
        mainLayout->addWidget(infoWidget);

        m_timer = new QTimer(this);
        connect(m_timer, &QTimer::timeout, this, &ObserverWindow::onRefresh);

        /* Dark theme */
        setStyleSheet("QMainWindow { background: #1c1c1e; }"
                      "QWidget { background: #1c1c1e; color: #f2f2f7; }"
                      "QComboBox, QLineEdit { background: #2c2c2e; color: white; border: 1px solid #48484a; }"
                      "QLabel { color: #f2f2f7; }");

        /* Load DLL */
        m_hDll = LoadLibraryW(L"observer.dll");
        if (!m_hDll) {
            QMessageBox::critical(this, "Error", "Failed to load observer.dll");
        }
    }

    void loadProcessList() {
        m_procCombo->clear();
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) return;
        PROCESSENTRY32W pe = {0};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                QString name = QString::fromWCharArray(pe.szExeFile);
                QString text = QString("%1 (PID: %2)").arg(name).arg(pe.th32ProcessID);
                m_procCombo->addItem(text, QVariant((quint32)pe.th32ProcessID));
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }

    void updateCharts(const ObserverStatsEx &stats) {
        QVector<double> cpu, gpu, mem, vram;
        for (int i = 0; i < stats.historyCount; ++i) {
            cpu.append(stats.history[i].cpuPercent);
            gpu.append(stats.history[i].gpuPercent);
            mem.append(stats.history[i].memMB);
            vram.append(stats.history[i].vramMB);
        }
        m_cpuChart->setData(cpu);
        m_gpuChart->setData(gpu);
        m_memChart->setData(mem);
        m_vramChart->setData(vram);

        m_cpuChart->setValueText(QString("%1%").arg(stats.current.cpuPercent, 0, 'f', 1));
        m_gpuChart->setValueText(QString("%1%").arg(stats.current.gpuPercent, 0, 'f', 1));
        m_memChart->setValueText(FormatMB(stats.current.memMB));
        m_vramChart->setValueText(FormatMB(stats.current.vramMB));
    }

    void updateInfo(const ObserverProcessInfo &info) {
        m_pathLabel->setText(QString::fromWCharArray(info.filePath));
        m_userLabel->setText(QString::fromWCharArray(info.userName));
        m_signedLabel->setText(info.hasValidSignature ? "Yes" : "No / Unknown");
        m_signerLabel->setText(QString::fromWCharArray(info.signerName));
    }

    HMODULE m_hDll = NULL;
    DWORD m_pid = 0;
    QComboBox *m_procCombo = nullptr;
    QLineEdit *m_pidEdit = nullptr;
    QLabel *m_procNameLabel = nullptr;
    MetricChart *m_cpuChart = nullptr;
    MetricChart *m_gpuChart = nullptr;
    MetricChart *m_memChart = nullptr;
    MetricChart *m_vramChart = nullptr;
    QLabel *m_pathLabel = nullptr;
    QLabel *m_userLabel = nullptr;
    QLabel *m_signedLabel = nullptr;
    QLabel *m_signerLabel = nullptr;
    QTimer *m_timer = nullptr;
};

static void logMsg(const QString &msg)
{
    QFile f("observer_debug.log");
    if (f.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
        f.write(QString("[%1] %2\n").arg(QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss")).arg(msg).toUtf8());
    }
}

int main(int argc, char *argv[])
{
    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"Global\\TRAE_ProcessGuardian_Observer_SingleInstance");
    if (!hMutex || GetLastError() == ERROR_ALREADY_EXISTS) {
        return 0;
    }

    /* If observer.exe is launched from a subfolder, tell Qt where to find platforms/ */
    {
        wchar_t exePath[MAX_PATH] = {0};
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        QString exe = QString::fromWCharArray(exePath);
        int idx = exe.lastIndexOf('\\');
        if (idx > 0) {
            QString binDir = exe.left(idx);
            idx = binDir.lastIndexOf('\\');
            if (idx > 0 && (binDir.mid(idx + 1).compare("Observe", Qt::CaseInsensitive) == 0 ||
                            binDir.mid(idx + 1).compare("observe", Qt::CaseInsensitive) == 0)) {
                binDir = binDir.left(idx);
            }
            qputenv("QT_QPA_PLATFORM_PLUGIN_PATH", QDir::toNativeSeparators(binDir).toLocal8Bit());
        }
    }

    QApplication a(argc, argv);
    a.setStyle("Fusion");

    QStringList args;
    for (int i = 0; i < argc; ++i) args.append(QString::fromLocal8Bit(argv[i]));
    logMsg("started args=" + args.join(" "));

    ObserverWindow w;

    DWORD pid = 0;
    for (int i = 1; i < argc; ++i) {
        QString arg = QString::fromLocal8Bit(argv[i]);
        bool ok = false;
        DWORD v = arg.toUInt(&ok);
        if (ok && v > 0) {
            pid = v;
            break;
        }
    }
    logMsg(QString("parsed pid=%1").arg(pid));
    if (pid > 0) {
        w.autoObserve(pid);
    }

    w.show();
    return a.exec();
}

#include "observer_app_moc.cpp"
