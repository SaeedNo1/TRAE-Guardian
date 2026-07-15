#include "mainwindow.h"
#include <QApplication>
#include <QStyleFactory>
#include <QTranslator>
#include <QSettings>
#include <QDir>
#include <QFile>
#include <QString>
#include <windows.h>
#include <tlhelp32.h>

static QString moduleDir()
{
    wchar_t buf[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, buf, MAX_PATH);
    QString path = QString::fromWCharArray(buf);
    int idx = path.lastIndexOf('\\');
    return idx >= 0 ? path.left(idx) : QDir::currentPath();
}

static BOOL IsQtGuiAlreadyRunning(void) {
    HWND hwnd = FindWindowW(NULL, L"Process Guardian");
    if (hwnd && IsWindowVisible(hwnd)) {
        ShowWindow(hwnd, SW_RESTORE);
        SetForegroundWindow(hwnd);
        return TRUE;
    }
    hwnd = FindWindowW(L"Qt6QWindowIcon", NULL);
    if (hwnd && IsWindowVisible(hwnd)) {
        ShowWindow(hwnd, SW_RESTORE);
        SetForegroundWindow(hwnd);
        return TRUE;
    }
    hwnd = FindWindowW(L"Qt5QWindowIcon", NULL);
    if (hwnd && IsWindowVisible(hwnd)) {
        ShowWindow(hwnd, SW_RESTORE);
        SetForegroundWindow(hwnd);
        return TRUE;
    }
    return FALSE;
}

int main(int argc, char *argv[])
{
    if (IsQtGuiAlreadyRunning()) {
        return 0;
    }
    
    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"TRAE_ProcessGuardian_QT_SingleInstance");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        if (hMutex) CloseHandle(hMutex);
        return 0;
    }

    QApplication a(argc, argv);
    a.setApplicationName("Process Guardian");
    a.setOrganizationName("TRAE");

    QString qmDir = moduleDir() + "\\translations\\";
    QString lang = "zh";
    {
        QSettings s(moduleDir() + "\\data\\settings.ini", QSettings::IniFormat);
        lang = s.value("UI/Language", "zh").toString();
    }

    QTranslator qtTranslator;
    QTranslator appTranslator;
    if (lang == "zh") {
        if (QFile::exists(qmDir + "trae_guardian_qt_zh_CN.qm"))
            appTranslator.load(qmDir + "trae_guardian_qt_zh_CN.qm");
        if (QFile::exists(qmDir + "qt_zh_CN.qm"))
            qtTranslator.load(qmDir + "qt_zh_CN.qm");
    } else {
        if (QFile::exists(qmDir + "trae_guardian_qt_en.qm"))
            appTranslator.load(qmDir + "trae_guardian_qt_en.qm");
        if (QFile::exists(qmDir + "qt_en.qm"))
            qtTranslator.load(qmDir + "qt_en.qm");
    }
    a.installTranslator(&qtTranslator);
    a.installTranslator(&appTranslator);

    a.setStyle(QStyleFactory::create("Fusion"));
    QPalette dark;
    dark.setColor(QPalette::Window, QColor(30, 30, 35));
    dark.setColor(QPalette::WindowText, QColor(230, 230, 230));
    dark.setColor(QPalette::Base, QColor(40, 40, 45));
    dark.setColor(QPalette::AlternateBase, QColor(50, 50, 55));
    dark.setColor(QPalette::ToolTipBase, QColor(50, 50, 55));
    dark.setColor(QPalette::ToolTipText, Qt::white);
    dark.setColor(QPalette::Text, QColor(230, 230, 230));
    dark.setColor(QPalette::Button, QColor(55, 55, 60));
    dark.setColor(QPalette::ButtonText, QColor(230, 230, 230));
    dark.setColor(QPalette::Highlight, QColor(0, 120, 215));
    dark.setColor(QPalette::HighlightedText, Qt::white);
    a.setPalette(dark);

    MainWindow w;
    w.setWindowTitle("Process Guardian");
    w.showNormal();
    w.raise();
    w.activateWindow();

    int ret = a.exec();

    if (hMutex) CloseHandle(hMutex);
    return ret;
}
