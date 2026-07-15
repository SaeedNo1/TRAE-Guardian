QT       += core gui widgets concurrent

CONFIG += c++17
CONFIG += warn_off

TARGET = trae_guardian_qt
TEMPLATE = app

# Output to parent bin directory
DESTDIR = $$PWD/../bin

INCLUDEPATH += $$PWD/..

SOURCES += \
    main.cpp \
    mainwindow.cpp \
    processtab.cpp \
    servicetab.cpp \
    registrytab.cpp \
    partitiontab.cpp \
    settingsdialog.cpp \
    aichattab.cpp \
    aihubtab.cpp \
    aiworker.cpp \
    ai_task_dialog.cpp \
    process_select_dialog.cpp \
    taskchatdialog.cpp \
    livemonitortab.cpp \
    roguesoftwaretab.cpp \
    $$PWD/../core.c \
    $$PWD/../ai_service.c \
    $$PWD/../partition_edit.c \
    $$PWD/../registry_tree.c \
    $$PWD/../registry_manager.c \
    $$PWD/../gui_ai.c

HEADERS += \
    mainwindow.h \
    processtab.h \
    servicetab.h \
    registrytab.h \
    partitiontab.h \
    settingsdialog.h \
    aichattab.h \
    aihubtab.h \
    aiworker.h \
    ai_task_dialog.h \
    process_select_dialog.h \
    taskchatdialog.h \
    livemonitortab.h \
    roguesoftwaretab.h \
    chatstyle.h \
    $$PWD/../core.h \
    $$PWD/../ai_service.h \
    $$PWD/../partition_edit.h \
    $$PWD/../registry_tree.h \
    $$PWD/../registry_manager.h \
    $$PWD/../gui_ai.h

# Translations
TRANSLATIONS += \
    $$PWD/trae_guardian_qt_en.ts \
    $$PWD/trae_guardian_qt_zh_CN.ts

# Windows libraries
LIBS += -lkernel32 -luser32 -lpsapi -ladvapi32 -lwinhttp -lcomctl32 -lole32 -loleaut32 -lgdi32 -lgdiplus -lshell32

DEFINES += UNICODE _UNICODE
