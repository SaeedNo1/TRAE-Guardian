TEMPLATE = app
TARGET = observer
CONFIG += c++17 qt widgets
QT += widgets

SOURCES += observer_app.cpp
HEADERS += observer_dll.h

LIBS += -lpdh -lpsapi -ladvapi32 -lwintrust -lcrypt32 -lkernel32 -luser32 -lgdi32

DESTDIR = $$PWD/../bin/observe
