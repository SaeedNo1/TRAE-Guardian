TEMPLATE = lib
TARGET = observer
CONFIG += c++17 dll

SOURCES += observer_dll.cpp
HEADERS += observer_dll.h

DEFINES += OBSERVER_DLL_EXPORTS

LIBS += -lpdh -lpsapi -ladvapi32 -lwintrust -lcrypt32 -lkernel32 -luser32

DESTDIR = $$PWD/../bin/observe
