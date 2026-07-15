CC = cl
CFLAGS = /c /EHsc /W3 /O2 /I"$(INCLUDE)"
LFLAGS = /LIBPATH:"$(LIB)" kernel32.lib user32.lib psapi.lib advapi32.lib comctl32.lib winhttp.lib WebView2Loader.lib

MSVC_DIR = C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC\14.29.30133
SDK_DIR = C:\Program Files (x86)\Windows Kits\10

INCLUDE = $(MSVC_DIR)\include
INCLUDE += $(SDK_DIR)\Include\10.0.19041.0\um
INCLUDE += $(SDK_DIR)\Include\10.0.19041.0\shared
INCLUDE += $(MSVC_DIR)\..\..\..\MSBuild\Microsoft\VC\v160\WebView2

LIB = $(MSVC_DIR)\lib\x64
LIB += $(SDK_DIR)\Lib\10.0.19041.0\um\x64

BUILD_DIR = build
OUTPUT_DIR = bin
TARGET = $(OUTPUT_DIR)\trae_guardian.exe

SRCS = main.c core.c ai_service.c
OBJS = $(SRCS:.c=.obj)

all: $(TARGET)

$(TARGET): $(OBJS)
	@if not exist $(BUILD_DIR) mkdir $(BUILD_DIR)
	@if not exist $(OUTPUT_DIR) mkdir $(OUTPUT_DIR)
	link /OUT:$(TARGET) $(LFLAGS) $(OBJS)
	copy /Y html\index.html $(OUTPUT_DIR)\html\
	copy /Y html\style.css $(OUTPUT_DIR)\html\
	copy /Y html\script.js $(OUTPUT_DIR)\html\
	@if not exist $(OUTPUT_DIR)\data mkdir $(OUTPUT_DIR)\data

.c.obj:
	$(CC) $(CFLAGS) $<

clean:
	del /Q *.obj $(BUILD_DIR)\*.obj $(TARGET)

.PHONY: all clean