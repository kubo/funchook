DUCKHOOK_OBJS = duckhook.o duckhook_x86.o

UNAME_S := $(shell uname -s)
UNAME_P := $(shell uname -p)
PLATFORM := $(UNAME_S)-$(UNAME_P)
srcdir = .

ifeq ($(PLATFORM),Linux-x86_64)

CC = gcc -m64
CFLAGS += -D_GNU_SOURCE -fPIC
LINK_SHARED = $(CC) -shared -g -Wl,--version-script,$(srcdir)/duckhook.map
LIBS = -ldl
DUCKHOOK_OBJS += duckhook_linux.o
TARGET = libduckhook.so

endif

ifeq ($(PLATFORM),Linux-i686)

CC = gcc -m32
CFLAGS += -D_GNU_SOURCE -fPIC
LINK_SHARED = $(CC) -shared -g -Wl,--version-script,$(srcdir)/duckhook.map
LIBS = -ldl
DUCKHOOK_OBJS += duckhook_linux.o
TARGET = libduckhook.so

endif

ifeq ($(PLATFORM),mingw64-cross)

# Windows x64 (Cross compile on linux)
CC = x86_64-w64-mingw32-gcc
CFLAGS += -DBUILD_DUCKHOOK_DLL
LINK_SHARED = $(CC) -shared -g -Wl,--out-implib,duckhook.lib
DUCKHOOK_OBJS += duckhook_windows.o
TARGET = duckhook.dll

endif

ifeq ($(PLATFORM),mingw32-cross)

# Windows 32bit (Cross compile on linux)
CC = i686-w64-mingw32-gcc
CFLAGS += -DBUILD_DUCKHOOK_DLL
LINK_SHARED = $(CC) -shared -g -Wl,--out-implib,duckhook.lib
DUCKHOOK_OBJS += duckhook_windows.o
TARGET = duckhook.dll

endif

CFLAGS += -g -I$(srcdir)/../include -Wall

DISTORM3_DIR = $(srcdir)/../distorm

VPATH = $(DISTORM3_DIR)/src:$(srcdir)
CFLAGS += -I$(DISTORM3_DIR)/include

DISTORM3_OBJS = \
	mnemonics.o \
	wstring.o \
	textdefs.o \
	prefix.o \
	operands.o \
	insts.o \
	instructions.o \
	distorm.o \
	decoder.o

OBJS = $(DUCKHOOK_OBJS) $(DISTORM3_OBJS)

all: $(TARGET)

all-platforms:
	$(MAKE) -f $(srcdir)/Makefile clean
	test -d x86_64 || mkdir x86_64
	cd x86_64 && $(MAKE) -f $(abspath $(srcdir))/Makefile srcdir=$(abspath $(srcdir)) PLATFORM=Linux-x86_64
	test -d i686 || mkdir i686
	cd i686 && $(MAKE) -f $(abspath $(srcdir))/Makefile srcdir=$(abspath $(srcdir)) PLATFORM=Linux-i686
	test -d mingw64 || mkdir mingw64
	cd mingw64 && $(MAKE) -f $(abspath $(srcdir))/Makefile srcdir=$(abspath $(srcdir)) PLATFORM=mingw64-cross
	test -d mingw32 || mkdir mingw32
	cd mingw32 && $(MAKE) -f $(abspath $(srcdir))/Makefile srcdir=$(abspath $(srcdir)) PLATFORM=mingw32-cross

$(TARGET): $(OBJS)
	$(LINK_SHARED) -o $@ $^ $(LIBS)

duckhook.o: duckhook.c $(srcdir)/../include/duckhook.h duckhook_internal.h
duckhook_unix.o: duckhook_unix.c $(srcdir)/../include/duckhook.h duckhook_internal.h
duckhook_windows.o: duckhook_windows.c $(srcdir)/../include/duckhook.h duckhook_internal.h
duckhook_x86.o: duckhook_x86.c $(srcdir)/../include/duckhook.h duckhook_internal.h

clean:
	$(RM) $(TARGET) $(OBJS)
