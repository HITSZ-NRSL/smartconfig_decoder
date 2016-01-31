AC_ROOT		= ..
include $(AC_ROOT)/common.mak

TEST_DIR	= $(AC_ROOT)/test

CFLAGS		+= -Iinclude

iCC             = $(shell find /opt/intel/cc/*/bin/icc)
iCFLAGS         = -w -mcpu=pentiumpro -march=pentiumpro $(COMMON_CFLAGS)
iOPTFLAGS       = -O3 -ip -ipo -D_FILE_OFFSET_BITS=64
PROF_DIR	= $(PWD)/prof

LIBPCRE		=
ifeq ($(PCRE), true)
	LIBPCRE	= $(shell pcre-config --libs)
endif

ifneq ($(OSNAME), cygwin) #There is yet no libpcap support for windows, so we skip the crawler
	HAVE_PCAP	= $(shell ld -lpcap 2> /dev/null && echo yes)
endif


SBINFILES       = airodump-ng$(EXE) \
		  smartconfig-response$(EXE)
		  
OBJS_ADU	= airodump-ng.o common.o crypto.o uniqueiv.o osdep/radiotap/radiotap.o
OBJS_SCR	= smartconfig-response.o

ifneq ($(OSNAME), Linux)
	OBJS_ADU	+= osdep/common.o
endif

OSD		= osdep
LIBS		:= -L$(OSD) -l$(OSD) $(LIBS)

LIBOSD		= $(OSD)/lib$(OSD).a

LIBSSL		= -lssl -lcrypto
ifeq ($(subst TRUE,true,$(filter TRUE true,$(gcrypt) $(GCRYPT))),true)
	LIBSSL		= -lgcrypt $(LDFLAGS)
	CFLAGS 		+= -DUSE_GCRYPT
	OBJS_ADU	+= sha1-git.o
	OBJS_SCR	+= sha1-git.o
else
	LIBSSL		= -lssl -lcrypto $(LDFLAGS)
endif


ifeq ($(subst TRUE,true,$(filter TRUE true,$(sqlite) $(SQLITE))),true)
	LIBSQL		= -L/usr/local/lib -lsqlite3
else
	LIBSQL		=
endif

all: $(SBINFILES)

$(LIBOSD):
	$(MAKE) -C $(OSD)

airodump-ng$(EXE): $(OBJS_ADU) $(LIBOSD)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS_ADU) -o $(@) $(LIBS) $(LIBSSL) -lpthread $(LIBPCRE)

smartconfig-response$(EXE): $(OBJS_SCR) 
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS_SCR) -o $(@) $(LIBS) 

strip: $(SBINFILES)
	strip $(SBINFILES)

clean:
	$(MAKE) -C $(OSD) clean
	-rm -f $(SBINFILES) *.o a.out

distclean: clean

install: all
	$(MAKE) -C $(OSD) install
	install -d $(DESTDIR)$(sbindir)
	install -m 755 $(SBINFILES) $(DESTDIR)$(sbindir)

uninstall:
	$(MAKE) -C $(OSD) uninstall
	-rm -f $(DESTDIR)$(sbindir)/airodump-ng$(EXE)
	-rm -f $(DESTDIR)$(sbindir)/smartconfig-response$(EXE)
	-rm -rf $(DESTDIR)$(etcdir)
