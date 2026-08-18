CC ?= gcc
CFLAGS ?= -O2 -std=gnu11 -D_FORTIFY_SOURCE=2
CPPFLAGS ?=
LDFLAGS ?=
LDLIBS = -lssl -lcrypto -lacl -lz -lbz2 -llzma -lm

TARGET = potency
SOURCES = potency.c
OBJECTS = $(SOURCES:.c=.o)

PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin

WARNFLAGS = -Wall -Wextra

.PHONY: all clean install uninstall debug release

all: release

release: CFLAGS += $(WARNFLAGS)
release: $(TARGET)

debug: CFLAGS += -g -O0 -DDEBUG $(WARNFLAGS)
debug: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

install: release
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)

clean:
	rm -f $(OBJECTS) $(TARGET)

distclean: clean
	rm -f *.log *.out
