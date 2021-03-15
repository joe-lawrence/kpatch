include ../../Makefile.inc

CFLAGS += -MMD -MP
CFLAGS += -Wall -g -Werror
# TODO
# CFLAGS += -Wsign-compare -Wconversion -Wno-sign-conversion
LDLIBS = -lelf

TARGETS = klp-convert
SOURCES = klp-convert.c \
          elf.c

all: $(TARGETS)

-include $(SOURCES:.c=.d)

klp-convert: klp-convert.o elf.o

install: all
	$(INSTALL) -d $(LIBEXECDIR)/klp-convert
	$(INSTALL) $(TARGETS) $(LIBEXECDIR)/klp-convert

uninstall:
	$(RM) -R $(LIBEXECDIR)/klp-convert

clean:
	$(RM) $(TARGETS) *.{o,d}
