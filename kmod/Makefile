include ../Makefile.inc


.PHONY: all
all:

.PHONY: install
install:
	$(INSTALL) -d $(DATADIR)/patch
	$(INSTALL) -m 644 patch/* $(DATADIR)/patch

.PHONY: uninstall
uninstall:
	$(RM) -R $(DATADIR)

clean:
