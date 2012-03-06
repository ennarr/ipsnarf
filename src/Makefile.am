AUTOMAKE_OPTIONS = foreign no-dependencies

bin_PROGRAMS = ipsnarf

ipsnarf_SOURCES = ipsnarf.c conf.c util.c worker.c ipsnarf.h

LDADD = @LIBNETLIB@ @PCAPLIB@

INCLUDES = @PCAPINC@ @LIBNETINC@ -I../include

DEFS = @DEFS@ @LIBNETDEF@
