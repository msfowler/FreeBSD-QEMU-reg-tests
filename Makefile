CFLAGS=-static

MIPS_CC = cc-mips64
X86_CC = gcc
SPARC_CC = cc-sparc64

MIPS_EXE=./mips_test
X86_EXE=./x86_test
SPARC_EXE = ./sparc_test

bin: $(MIPS_EXE) $(X86_EXE) $(SPARC_EXE)

$(MIPS_EXE) : FreeBSD-test.c helpers/mips_exec_test
	$(MIPS_CC) $(CFLAGS) -DARCH=ARCH_MIPS -o $(MIPS_EXE) FreeBSD-test.c

$(X86_EXE) : FreeBSD-test.c helpers/x86_exec_test
	$(X86_CC) -g $(CFLAGS) -DARCH=ARCH_X86 -o $(X86_EXE) FreeBSD-test.c

$(SPARC_EXE) : FreeBSD-test.c helpers/sparc_exec_test
	$(SPARC_CC) $(CFLAGS) -DARCH=ARCH_SPARC -o $(SPARC_EXE) FreeBSD-test.c

helpers/mips_exec_test : exec-test.c
	$(MIPS_CC) $(CFLAGS) -o helpers/mips_exec_test exec-test.c

helpers/x86_exec_test : exec-test.c
	$(X86_CC) $(CFLAGS) -o helpers/x86_exec_test exec-test.c

helpers/sparc_exec_test : exec-test.c
	$(SPARC_CC) $(CFLAGS) -o helpers/sparc_exec_test exec-test.c

mips : $(MIPS_EXE)
	qemu-mips64 $(MIPS_EXE)

sparc64: $(SPARC_EXE)
	qemu-sparc64 $(SPARC_EXE)

all: $(MIPS_EXE) $(X86_EXE) $(SPARC_EXE)
	$(X86_EXE)
	qemu-mips64 $(MIPS_EXE)
	qemu-sparc64 $(SPARC_EXE)

clean:
	rm -f $(MIPS_EXE)
	rm -f $(X86_EXE)
	rm -f $(SPARC_EXE)
	rm -f *.core
	rm -f helpers/*
