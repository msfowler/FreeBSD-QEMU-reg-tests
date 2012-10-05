CFLAGS=-static

MIPS_EXE=./mips_test
X86_EXE=./x86_test
SPARC_EXE = ./sparc_test

bin: $(MIPS_EXE) $(X86_EXE) $(SPARC_EXE)

$(MIPS_EXE) : FreeBSD-test.c
	cc-mips64 $(CFLAGS) -o $(MIPS_EXE) FreeBSD-test.c

$(X86_EXE) : FreeBSD-test.c
	gcc -g $(CFLAGS) -o $(X86_EXE) FreeBSD-test.c

$(SPARC_EXE) : FreeBSD-test.c
	cc-sparc64 $(CFLAGS) -o $(SPARC_EXE) FreeBSD-test.c

mips : $(MIPS_EXE)
	qemu-mips64 $(MIPS_EXE)

sparc64: $(SPARC_EXE)
	qemu-sparc64 $(SPARC_EXE)

all: $(MIPS_EXE) $(X86_EXE) $(SPARC_EXE)
	$(X86_EXE)
	qemu-mips64 $(MIPS_EXE)
	qemu-sparc64 $(SPARC_EXE)

clean:
	rm $(MIPS_EXE)
	rm $(X86_EXE)
	rm $(SPARC_EXE)
	rm *.core
