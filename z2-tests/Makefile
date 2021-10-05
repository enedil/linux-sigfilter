HOST=test test-check-ctx test-unload
HOST32=test32
BPF=bpf-block-all.o bpf-block-trap.o bpf-check-ctx.o bpf-check-copy.o \
    bpf-check-invalid-get.o bpf-check-invalid-set.o bpf-check-invalid-set2.o \
    bpf-reg.o bpf-stack.o bpf-check-tls.o bpf-stack32.o

TARGETS=$(HOST) $(BPF) $(HOST32)

LIBBPF=libbpf/src/libbpf.a
LIBBPF32=libbpf/x32/libbpf.a

# Override local libbpf
CFLAGS=-I libbpf/src -O2
LDFLAGS=-lelf -lz

all: $(TARGETS)

$(HOST): %: %.c $(LIBBPF)
	cc -o $@ $< $(LDFLAGS) $(CFLAGS) $(LIBBPF)

test32: test.c $(LIBBPF32)
	cc -m32 -o $@ $< $(LDFLAGS) $(CFLAGS) $(LIBBPF32)


$(BPF): %.o: %.c sigfilter.h
	clang-11 -target bpf -O2 $< -c

$(LIBBPF):
	$(MAKE) -C libbpf/src

$(LIBBPF32):
	mkdir -p libbpf/x32
	$(MAKE) -C libbpf/src  OBJDIR=$(PWD)/libbpf/x32 CFLAGS=-m32 LDFLAGS=-m32

.PHONY: clean $(LIBBPF) $(LIBBPF32)
clean:
	rm -fr libbpf/x32
	$(MAKE) -C libbpf/src clean
	rm -f $(TARGETS)
