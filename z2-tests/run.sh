#!/bin/bash

make
for tst in bpf-block-all bpf-block-trap bpf-check-copy bpf-check-invalid-get \
	bpf-check-invalid-set{,2} bpf-reg bpf-stack; do
	echo -n "$tst: "
	./test $tst.o
done

for tst in bpf-check-tls bpf-stack32; do
	echo -n "$tst: "
	./test32 $tst.o
done

echo -n "test-check-ctx: "
# mute all (expected) libbpf warnings
./test-check-ctx 2>/dev/null

echo -n "test-unload: "
./test-unload
