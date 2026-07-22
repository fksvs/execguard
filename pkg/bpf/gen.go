package bpf

//go:generate go tool bpf2go -tags linux -cc clang -cflags "-O2 -g -Wall -I../../bpf/include" guard ../../bpf/src/guard.bpf.c
