# Compile C and Golang binary.

```bash
clang -O2 -g -Wall -target bpf -I/usr/include/linux -c arp_capture.c -o arp_capture.o
```

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build
```
