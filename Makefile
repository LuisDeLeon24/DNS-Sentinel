KERN_SRC = src/bpf/dns-sentinel-kern.c
USER_SRC = src/user/dns_sentinel_user.c

all: dns_sentinel_kern.o dns_sentinel_user

dns_sentinel_kern.o: $(KERN_SRC)
	clang -O2 -g -target bpf -c $(KERN_SRC) -o dns_sentinel_kern.o

dns_sentinel_user: $(USER_SRC)
	cc $(USER_SRC) -lbpf -lelf -o dns_sentinel_user

clean:
	rm -f dns_sentinel_kern.o dns_sentinel_user

