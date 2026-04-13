LDLIBS += -lpcap

all: arp-spoof

arp-spoof: main.c
	gcc -Wall -o arp-spoof main.c $(LDLIBS)

clean:
	rm -f arp-spoof *.o
