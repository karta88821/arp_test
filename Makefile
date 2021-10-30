all: arp.c main.c arp.h
	gcc main.c arp.c arp.h -o arp -g
clean:
	rm -f arp
