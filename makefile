LDLIBS=-lpcap -pthread

all: arp-spoof

main.o: mac.h ip.h get_mac.h get_ip.h ethhdr.h arphdr.h main.cpp

arphdr.o: mac.h get_mac.h get_ip.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

get_mac.o : get_mac.h get_mac.cpp

get_ip.o : get_ip.h get_ip.cpp

arp-spoof: main.o arphdr.o ethhdr.o ip.o mac.o get_mac.o get_ip.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o
