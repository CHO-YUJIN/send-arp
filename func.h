#ifndef FUNC_H
#define FUNC_H

#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)

struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

int MyIpMac(char* dev, char* myip, char* mymac);
Mac GetVictimMac(pcap_t* handler, char* MyIp, Mac MyMac, char* VictimIp);
EthArpPacket CreatePacket(Mac smac, Mac dmac, char* sip, char* dip, bool isRequest);
void SendPacket(pcap_t* handle, EthArpPacket packet);
void SendArp(pcap_t* handle, char* VictimIp, Mac VictimMac, char* TargetIp, char* MyMac);
void usage();

#endif // FUNC_H
