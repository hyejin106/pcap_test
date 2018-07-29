#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define PRINT_MAC "%s - %02x:%02x:%02x:%02x:%02x:%02x\n"

void usage() {
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}

void printMAC(const char* msg, unsigned char* target) {
    printf(PRINT_MAC, msg, target[0], target[1], target[2], target[3], target[4], target[5]);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        printf("\n===============================\n");
        printf("%u bytes captured\n", header->caplen);

        struct ether_header* eth_header = (ether_header *)packet;
        printMAC("Ethernet SMAC", eth_header->ether_shost);
        printMAC("Ethernet DMAC", eth_header->ether_dhost);
        printf("Ethernet TYPE: %04x\n", ntohs(eth_header->ether_type));
        

        if(ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
            packet += sizeof(struct ether_header);

            struct ip* ip_header = (ip *)packet;
            printf("IP SIP: %s\n", inet_ntoa(ip_header->ip_src));
            printf("IP DIP: %s\n", inet_ntoa(ip_header->ip_dst));

            if(ip_header->ip_p == IPPROTO_TCP) {
                packet += ip_header->ip_hl * 4;

                struct tcphdr* tcp_header = (tcphdr *)packet;
                printf("TCP SPORT: %d\n", ntohs(tcp_header->th_sport));
                printf("TCP DPORT: %d\n", ntohs(tcp_header->th_dport));

                int data_length = header->caplen - sizeof(struct ether_header) - ip_header->ip_hl*4 - tcp_header->th_off*4;
                printf("TCP DATA LENGTH: %d\n", data_length);
                packet += tcp_header->th_off * 4;
                
                if (data_length > 15) data_length = 15;
                printf("TCP DATA: ");
                for(int i = 0; i < data_length; i++)
                    printf("%x ", packet[i]);
            }
        }
    }

    pcap_close(handle);
    return 0;
}

