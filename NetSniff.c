#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <jansson.h>

#define MAX_TCP_CONNECTIONS 100
#define MAX_PACKETS 1000

typedef struct {
    struct in_addr src_ip;
    struct in_addr dest_ip;
    uint16_t src_port;
    uint16_t dest_port;
} tcp_connection;

tcp_connection tcp_connections[MAX_TCP_CONNECTIONS];
int connection_count = 0;
int packet_counts[MAX_PACKETS] = {0};
int packet_index = 0;

pthread_mutex_t lock;

void print_timestamp(const struct pcap_pkthdr *header) {
    char timestr[64];
    time_t local_tv_sec;
    struct tm *local_time;

    local_tv_sec = header->ts.tv_sec;
    local_time = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", local_time);
    printf("[+] Packet Captured: %s.%.6d\n", timestr, (int)header->ts.tv_usec);
}

void print_ethernet_header(const u_char *packet) {
    struct ethhdr *eth = (struct ethhdr *)packet;

    printf("[+] Ethernet Header:\n");
    printf("  |- Source MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
           eth->h_source[0], eth->h_source[1], eth->h_source[2],
           eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("  |- Destination MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
           eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
           eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    printf("  |- Protocol: 0x%04x\n", ntohs(eth->h_proto));
}

void print_payload(const u_char *payload, int len) {
    int i;
    const u_char *ch = payload;

    printf("[+] Payload:\n");
    for (i = 0; i < len; i++) {
        if (i % 16 == 0)
            printf("  |- %04x: ", i);
        printf("%02x ", *ch);
        ch++;
        if (i % 16 == 15)
            printf("\n");
    }
    if (i % 16 != 0)
        printf("\n");
}

void format_mac_address(const unsigned char *mac, char *str) {
    sprintf(str, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void log_packet_details(const u_char *packet, const struct pcap_pkthdr *header, const struct ethhdr *eth, const struct iphdr *ip_header) {
    json_t *log_entry = json_object();
    char src_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    char src_mac[18];
    char dest_mac[18];

    inet_ntop(AF_INET, &(ip_header->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->daddr), dest_ip, INET_ADDRSTRLEN);
    format_mac_address(eth->h_source, src_mac);
    format_mac_address(eth->h_dest, dest_mac);

    json_object_set_new(log_entry, "timestamp", json_string(ctime(&header->ts.tv_sec)));
    json_object_set_new(log_entry, "source_mac", json_string(src_mac));
    json_object_set_new(log_entry, "destination_mac", json_string(dest_mac));
    json_object_set_new(log_entry, "protocol", json_string("0x0800"));
    json_object_set_new(log_entry, "source_ip", json_string(src_ip));
    json_object_set_new(log_entry, "destination_ip", json_string(dest_ip));

    char payload[header->caplen * 3 + 1];
    for (int i = 0; i < header->caplen; i++)
        sprintf(&payload[i * 3], "%02x ", packet[i]);
    json_object_set_new(log_entry, "payload", json_string(payload));

    FILE *logfile = fopen("packets.log", "a");
    if (logfile != NULL) {
        char *log_entry_str = json_dumps(log_entry, 0);
        fprintf(logfile, "%s\n", log_entry_str);
        free(log_entry_str);
        fclose(logfile);
    }
    json_decref(log_entry);
}

void send_alert(const char *message) {
    FILE *alertfile = fopen("alerts.log", "a");
    if (alertfile != NULL) {
        fprintf(alertfile, "%s\n", message);
        fclose(alertfile);
    }
}

void check_signature(const u_char *packet, const struct pcap_pkthdr *header) {
    const char *signature = "malicious";
    if (header->caplen >= strlen(signature) && memmem(packet, header->caplen, signature, strlen(signature))) {
        send_alert("[+] Alert Sent: Signature Match Found: Malicious Payload Detected");
    }
}

void check_anomalies(const struct iphdr *ip_header) {
    pthread_mutex_lock(&lock);
    packet_counts[packet_index]++;
    if (packet_index == MAX_PACKETS - 1) {
        packet_index = 0;
    } else {
        packet_index++;
    }
    pthread_mutex_unlock(&lock);

    int total_packets = 0;
    for (int i = 0; i < MAX_PACKETS; i++) {
        total_packets += packet_counts[i];
    }

    if (total_packets > 1000) {
        send_alert("[+] Alert Sent: Anomaly Detected: High traffic volume!");
    }
}

void check_stateful_analysis(const struct iphdr *ip_header, const struct tcphdr *tcp_header) {
    for (int i = 0; i < connection_count; i++) {
        if (tcp_connections[i].src_ip.s_addr == ip_header->saddr &&
            tcp_connections[i].dest_ip.s_addr == ip_header->daddr &&
            tcp_connections[i].src_port == ntohs(tcp_header->source) &&
            tcp_connections[i].dest_port == ntohs(tcp_header->dest)) {
            return;
        }
    }

    if (connection_count < MAX_TCP_CONNECTIONS) {
        tcp_connections[connection_count].src_ip.s_addr = ip_header->saddr;
        tcp_connections[connection_count].dest_ip.s_addr = ip_header->daddr;
        tcp_connections[connection_count].src_port = ntohs(tcp_header->source);
        tcp_connections[connection_count].dest_port = ntohs(tcp_header->dest);
        connection_count++;
        char alert_message[256];
        snprintf(alert_message, sizeof(alert_message), "[+] Alert Sent: New TCP Connection: %s:%d -> %s:%d",
                 inet_ntoa(*(struct in_addr *)&ip_header->saddr),
                 ntohs(tcp_header->source),
                 inet_ntoa(*(struct in_addr *)&ip_header->daddr),
                 ntohs(tcp_header->dest));
        send_alert(alert_message);
    } else {
        send_alert("[+] Alert Sent: Stateful Analysis: Too many connections tracked!");
    }
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));

    print_timestamp(header);
    print_ethernet_header(packet);

    printf("[+] IP Header:\n");
    printf("  |- Version: %d\n", ip_header->version);
    printf("  |- Header Length: %d bytes\n", ip_header->ihl * 4);
    printf("  |- TOS: 0x%x\n", ip_header->tos);
    printf("  |- Total Length: %d bytes\n", ntohs(ip_header->tot_len));
    printf("  |- Identification: 0x%x\n", ntohs(ip_header->id));
    printf("  |- Flags: 0x%x\n", ip_header->frag_off);
    printf("  |- Fragment Offset: %d\n", ntohs(ip_header->frag_off) & 0x1FFF);
    printf("  |- TTL: %d\n", ip_header->ttl);
    printf("  |- Protocol: %d\n", ip_header->protocol);
    printf("  |- Checksum: 0x%x\n", ntohs(ip_header->check));
    printf("  |- Source IP: %s\n", inet_ntoa(*(struct in_addr *)&ip_header->saddr));
    printf("  |- Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&ip_header->daddr));

    check_signature(packet, header);

    if (ip_header->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + ip_header->ihl * 4 + sizeof(struct ethhdr));
        printf("[+] TCP Header:\n");
        printf("  |- Source Port: %u\n", ntohs(tcp_header->source));
        printf("  |- Destination Port: %u\n", ntohs(tcp_header->dest));
        check_stateful_analysis(ip_header, tcp_header);
    } else if (ip_header->protocol == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)(packet + ip_header->ihl * 4 + sizeof(struct ethhdr));
        printf("[+] UDP Header:\n");
        printf("  |- Source Port: %u\n", ntohs(udp_header->source));
        printf("  |- Destination Port: %u\n", ntohs(udp_header->dest));
    }

    int header_size = sizeof(struct ethhdr) + ip_header->ihl * 4;
    print_payload(packet + header_size, header->len - header_size);

    log_packet_details(packet, header, eth, ip_header);
    check_anomalies(ip_header);
}

void *start_packet_capture(void *arg) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *dev;
    pcap_t *handle;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return NULL;
    }

    dev = alldevs;
    printf("[+] Device: %s\n", dev->name);

    handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev->name, errbuf);
        return NULL;
    }

    pcap_loop(handle, -1, packet_handler, NULL);
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return NULL;
}

int main() {
    pthread_t capture_thread;

    if (pthread_mutex_init(&lock, NULL) != 0) {
        printf("Mutex init failed\n");
        return 1;
    }

    printf("[+] Starting NetSniff...\n");
    printf("[+] Packet Sniffing Started...\n");
    printf("[+] Signature-Based Detection Enabled...\n");
    printf("[+] Anomaly Detection Enabled...\n");
    printf("[+] Stateful Protocol Analysis Enabled...\n");
    printf("[+] Logging Packets to 'packets.log'...\n");
    printf("[+] Sending Alerts to 'alerts.log'...\n");

    if (pthread_create(&capture_thread, NULL, start_packet_capture, NULL) != 0) {
        fprintf(stderr, "Error creating thread\n");
        return 1;
    }

    pthread_join(capture_thread, NULL);
    pthread_mutex_destroy(&lock);

    return 0;
}
