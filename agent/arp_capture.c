#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>

// Constants
#define ETH_ALEN 6
#define ETH_P_ARP 0x0806
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2
#define XDP_DROP 1
#define XDP_PASS 2

#define ntohs(x) __builtin_bswap16(x)

// ARP header structure
struct arphdr {
    unsigned short int ar_hrd;  // Hardware address type 
    unsigned short int ar_pro;  // Protocol address type
    unsigned char ar_hln;       // Hardware address length
    unsigned char ar_pln;       // Protocol address length
    unsigned short int ar_op;   // ARP opcode (command)
};

// Event structure to capture ARP details
struct arp_event {
    unsigned char src_mac[ETH_ALEN];
    unsigned char dst_mac[ETH_ALEN];
    unsigned char src_ip[4];
    unsigned char dst_ip[4];
    unsigned short op; // ARP opcode: request (1) or reply (2)
};

// Perf event map
struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 1024
};

// XDP program to capture ARP packets
SEC("xdp")
int capture_arp(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Ethernet header
    struct ethhdr *eth = data;

    // Bounds check for Ethernet header
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    // Check if it's an ARP packet
    if (ntohs(eth->h_proto) != ETH_P_ARP)
        return XDP_PASS;

    // ARP header
    struct arphdr *arp = data + sizeof(struct ethhdr);

    // Bounds check for ARP header
    if ((void *)(arp + 1) > data_end)
        return XDP_DROP;

    // Event to store ARP details
    struct arp_event event = {};

    // Pointer arithmetic to extract ARP details
    unsigned char *packet_start = (unsigned char *)(arp + 1);
    unsigned char *src_mac = packet_start;
    unsigned char *src_ip = src_mac + ETH_ALEN;
    unsigned char *dst_mac = src_ip + 4;
    unsigned char *dst_ip = dst_mac + ETH_ALEN;

    // Final bounds check
    if ((void *)(dst_ip + 4) > data_end)
        return XDP_DROP;

    // Copy ARP details to the event
    __builtin_memcpy(event.src_mac, src_mac, ETH_ALEN);
    __builtin_memcpy(event.src_ip, src_ip, 4);
    __builtin_memcpy(event.dst_mac, dst_mac, ETH_ALEN);
    __builtin_memcpy(event.dst_ip, dst_ip, 4);
    event.op = ntohs(arp->ar_op); // Store ARP opcode

    // Submit event to perf buffer
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
