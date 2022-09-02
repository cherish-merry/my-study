#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/ip.h>

int my_program(struct xdp_md *ctx) {
    void *data = (void *) (long) ctx->data; //
    void *data_end = (void *) (long) ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *th;
    ip = data + sizeof(*eth);

    if (data + sizeof(*eth) + sizeof(struct iphdr) > data_end) {
        return XDP_DROP;
    }

    if (ip->protocol == IPPROTO_TCP) {
        th = (struct tcphdr *) (ip + 1);
        if ((void *) (th + 1) > data_end) {
            return XDP_DROP;
        }

        if (th->dest == htons(9090)) {
            eth->h_dest[0] = 0x08;
            eth->h_dest[1] = 0x00;
            eth->h_dest[2] = 0x27;
            eth->h_dest[3] = 0xdd;
            eth->h_dest[4] = 0x38;
            eth->h_dest[5] = 0x2a;
            return XDP_TX;
        }

        return XDP_DROP;
    }

    return XDP_PASS;
}
