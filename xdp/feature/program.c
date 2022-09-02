#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/ip.h>
// bpf_trace_printk("hello world");
// sudo cat /sys/kernel/debug/tracing/trace_pipe
// u32 u8 u64




//BPF_ARRAY("name", leaf_type=u64, size=1000)


// protocolIdentifier、sourceIPAddress、destinationIPAddress、sourceTransportPort、destinationTransportPort



//Flow Duration
//Active Min、Active Mean、
//Flow IAT Min、Flow IAT Mean、Flow IAT Std、Fwd IAT Min、B.IAT Mean
//B.Packet Len Std、Avg Packet Size
const u64 flowTimeout = 120000000L;

const u64 activityTimeout = 5000000L;

struct FLOW_KEY {
    u8 protocolIdentifier;
    u8 padding_8;
    u16 padding_16;
    u32 sourceIPAddress;
    u32 destinationIPAddress;
    u32 sourceTransportPort;
    u32 destinationTransportPort;
};


struct FLOW_FEATURE_NODE {
    u32 packet_num;

    u64 flow_start_time;

    u64 flow_last_time;

    u64 active_start_time;

    u64 active_end_time;

    u64 min_active_time;

    u64 total_active_time;

    u64 total_packet_length;

    u64 min_IAT;

    u64 total_IAT;

    u64 min_fwd_IAT;

    u64 total_bak_IAT;
};
BPF_TABLE("lru_hash", struct FLOW_KEY,  struct FLOW_FEATURE_NODE, flow_table,  10000);
BPF_HASH(packet_cnt, u8, u32
);

int my_program(struct xdp_md *ctx) {
    void *data = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *th;
    struct udphdr *uh;
    ip = data + sizeof(*eth);

    if (data + sizeof(*eth) + sizeof(struct iphdr) > data_end) {
        return XDP_DROP;
    }

    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        struct FLOW_KEY flowKey = {0, 0, 0, 0, 0, 0, 0};
        if (ip->protocol == IPPROTO_TCP) {
            th = (struct tcphdr *) (ip + 1);
            if ((void *) (th + 1) > data_end) {
                return XDP_DROP;
            }
            flowKey.sourceTransportPort = th->source;
            flowKey.destinationTransportPort = th->dest;
        } else {
            uh = (struct udphdr *) (ip + 1);
            if ((void *) (uh + 1) > data_end) {
                return XDP_DROP;
            }
            flowKey.sourceTransportPort = uh->source;
            flowKey.destinationTransportPort = uh->dest;
        }
        flowKey.protocolIdentifier = ip->protocol;
        flowKey.sourceIPAddress = ip->saddr;
        flowKey.destinationIPAddress = ip->daddr;
        struct FLOW_FEATURE_NODE * node =  flow_table.lookup(&flowKey);
        if(node == NULL){
            bpf_trace_printk("null");
        } else {
            bpf_trace_printk("not null");
        }
    }
    return XDP_PASS;
}
