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

    u32 fwd_packet_num;

    u32 total_packet_length;

    u32 min_IAT;

    u32 total_IAT;

    u32 min_fwd_IAT;

    u32 total_bak_IAT;

    u64 flow_start_time;

    u64 flow_last_time;

    u64 active_start_time;

    u64 active_end_time;

    u64 min_active_time;

    u64 total_active_time;
};
BPF_TABLE("lru_hash", struct FLOW_KEY,  struct FLOW_FEATURE_NODE, flow_table,  10000);
BPF_HASH(packet_cnt, u8, u32
);


int my_program(struct xdp_md *ctx) {
    u64 flowTimeout = 120000000;
    u64 activityTimeout = 5000000;
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
        u32 payload, sourceTransportPort, destinationTransportPort;
        u16 fin, rst;
        if (ip->protocol == IPPROTO_TCP) {
            th = (struct tcphdr *) (ip + 1);
            if ((void *) (th + 1) > data_end) {
                return XDP_DROP;
            }
            payload = data_end - data - sizeof ip - sizeof th;
            sourceTransportPort = th->source;
            destinationTransportPort = th->dest;
            fin = th->fin;
            rst = th->rst;
        } else {
            uh = (struct udphdr *) (ip + 1);
            if ((void *) (uh + 1) > data_end) {
                return XDP_DROP;
            }
            payload = data_end - data - sizeof ip - sizeof uh;
            sourceTransportPort = uh->source;
            destinationTransportPort = uh->dest;
        }


        struct FLOW_KEY fwdFlowKey = {0, 0, 0, 0, 0, 0, 0};
        fwdFlowKey.protocolIdentifier = ip->protocol;
        fwdFlowKey.sourceIPAddress = ip->saddr;
        fwdFlowKey.destinationIPAddress = ip->daddr;
        fwdFlowKey.sourceTransportPort = sourceTransportPort;
        fwdFlowKey.destinationTransportPort = destinationTransportPort;


        struct FLOW_KEY backFlowKey = {0, 0, 0, 0, 0, 0, 0};
        backFlowKey.protocolIdentifier = ip->protocol;
        backFlowKey.sourceIPAddress = ip->daddr;
        backFlowKey.destinationIPAddress = ip->saddr;
        backFlowKey.sourceTransportPort = destinationTransportPort;
        backFlowKey.destinationTransportPort = sourceTransportPort;

        struct FLOW_FEATURE_NODE *fwdNode = flow_table.lookup(&fwdFlowKey);
        struct FLOW_FEATURE_NODE *backNode = flow_table.lookup(&backFlowKey);

        u64 currentTime = bpf_ktime_get_ns() / 1000;
        if (fwdNode == backNode) {
            struct FLOW_FEATURE_NODE zero = {};
            zero.packet_num = 1;
            zero.fwd_packet_num = 1;
            zero.total_packet_length = payload;
            zero.flow_last_time = zero.flow_start_time = zero.active_start_time = zero.active_end_time = currentTime;
            flow_table.insert(&fwdFlowKey, &zero);
            return XDP_PASS;
        }

        if(backNode != NULL)  bpf_trace_printk("Hello World");

        bool fwd = fwdNode != NULL;
        struct FLOW_FEATURE_NODE *node = fwd ? fwdNode : backNode;
        struct FLOW_KEY flowKey = fwd ? fwdFlowKey : backFlowKey;
        if (node != NULL) {
            node->packet_num++;
            node->total_packet_length += payload;
            u64 currentIAT = currentTime - node->flow_last_time;
            node->flow_last_time = currentTime;

            node->min_IAT =
                    node->min_IAT == 0 ? currentIAT : currentIAT < node->min_IAT ? currentIAT : node->min_IAT;
            node->total_IAT += currentIAT;

            if (fwdNode != NULL) {
                node->fwd_packet_num++;
                node->min_fwd_IAT =
                        node->min_fwd_IAT == 0 ? currentIAT : currentIAT < node->min_fwd_IAT ? currentIAT
                                                                                             : node->min_fwd_IAT;
            }

            if (backNode != NULL) {
                node->total_bak_IAT += currentIAT;
            }

            if (currentTime - node->active_end_time > activityTimeout) {
                if (node->active_end_time > node->active_start_time) {
                    int currentActive = node->active_end_time - node->active_start_time;
                    node->total_active_time += currentActive;
                    node->min_active_time =
                            node->min_active_time == 0 ? currentActive : currentActive < node->min_active_time
                                                                         ? currentActive : node->min_active_time;
                    node->active_start_time = node->active_end_time = currentTime;
                } else {
                    node->active_end_time = currentTime;
                }
            }


            if (currentTime - node->flow_start_time > flowTimeout) {
                bpf_trace_printk("timeout");
                // for analysis
                flow_table.delete(&flowKey);
            }

            if (ip->protocol == IPPROTO_TCP && (fin == 1 || rst == 1)) {
                bpf_trace_printk("fin or rst");
                // for analysis
                flow_table.delete(&flowKey);
            }
        }

    }
    return XDP_PASS;
}