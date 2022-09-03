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
    u32 packetNum;

    u32 totalPacketLength;

    u32 minIAT;

    u32 maxIAT;

    u32 totalIAT;

    u64 flowStartTime;

    u64 flowEndTime;

    u64 activeStartTime;

    u64 activeEndTime;

    u64 minActiveTime;

    u64 totalActiveTime;
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

        struct FLOW_FEATURE_NODE *fwdNode = flow_table.lookup(&fwdFlowKey);

        u64 currentTime = bpf_ktime_get_ns() / 1000;

        if (fwdNode == NULL) {
            struct FLOW_FEATURE_NODE zero = {};
            zero.packetNum = 1;
            zero.totalPacketLength = payload;
            zero.flowStartTime = zero.flowEndTime = zero.activeStartTime = zero.activeEndTime;
            flow_table.insert(&fwdFlowKey, &zero);
            return XDP_PASS;
        }

        fwdNode->packetNum++;
        fwdNode->totalPacketLength += payload;

        u64 currentIAT = currentTime - fwdNode->flowEndTime;
        fwdNode->flowEndTime = currentTime;

        fwdNode->minIAT =
                fwdNode->maxIAT == 0 ? currentIAT : currentIAT < fwdNode->minIAT ? currentIAT : fwdNode->minIAT;

        fwdNode->maxIAT = currentIAT > fwdNode->maxIAT ? currentIAT : fwdNode->maxIAT;

        fwdNode->totalIAT += currentIAT;


        if (currentTime - fwdNode->activeEndTime > activityTimeout) {
            if (fwdNode->activeEndTime > fwdNode->activeStartTime) {
                int currentActive = fwdNode->activeEndTime - fwdNode->activeStartTime;
                fwdNode->totalActiveTime += currentActive;
                fwdNode->minActiveTime =
                        fwdNode->minActiveTime == 0 ? currentActive : currentActive < fwdNode->minActiveTime
                                                                      ? currentActive : fwdNode->minActiveTime;
                fwdNode->activeStartTime = fwdNode->activeEndTime = currentTime;
            } else {
                fwdNode->activeStartTime = currentTime;
            }
        }

        if (currentTime - fwdNode->flowStartTime > flowTimeout) {
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
    return XDP_PASS;
}