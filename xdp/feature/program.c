#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/ip.h>

#define MAX_TREE_DEPTH  24
#define TREE_LEAF -1
#define FEATURE_VEC_LENGTH 22

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
    u32 protocol;

    u32 FIN;

    u32 SYN;

    u32 RST;

    u32 PSH;

    u32 ACK;

    u32 WIN;

    u32 packetNum;

    u32 minPacketLength;

    u32 maxPacketLength;

    u32 totalPacketLength;

    u32 minIAT;

    u32 maxIAT;

    u32 totalIAT;

    u64 flowStartTime;

    u64 flowEndTime;

    u64 activeStartTime;

    u64 activeEndTime;

    u64 minActiveTime;

    u64 maxActiveTime;

    u64 minIdle;

    u64 maxIdle;
};


BPF_TABLE("lru_hash", struct FLOW_KEY,  struct FLOW_FEATURE_NODE, flow_table,  10000);
BPF_TABLE("lru_hash", struct FLOW_KEY,  struct FLOW_FEATURE_NODE, exception_table,  10000);
BPF_HASH(packet_cnt, u8, u32
);

u32 static analysis(struct FLOW_FEATURE_NODE *fwdNode) {
    u64 feature_vec[FEATURE_VEC_LENGTH];

    feature_vec[0] = fwdNode->protocol;

    feature_vec[1] = fwdNode->flowEndTime - fwdNode->flowStartTime;

    feature_vec[2] = fwdNode->packetNum;

    feature_vec[3] = fwdNode->totalPacketLength;

    feature_vec[4] = fwdNode->maxPacketLength;

    feature_vec[5] = fwdNode->minPacketLength;

    feature_vec[6] = fwdNode->totalPacketLength / fwdNode->packetNum;

    feature_vec[7] = fwdNode->totalPacketLength / (feature_vec[1] / 1000000);

    feature_vec[8] = fwdNode->packetNum / (feature_vec[1] / 1000000);

    feature_vec[9] = fwdNode->totalIAT / (fwdNode->packetNum - 1);

    feature_vec[10] = fwdNode->maxIAT;

    feature_vec[11] = fwdNode->minIAT;

    feature_vec[12] = fwdNode->FIN;

    feature_vec[13] = fwdNode->SYN;

    feature_vec[14] = fwdNode->RST;

    feature_vec[15] = fwdNode->PSH;

    feature_vec[16] = fwdNode->ACK;

    feature_vec[17] = fwdNode->WIN;

    feature_vec[18] = fwdNode->maxActiveTime;

    feature_vec[19] = fwdNode->minActiveTime;

    feature_vec[20] = fwdNode->maxIdle;

    feature_vec[21] = fwdNode->minIdle;

    u32 current_node = 0;
    for (int i = 0; i < MAX_TREE_DEPTH; i++) {
        s32 *left_val = child_left.lookup(&current_node);
        s32 *right_val = child_right.lookup(&current_node);
        s32 *feature_val = feature.lookup(&current_node);
        u64 *threshold_val = threshold.lookup(&current_node);

        if (left_val == NULL || right_val == NULL || feature_val == NULL ||
            threshold_val == NULL || *left_val == TREE_LEAF ||
            *feature_val > sizeof(feature_vec) / sizeof(feature_vec[0]) || *feature_val >= FEATURE_VEC_LENGTH) {
            break;
        }

        u64 a = feature_vec[*feature_val];

        if (a <= *threshold_val) current_node = *left_val;
        else current_node = *right_val;


        bpf_trace_printk("feature_val:%u,threshold_val:%lu,feature_vec:%lu", *feature_val, *threshold_val, a);
    }

    u32 * value_val = value.lookup(&current_node);

    if (value_val == NULL) return 0;
    return *value_val;
}


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
        u16 fin, syn, rst, psh, ack, win;
        if (ip->protocol == IPPROTO_TCP) {
            th = (struct tcphdr *) (ip + 1);
            if ((void *) (th + 1) > data_end) {
                return XDP_DROP;
            }
            payload = data_end - (void *) (long) (th + 1);

            sourceTransportPort = th->source;
            destinationTransportPort = th->dest;
            fin = th->fin;
            syn = th->syn;
            psh = th->psh;
            rst = th->rst;
            ack = th->ack;
            win = th->window;
        } else {
            uh = (struct udphdr *) (ip + 1);
            if ((void *) (uh + 1) > data_end) {
                return XDP_DROP;
            }
            payload = data_end - (void *) (long) (uh + 1);
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
            if (ip->protocol == IPPROTO_TCP) {
                zero.WIN = win;
            }
            zero.protocol = ip->protocol;
            zero.packetNum = 1;
            zero.minPacketLength = zero.maxPacketLength = zero.totalPacketLength = payload;
            zero.flowStartTime = zero.flowEndTime = zero.activeStartTime = zero.activeEndTime = currentTime;
            flow_table.insert(&fwdFlowKey, &zero);
            return XDP_PASS;
        }

        if (ip->protocol == IPPROTO_TCP) {
            fwdNode->FIN += fin;
            fwdNode->SYN += syn;
            fwdNode->RST += rst;
            fwdNode->PSH += psh;
            fwdNode->ACK += ack;
        }

        fwdNode->packetNum++;
        fwdNode->minPacketLength = payload < fwdNode->minPacketLength ? payload : fwdNode->minPacketLength;
        fwdNode->maxPacketLength = payload > fwdNode->maxPacketLength ? payload : fwdNode->maxPacketLength;
        fwdNode->totalPacketLength += payload;

        u64 currentIAT = currentTime - fwdNode->flowEndTime;
        fwdNode->flowEndTime = currentTime;

        fwdNode->minIAT =
                fwdNode->minIAT == 0 ? currentIAT : currentIAT < fwdNode->minIAT ? currentIAT : fwdNode->minIAT;

        fwdNode->maxIAT = currentIAT > fwdNode->maxIAT ? currentIAT : fwdNode->maxIAT;

        fwdNode->totalIAT += currentIAT;


        if (currentTime - fwdNode->activeEndTime > activityTimeout) {
//            bpf_trace_printk("active timeout");
            if (fwdNode->activeEndTime > fwdNode->activeStartTime) {
                int currentActive = fwdNode->activeEndTime - fwdNode->activeStartTime;
                fwdNode->minActiveTime =
                        fwdNode->minActiveTime == 0 ? currentActive : currentActive < fwdNode->minActiveTime
                                                                      ? currentActive : fwdNode->minActiveTime;
                fwdNode->maxActiveTime =
                        currentActive > fwdNode->maxActiveTime ? currentActive : fwdNode->maxActiveTime;

                int currentIdle = currentTime - fwdNode->activeEndTime;

                fwdNode->minIdle = fwdNode->minIdle == 0 ? currentIdle : currentIdle < fwdNode->minIdle ? currentIdle
                                                                                                        : fwdNode->minIdle;
                fwdNode->maxIdle = fwdNode->maxIdle == 0 ? currentIdle : currentIdle > fwdNode->maxIdle ? currentIdle
                                                                                                        : fwdNode->maxIdle;
                fwdNode->activeStartTime = fwdNode->activeEndTime = currentTime;
            }
        } else {
            fwdNode->activeEndTime = currentTime;
        }

        if (currentTime - fwdNode->flowStartTime > flowTimeout) {
            bpf_trace_printk("timeout");
            // for analysis
            flow_table.delete(&fwdFlowKey);
            if (analysis(fwdNode) == 1) exception_table.insert(&fwdFlowKey, fwdNode);
        }

        if (ip->protocol == IPPROTO_TCP && (fin == 1 || rst == 1)) {
            bpf_trace_printk("fin or rst");
            // for analysis
            flow_table.delete(&fwdFlowKey);
            if (analysis(fwdNode) == 1) exception_table.insert(&fwdFlowKey, fwdNode);
        }
    }
    return XDP_PASS;
}


