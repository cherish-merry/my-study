#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/ip.h>

#define MAX_TREE_DEPTH  8
#define TREE_LEAF -1
#define FEATURE_VEC_LENGTH 32

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
    u8 protocol;

    u8 endWay;

    u32 WIN;

    u8 FIN;

    u8 SYN;

    u8 RST;

    u8 PSH;

    u8 ACK;

    u8 URG;

    u8 CWR;

    u8 ECE;


    u32 packetNum;

    u32 minPacketLength;

    u32 maxPacketLength;

    u32 totalPacketLength;

    u32 minIAT;

    u32 maxIAT;

    u32 totalIAT;

    u32 activePackets;

    u64 activeTotalTime;

    u32 idlePackets;

    u64 idleTotalTime;

    u64 flowStartTime;

    u64 flowEndTime;

    u64 activeStartTime;

    u64 activeEndTime;

    u64 minActiveTime;

    u64 maxActiveTime;

    u64 minIdle;

    u64 maxIdle;
};

struct PACKET_INFO {
    struct FLOW_KEY flowKey;
    u32 payload;
    u8 fin, syn, rst, psh, ack, urg, cwr, ece;
    u16 win;
    u64 currentTime;
};

static u64 flowTimeout = 120000000;
static u64 activityTimeout = 5000000;

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

    feature_vec[7] = fwdNode->maxPacketLength - fwdNode->minPacketLength;

    feature_vec[8] = fwdNode->totalPacketLength / (feature_vec[1] / 1000000);

    feature_vec[9] = fwdNode->packetNum / (feature_vec[1] / 1000000);

    feature_vec[10] = fwdNode->totalIAT / (fwdNode->packetNum - 1);

    feature_vec[11] = fwdNode->maxIAT - fwdNode->minIAT;

    feature_vec[12] = fwdNode->maxIAT;

    feature_vec[13] = fwdNode->minIAT;

    feature_vec[14] = fwdNode->FIN;

    feature_vec[15] = fwdNode->SYN;

    feature_vec[16] = fwdNode->RST;

    feature_vec[17] = fwdNode->PSH;

    feature_vec[18] = fwdNode->ACK;

    feature_vec[19] = fwdNode->URG;

    feature_vec[20] = fwdNode->CWR;

    feature_vec[21] = fwdNode->ECE;

    feature_vec[22] = fwdNode->WIN;

    feature_vec[23] = fwdNode->activeTotalTime / fwdNode->activePackets;

    feature_vec[24] = fwdNode->maxIAT - fwdNode->minIAT;

    feature_vec[25] = fwdNode->maxActiveTime;

    feature_vec[26] = fwdNode->minActiveTime;

    feature_vec[27] = fwdNode->idleTotalTime / fwdNode->idlePackets;

    feature_vec[28] = fwdNode->maxIdle - fwdNode->minIdle;

    feature_vec[29] = fwdNode->maxIdle;

    feature_vec[30] = fwdNode->minIdle;

    feature_vec[31] = fwdNode->endWay;

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

void static endActiveIdleTime(u64 currentTime, struct FLOW_FEATURE_NODE *fwdNode) {
    if (fwdNode->activeEndTime - fwdNode->activeStartTime > 0) {
        u64 addTime = fwdNode->activeEndTime - fwdNode->activeStartTime;
        if (fwdNode->maxActiveTime == 0) fwdNode->maxActiveTime = addTime;
        else fwdNode->maxActiveTime = addTime > fwdNode->maxActiveTime ? addTime : fwdNode->maxActiveTime;

        if (fwdNode->minActiveTime == 0) fwdNode->minActiveTime = addTime;
        else fwdNode->minActiveTime = addTime < fwdNode->minActiveTime ? addTime : fwdNode->minActiveTime;

        fwdNode->activeTotalTime += addTime;
    }

    if (currentTime - fwdNode->activeEndTime > activityTimeout) {
        u64 addTime = currentTime - fwdNode->activeEndTime;

        if (fwdNode->maxIdle == 0) fwdNode->maxIdle = addTime;
        else fwdNode->maxIdle = addTime > fwdNode->maxIdle ? addTime : fwdNode->maxIdle;

        if (fwdNode->minIdle == 0) fwdNode->minIdle = addTime;
        else fwdNode->minIdle = addTime < fwdNode->minIdle ? addTime : fwdNode->minIdle;
    }
}

void static addFirstPacket(struct PACKET_INFO packetInfo) {
    struct FLOW_FEATURE_NODE zero = {};
    if (ip->protocol == IPPROTO_TCP) {
        zero.WIN = packetInfo.win;
    }
    zero.protocol = packetInfo.flowKey.protocolIdentifier;
    zero.packetNum = 1;
    zero.minPacketLength = zero.maxPacketLength = zero.totalPacketLength = packetInfo.payload;
    zero.flowStartTime = zero.flowEndTime = zero.activeStartTime = zero.activeEndTime = packetInfo.currentTime;
    flow_table.insert(&packetInfo.flowKey, &zero);
}

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
        u8 protocol;
        u32 sourceTransportPort, destinationTransportPort;
        struct PACKET_INFO packetInfo = {};
        if (ip->protocol == IPPROTO_TCP) {
            th = (struct tcphdr *) (ip + 1);
            if ((void *) (th + 1) > data_end) {
                return XDP_DROP;
            }
            protocol = IPPROTO_TCP;
            packetInfo.payload = data_end - (void *) (long) (th + 1);
            sourceTransportPort = th->source;
            destinationTransportPort = th->dest;
            packetInfo.fin = th->fin;
            packetInfo.syn = th->syn;
            packetInfo.psh = th->psh;
            packetInfo.rst = th->rst;
            packetInfo.ack = th->ack;
            packetInfo.urg = th->urg;
            packetInfo.cwr = th->cwr;
            packetInfo.ece = th->ece;
            packetInfo.win = th->window;
        } else {
            uh = (struct udphdr *) (ip + 1);
            if ((void *) (uh + 1) > data_end) {
                return XDP_DROP;
            }
            protocol = IPPROTO_UDP;
            packetInfo.payload = data_end - (void *) (long) (uh + 1);
            sourceTransportPort = uh->source;
            destinationTransportPort = uh->dest;
        }

        struct FLOW_KEY fwdFlowKey = {0, 0, 0, 0, 0, 0, 0};
        fwdFlowKey.protocolIdentifier = protocol;
        fwdFlowKey.sourceIPAddress = ip->saddr;
        fwdFlowKey.destinationIPAddress = ip->daddr;
        fwdFlowKey.sourceTransportPort = sourceTransportPort;
        fwdFlowKey.destinationTransportPort = destinationTransportPort;

        packetInfo.flowKey = fwdFlowKey;
        packetInfo.currentTime = bpf_ktime_get_ns() / 1000;

        struct FLOW_FEATURE_NODE *fwdNode = flow_table.lookup(&fwdFlowKey);

        if (fwdNode == NULL) {
            addFirstPacket(currentTime, fwdFlowKey);
            return XDP_PASS;
        }

        if (currentTime - fwdNode->flowStartTime > flowTimeout) {
            //analysis
            bpf_trace_printk("timeout");
            flow_table.delete(&fwdFlowKey);
            if (analysis(fwdNode) == 1) exception_table.insert(&fwdFlowKey, fwdNode);

            //endActiveIdleTime
            endActiveIdleTime(currentTime, fwdNode);

            //addFirstPacket
        }


        if (ip->protocol == IPPROTO_TCP) {
            fwdNode->FIN += fin;
            fwdNode->SYN += syn;
            fwdNode->RST += rst;
            fwdNode->PSH += psh;
            fwdNode->ACK += ack;
            fwdNode->URG += urg;
            fwdNode->CWR += cwr;
            fwdNode->ECE += ece;
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

        if (ip->protocol == IPPROTO_TCP && (fin == 1 || rst == 1)) {
            bpf_trace_printk("fin or rst");
            // for analysis
            flow_table.delete(&fwdFlowKey);
            if (analysis(fwdNode) == 1) exception_table.insert(&fwdFlowKey, fwdNode);
        }
    }
    return XDP_PASS;
}


