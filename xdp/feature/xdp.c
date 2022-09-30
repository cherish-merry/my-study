#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/ip.h>

#define MAX_TREE_DEPTH  15
#define TREE_LEAF -1
#define FEATURE_VEC_LENGTH 64

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

static u64 flowTimeout = 15000000;
static u64 activityTimeout = 1000000;
static const char *feature_map[] = {"Protocol", "Flow Duration",
                                    "Total Packet", "Total Length of Packet",
                                    "Packet Length Max", "Packet Length Min",
                                    "Packet Length Mean", "Packet Length Extreme Deviation",
                                    "Flow Bytes/s", "Flow Packets/s",
                                    "IAT Mean", "IAT Extreme Deviation", "IAT Max",
                                    "IAT Min", "FIN", "SYN", "RST", "PSH", "ACK",
                                    "URG", "CWR", "ECE", "WIN", "Active Mean",
                                    "Active Extreme Deviation", "Active Max", "Active Min",
                                    "Idle Mean", "Idle Extreme Deviation",
                                    "Idle Max", "Idle Min", "End Way"};


BPF_TABLE("lru_hash", struct FLOW_KEY,  struct FLOW_FEATURE_NODE, flow_table,  10000);
BPF_TABLE("lru_hash", struct FLOW_KEY,  struct FLOW_FEATURE_NODE, result_table,  10000);
BPF_TABLE("lru_hash", struct FLOW_KEY,  u32 , exception_table,  10000);
BPF_PERCPU_ARRAY(statistic, u32,
5);


u32 static analysis(struct FLOW_FEATURE_NODE *fwdNode, struct FLOW_KEY fwdFlowKey) {
    if (fwdNode->flowEndTime - fwdNode->flowStartTime < 10) return 0;

    u64 feature_vec[FEATURE_VEC_LENGTH];

    bpf_trace_printk("IP:%llu", fwdFlowKey.sourceIPAddress);

    feature_vec[0] = fwdNode->protocol;
    bpf_trace_printk("Protocol:%llu", feature_vec[0]);

    feature_vec[1] = fwdNode->flowEndTime - fwdNode->flowStartTime;
    bpf_trace_printk("Flow Duration:%llu", feature_vec[1]);

    feature_vec[2] = fwdNode->packetNum;
    bpf_trace_printk("Total Fwd Packet:%llu", feature_vec[2]);
    feature_vec[3] = fwdNode->totalPacketLength;
    bpf_trace_printk("Total Length of Fwd Packet:%llu", feature_vec[3]);

    feature_vec[4] = fwdNode->maxPacketLength;
    bpf_trace_printk("Fwd Packet Length Max:%llu", feature_vec[4]);

    feature_vec[5] = fwdNode->minPacketLength;
    bpf_trace_printk("Fwd Packet Length Min:%llu", feature_vec[5]);

    feature_vec[6] = fwdNode->totalPacketLength / fwdNode->packetNum;
    bpf_trace_printk("Fwd Packet Length Mean:%llu", feature_vec[6]);

    feature_vec[7] = 100 * (fwdNode->maxPacketLength - fwdNode->minPacketLength) /
                     (fwdNode->maxPacketLength + fwdNode->minPacketLength);
    bpf_trace_printk("Fwd Packet Length Extreme Deviation:%llu", feature_vec[7]);

    feature_vec[8] = fwdNode->totalPacketLength * 1000000 / feature_vec[1];
    bpf_trace_printk("Flow Bytes/s:%llu", feature_vec[8]);

    feature_vec[9] = fwdNode->packetNum * 1000000 / feature_vec[1];
    bpf_trace_printk("Flow Packets/s:%llu", feature_vec[9]);

    feature_vec[10] = fwdNode->totalIAT / (fwdNode->packetNum - 1);
    bpf_trace_printk("Fwd IAT Mean:%llu", feature_vec[10]);

    feature_vec[11] = 100 * (fwdNode->maxIAT - fwdNode->minIAT) / (fwdNode->maxIAT + fwdNode->minIAT);
    bpf_trace_printk("Fwd IAT Extreme Deviation:%llu", feature_vec[11]);

    feature_vec[12] = fwdNode->maxIAT;
    bpf_trace_printk("Fwd IAT Max:%llu", feature_vec[12]);

    feature_vec[13] = fwdNode->minIAT;
    bpf_trace_printk("Fwd IAT Min:%llu", feature_vec[13]);

    feature_vec[14] = fwdNode->FIN;
    bpf_trace_printk("FIN Flag Count:%llu", feature_vec[14]);

    feature_vec[15] = fwdNode->SYN;
    bpf_trace_printk("SYN Flag Count:%llu", feature_vec[15]);

    feature_vec[16] = fwdNode->RST;
    bpf_trace_printk("RST Flag Count:%llu", feature_vec[16]);

    feature_vec[17] = fwdNode->PSH;
    bpf_trace_printk("PSH Flag Count:%llu", feature_vec[17]);

    feature_vec[18] = fwdNode->ACK;
    bpf_trace_printk("ACK Flag Count:%llu", feature_vec[18]);

    feature_vec[19] = fwdNode->URG;
    bpf_trace_printk("URG Flag Count:%llu", feature_vec[19]);

    feature_vec[20] = fwdNode->CWR;
    bpf_trace_printk("CWR Flag Count:%llu", feature_vec[20]);

    feature_vec[21] = fwdNode->ECE;
    bpf_trace_printk("ECE Flag Count:%llu", feature_vec[21]);

    feature_vec[22] = fwdNode->WIN;
    bpf_trace_printk("FWD Init Win Bytes:%llu", feature_vec[22]);

    feature_vec[23] = fwdNode->activeTotalTime / fwdNode->activePackets;
    bpf_trace_printk("Active Mean:%llu", feature_vec[23]);

    feature_vec[24] =
            100 * (fwdNode->maxActiveTime - fwdNode->minActiveTime) / (fwdNode->maxActiveTime + fwdNode->minActiveTime);
    bpf_trace_printk("Active Extreme Deviation:%llu", feature_vec[24]);

    feature_vec[25] = fwdNode->maxActiveTime;
    bpf_trace_printk("Active Max:%llu", feature_vec[25]);

    feature_vec[26] = fwdNode->minActiveTime;
    bpf_trace_printk("Active Min:%llu", feature_vec[26]);

    feature_vec[27] = fwdNode->idleTotalTime / fwdNode->idlePackets;
    bpf_trace_printk("Idle Mean:%llu", feature_vec[27]);

    feature_vec[28] = 100 * (fwdNode->maxIdle - fwdNode->minIdle) / (fwdNode->maxIdle + fwdNode->minIdle);
    bpf_trace_printk("Idle Extreme Deviation:%llu", feature_vec[28]);

    feature_vec[29] = fwdNode->maxIdle;
    bpf_trace_printk("Idle Max:%llu", feature_vec[29]);

    feature_vec[30] = fwdNode->minIdle;
    bpf_trace_printk("Idle Min:%llu", feature_vec[30]);

    feature_vec[31] = fwdNode->endWay;
    bpf_trace_printk("End Way:%llu", feature_vec[31]);

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
        fwdNode->activePackets += 1;

    }

    if (currentTime - fwdNode->activeEndTime > activityTimeout) {
        u64 addTime = currentTime - fwdNode->activeEndTime;

        if (fwdNode->maxIdle == 0) fwdNode->maxIdle = addTime;
        else fwdNode->maxIdle = addTime > fwdNode->maxIdle ? addTime : fwdNode->maxIdle;

        if (fwdNode->minIdle == 0) fwdNode->minIdle = addTime;
        else fwdNode->minIdle = addTime < fwdNode->minIdle ? addTime : fwdNode->minIdle;

        fwdNode->idleTotalTime += addTime;
        fwdNode->idlePackets += 1;
        fwdNode->flowEndTime = currentTime;
    }
}

void static updateActiveIdleTime(u64 currentTime, struct FLOW_FEATURE_NODE *fwdNode) {
    if (currentTime - fwdNode->flowEndTime > activityTimeout) {
        if (fwdNode->activeEndTime - fwdNode->activeStartTime > 0) {
            u64 addTime = fwdNode->activeEndTime - fwdNode->activeStartTime;
            if (fwdNode->maxActiveTime == 0) fwdNode->maxActiveTime = addTime;
            else fwdNode->maxActiveTime = addTime > fwdNode->maxActiveTime ? addTime : fwdNode->maxActiveTime;

            if (fwdNode->minActiveTime == 0) fwdNode->minActiveTime = addTime;
            else fwdNode->minActiveTime = addTime < fwdNode->minActiveTime ? addTime : fwdNode->minActiveTime;

            fwdNode->activeTotalTime += addTime;
            fwdNode->activePackets += 1;
        }

        u64 addTime = currentTime - fwdNode->activeEndTime;

        if (fwdNode->maxIdle == 0) fwdNode->maxIdle = addTime;
        else fwdNode->maxIdle = addTime > fwdNode->maxIdle ? addTime : fwdNode->maxIdle;

        if (fwdNode->minIdle == 0) fwdNode->minIdle = addTime;
        else fwdNode->minIdle = addTime < fwdNode->minIdle ? addTime : fwdNode->minIdle;
        fwdNode->idleTotalTime += addTime;
        fwdNode->idlePackets += 1;


        fwdNode->activeStartTime = fwdNode->activeEndTime = currentTime;
    } else {
        fwdNode->activeEndTime = currentTime;
    }
}

void static addFirstPacket(struct PACKET_INFO packetInfo) {
    u8 statistic_flow = 2;
    statistic.increment(statistic_flow);


    struct FLOW_FEATURE_NODE zero = {};
    if (packetInfo.flowKey.protocolIdentifier == IPPROTO_TCP) {
        zero.WIN = packetInfo.win;
    }
    zero.protocol = packetInfo.flowKey.protocolIdentifier;
    zero.packetNum = 1;
    zero.minPacketLength = zero.maxPacketLength = zero.totalPacketLength = packetInfo.payload;
    zero.flowStartTime = zero.flowEndTime = zero.activeStartTime = zero.activeEndTime = packetInfo.currentTime;
    zero.FIN = packetInfo.fin;
    zero.SYN = packetInfo.syn;
    zero.RST = packetInfo.rst;
    zero.PSH = packetInfo.psh;
    zero.ACK = packetInfo.ack;
    zero.URG = packetInfo.urg;
    zero.CWR = packetInfo.cwr;
    zero.ECE = packetInfo.ece;
    flow_table.insert(&packetInfo.flowKey, &zero);
}

void static addPacket(struct PACKET_INFO packetInfo, struct FLOW_FEATURE_NODE *fwdNode) {
    fwdNode->FIN += packetInfo.fin;
    fwdNode->SYN += packetInfo.syn;
    fwdNode->RST += packetInfo.rst;
    fwdNode->PSH += packetInfo.psh;
    fwdNode->ACK += packetInfo.ack;
    fwdNode->URG += packetInfo.urg;
    fwdNode->CWR += packetInfo.cwr;
    fwdNode->ECE += packetInfo.ece;

    fwdNode->packetNum++;
    fwdNode->minPacketLength =
            packetInfo.payload < fwdNode->minPacketLength ? packetInfo.payload : fwdNode->minPacketLength;
    fwdNode->maxPacketLength =
            packetInfo.payload > fwdNode->maxPacketLength ? packetInfo.payload : fwdNode->maxPacketLength;
    fwdNode->totalPacketLength += packetInfo.payload;

    u64 currentIAT = packetInfo.currentTime - fwdNode->flowEndTime;
    fwdNode->minIAT =
            fwdNode->minIAT == 0 ? currentIAT : currentIAT < fwdNode->minIAT ? currentIAT : fwdNode->minIAT;
    fwdNode->maxIAT = currentIAT > fwdNode->maxIAT ? currentIAT : fwdNode->maxIAT;
    fwdNode->totalIAT += currentIAT;

    fwdNode->flowEndTime = packetInfo.currentTime;
}


int my_program(struct xdp_md *ctx) {
    void *data = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *th;
    struct udphdr *uh;
    ip = data + sizeof(*eth);

    u8 statistic_processed_packet = 0;
    statistic.increment(statistic_processed_packet);

    if (data + sizeof(*eth) + sizeof(struct iphdr) > data_end) {
        return XDP_DROP;
    }

    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {

        u8 statistic_tcp_udp_packet = 1;
        statistic.increment(statistic_tcp_udp_packet);

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
            addFirstPacket(packetInfo);
            return XDP_PASS;
        }

        if (packetInfo.currentTime - fwdNode->flowStartTime > flowTimeout) {
            //endActiveIdleTime
            endActiveIdleTime(packetInfo.currentTime, fwdNode);

            //analysis
            fwdNode->endWay = 0;
            if (analysis(fwdNode, fwdFlowKey) == 1) {
                u8 statistic_exception = 4;
                statistic.increment(statistic_exception);
                bpf_trace_printk("Label: Attack\n");

                u32 one = 1;
                u32 * val = exception_table.lookup(&fwdFlowKey);
                if (val) {
                    *val += 1;
                } else exception_table.insert(&fwdFlowKey, &one);
            } else {
                bpf_trace_printk("Label: Normal\n");
            }

            u8 statistic_flow_end = 3;
            statistic.increment(statistic_flow_end);

            if (fwdFlowKey.sourceIPAddress == 1929488576) {
                result_table.insert(&fwdFlowKey, fwdNode);
            }

            //remove
            flow_table.delete(&fwdFlowKey);

            //addFirstPacket
            addFirstPacket(packetInfo);
            return XDP_PASS;
        }


        if (packetInfo.fin == 1 || packetInfo.rst == 1) {
            //updateActiveIdleTime
            updateActiveIdleTime(packetInfo.currentTime, fwdNode);

            // addPacket
            addPacket(packetInfo, fwdNode);

            //endActiveIdleTime
            endActiveIdleTime(packetInfo.currentTime, fwdNode);


            //analysis
            fwdNode->endWay = 1;
            if (analysis(fwdNode, fwdFlowKey) == 1) {
                u8 statistic_exception = 4;
                statistic.increment(statistic_exception);
                bpf_trace_printk("Label: Attack\n");
                u32 one = 1;
                u32 * val = exception_table.lookup(&fwdFlowKey);
                if (val) {
                    *val += 1;
                } else exception_table.insert(&fwdFlowKey, &one);
            } else {
                bpf_trace_printk("Label: Normal\n");
            }

            u8 statistic_flow_end = 3;
            statistic.increment(statistic_flow_end);

            if (fwdFlowKey.sourceIPAddress == 1929488576) {
                result_table.insert(&fwdFlowKey, fwdNode);
            }



            //remove
            flow_table.delete(&fwdFlowKey);

            return XDP_PASS;
        }

        //updateActiveIdleTime
        updateActiveIdleTime(packetInfo.currentTime, fwdNode);

        // addPacket
        addPacket(packetInfo, fwdNode);
    }
    return XDP_PASS;
}


