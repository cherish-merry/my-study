#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/ip.h>

#define MAX_TREE_DEPTH  15
#define TREE_LEAF -1
#define FEATURE_VEC_LENGTH 16
#define flow_timeout  15000
#define activity_timeout  3000
#define statistic_packet_num  0
#define statistic_tcp  1
#define statistic_udp  2
#define statistic_flow  3
#define statistic_flow_timeout  4
#define statistic_flow_fin  5
#define statistic_flow_rst  6
#define statistic_exception  7


struct STATISTIC {
    u32 n;
    u32 dev;
    s32 m1;
    u32 m2;
    u32 sum;
    u32 min;
    u32 max;
};

struct FLOW_KEY {
    u8 protocol;
    u32 src;
    u32 dest;
    u32 src_port;
    u32 dest_port;
};

struct FLOW_FEATURE_NODE {
    u8 protocol;

    u8 syn;

    u8 fin;

    u8 rst;

    u8 psh;

    u8 urg;

    u16 win;

    u64 flow_start_time;
    u64 flow_end_time;
    u64 active_start_time;
    u64 active_end_time;

    struct STATISTIC packet_length;

    struct STATISTIC iat;
};

struct PACKET_INFO {
    struct FLOW_KEY *flow_key;
    u8 fin, rst, syn, psh, urg;
    u16 win;
    u64 current_time;
    u32 payload;
};

BPF_TABLE("lru_hash", struct FLOW_KEY,  struct FLOW_FEATURE_NODE, flow_table,  10000);
BPF_TABLE("lru_hash", struct FLOW_KEY,  struct FLOW_FEATURE_NODE, result_table,  10000);
BPF_TABLE("lru_hash", struct FLOW_KEY,  u32 , exception_table,  10000);
BPF_PERCPU_ARRAY(statistic, u32,
8);

void static increase(struct STATISTIC *statistic, u32 d) {
    if (statistic->n == 0) {
        statistic->m1 = statistic->m2 = 0;
        statistic->min = statistic->max = d;
    }
    statistic->n++;
    statistic->sum += d;
    if (d < statistic->min) statistic->min = d;
    if (d > statistic->max) statistic->max = d;
    if (d > statistic->m1) {
        statistic->dev = d - statistic->m1;
        statistic->m1 += statistic->dev / statistic->n;
    } else {
        statistic->dev = statistic->m1 - d;
        statistic->m1 -= statistic->dev / statistic->n;
    }
    statistic->m2 += (statistic->n - 1) * statistic->dev * statistic->dev / statistic->n;
}

u32 static analysis(struct FLOW_FEATURE_NODE *flow) {
    if (flow->flow_end_time - flow->flow_start_time < 1 || flow->packet_length.n <= 1) return 0;

    u64 feature_vec[FEATURE_VEC_LENGTH];

    feature_vec[0] = flow->flow_end_time - flow->flow_start_time;

    feature_vec[1] = flow->packet_length.sum * 1000 / (flow->flow_end_time - flow->flow_start_time);

    feature_vec[2] = flow->packet_length.n * 1000 * 100 / (flow->flow_end_time - flow->flow_start_time);

    feature_vec[3] = flow->iat.sum / flow->iat.n;

    feature_vec[4] = flow->iat.m2 / (flow->iat.n - 1);

    feature_vec[5] = flow->iat.max;

    feature_vec[6] = flow->iat.min;

    feature_vec[7] = flow->packet_length.n;

    feature_vec[8] = flow->packet_length.min;

    feature_vec[9] = flow->packet_length.max;


    feature_vec[10] = flow->packet_length.sum / flow->packet_length.n;

    feature_vec[11] = flow->packet_length.m2 / (flow->packet_length.n - 1);


    feature_vec[12] = flow->fin;

    feature_vec[13] = flow->syn;

    feature_vec[14] = flow->rst;

    feature_vec[15] = flow->psh;



//    for (int i = 0; i < FEATURE_VEC_LENGTH; i++) {
//        bpf_trace_printk("%u:%u", i, feature_vec[i]);
//    }

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
//        bpf_trace_printk("feature_val:%u,threshold_val:%lu,feature_vec:%lu", *feature_val, *threshold_val, a);
    }
    u32 * value_val = value.lookup(&current_node);
    if (value_val == NULL) return 0;

    if (*value_val == 1) {
        statistic.increment(statistic_exception);
//        bpf_trace_printk("Label: Attack\n");
    } else {
//        bpf_trace_printk("Label: Normal\n");
    }
    return *value_val;
}


void static addFirstPacket(struct PACKET_INFO *packet_info) {
    statistic.increment(statistic_flow);
    struct FLOW_FEATURE_NODE zero = {};
    zero.fin += packet_info->fin;
    zero.syn += packet_info->syn;
    zero.rst += packet_info->rst;
    zero.psh += packet_info->psh;
    zero.urg += packet_info->urg;
    zero.protocol = packet_info->flow_key->protocol;
    zero.win = packet_info->win;
    zero.flow_start_time = zero.flow_end_time = packet_info->current_time;
    increase(&zero.packet_length, packet_info->payload);
    flow_table.insert(packet_info->flow_key, &zero);
}

void static addPacket(struct PACKET_INFO *packet_info, struct FLOW_FEATURE_NODE *flow) {
    flow->fin += packet_info->fin;
    flow->syn += packet_info->syn;
    flow->rst += packet_info->rst;
    flow->psh += packet_info->psh;
    flow->urg += packet_info->urg;
    increase(&flow->packet_length, packet_info->payload);
    increase(&flow->iat, packet_info->current_time - flow->flow_end_time);
    flow->flow_end_time = packet_info->current_time;
}

void static printStatistic() {
    u32 idx;
    u32 * cnt;
    for (int i = 0; i < 8; i++) {
        idx = i;
        cnt = statistic.lookup(&idx);
        if (cnt) {
            if(i == 0) bpf_trace_printk("packet_num: %u", *cnt);
            if(i == 1) bpf_trace_printk("tcp: %u", *cnt);
            if(i == 2) bpf_trace_printk("udp: %u", *cnt);
            if(i == 3) bpf_trace_printk("flow: %u", *cnt);
            if(i == 4) bpf_trace_printk("flow_timeout: %u", *cnt);
            if(i == 5) bpf_trace_printk("flow_fin: %u", *cnt);
            if(i == 6) bpf_trace_printk("flow_rst: %u", *cnt);
            if(i == 7) bpf_trace_printk("exception: %u", *cnt);
        }
    }
    bpf_trace_printk("-------------------------------------");
}

int my_program(struct xdp_md *ctx) {
    void *data = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *th;
    struct udphdr *uh;

//    printStatistic();
    statistic.increment(statistic_packet_num);


    ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(struct iphdr) > data_end) {
        return XDP_DROP;
    }

//    if (ip->saddr != 1929488576) {
//        return XDP_PASS;
//    }

//    if (htonl(ip->saddr) < 184549120 || htonl(ip->saddr) > 184549375) {
//        return XDP_PASS;
//    }


    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        u8 protocol;
        u32 src_port, dest_port;
        struct PACKET_INFO packet_info = {};

        if (ip->protocol == IPPROTO_TCP) {
            th = (struct tcphdr *) (ip + 1);
            if ((void *) (th + 1) > data_end) {
                return XDP_DROP;
            }
            statistic.increment(statistic_tcp);
            protocol = IPPROTO_TCP;
            packet_info.payload = data_end - (void *) (long) (th) - (th->doff << 2);
            src_port = th->source;
            dest_port = th->dest;
            packet_info.fin = th->fin;
            packet_info.syn = th->syn;
            packet_info.psh = th->psh;
            packet_info.rst = th->rst;
            packet_info.urg = th->urg;
            packet_info.win = htons(th->window);

        } else {
            uh = (struct udphdr *) (ip + 1);
            if ((void *) (uh + 1) > data_end) {
                return XDP_DROP;
            }
            statistic.increment(statistic_udp);
            protocol = IPPROTO_UDP;
            packet_info.payload = data_end - (void *) (long) (uh + 1);
            src_port = uh->source;
            dest_port = uh->dest;
        }

        struct FLOW_KEY flow_key = {};
        flow_key.protocol = protocol;
        flow_key.src = ip->saddr;
        flow_key.dest = ip->daddr;
        flow_key.src_port = src_port;
        flow_key.dest_port = dest_port;

        packet_info.flow_key = &flow_key;
        packet_info.current_time = bpf_ktime_get_ns() / 1000000;

        struct FLOW_FEATURE_NODE *flow = flow_table.lookup(&flow_key);
        if (flow == NULL) {
            if (protocol == IPPROTO_UDP || packet_info.syn == 1) addFirstPacket(&packet_info);
            return XDP_PASS;
        }

        if (packet_info.current_time - flow->flow_start_time > flow_timeout) {
            statistic.increment(statistic_flow_timeout);
            //analysis
            analysis(flow);
            flow_table.delete(&flow_key);
            //addFirstPacket
            if (packet_info.fin != 1 && packet_info.rst != 1) addFirstPacket(&packet_info);
            return XDP_PASS;
        }

        if (packet_info.fin == 1 || packet_info.rst == 1) {
            if (packet_info.fin == 1) statistic.increment(statistic_flow_fin);
            if (packet_info.rst == 1) statistic.increment(statistic_flow_rst);

            addPacket(&packet_info, flow);
            analysis(flow);
            flow_table.delete(&flow_key);
            return XDP_PASS;
        }
        addPacket(&packet_info, flow);
    }
    return XDP_PASS;
}


