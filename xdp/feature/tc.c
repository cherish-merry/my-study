#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/ip.h>

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define MAX_TREE_DEPTH  24
#define TREE_LEAF -1
#define FEATURE_VEC_LENGTH 20

#define flow_timeout  120000000
#define activity_timeout  6000000

#define statistic_packet_num  0
#define statistic_tcp  1
#define statistic_udp  2
#define statistic_flow  3
#define statistic_flow_timeout  4
#define statistic_flow_fin  5
#define statistic_flow_rst  6
#define statistic_exception  7

struct FLOW_KEY {
    u8 protocol;
    u8 padding_8;
    u16 padding_16;
    u32 src;
    u32 dest;
    u32 src_port;
    u32 dest_port;
};

struct FLOW_FEATURE_NODE {
    // 标记源地址
    u32 src;

    //global
    u8 protocol;

    u8 fwd_fin;

    u8 back_fin;

    u64 flow_start_time;

    u64 flow_end_time;

    u32 packet_length;

    u32 packet_num;

    u32 min_packet_length;

    u32 max_packet_length;

    u8 fin;

    u8 syn;

    u8 rst;

    u8 psh;

    u8 ack;

    u8 urg;

    u8 cwr;

    u8 ece;

    u64 total_iat;

    u64 max_iat;

    u64 min_iat;

    u32 active_times;

    u32 idle_times;

    u64 active_start_time;

    u64 active_end_time;

    u64 max_active;

    u64 min_active;

    u64 total_active;

    u64 max_idle;

    u64 min_idle;

    u64 total_idle;


    //fwd
    u32 fwd_packet_length;

    u32 fwd_packet_num;

    u32 fwd_min_packet_length;

    u32 fwd_max_packet_length;

    u64 fwd_total_iat;

    u64 fwd_max_iat;

    u64 fwd_min_iat;

    u16 fwd_win;

    u64 fwd_flow_end_time;


    //back
    u32 back_packet_length;

    u32 back_packet_num;

    u32 back_min_packet_length;

    u32 back_max_packet_length;

    u64 back_total_iat;

    u64 back_max_iat;

    u64 back_min_iat;

    u16 back_win;

    u64 back_flow_end_time;
};

struct PACKET_INFO {
    struct FLOW_KEY *flow_key;
    u32 payload;
    u8 fin, syn, rst, psh, ack, urg, cwr, ece;
    u16 win;
    u64 current_time;
};

BPF_TABLE("lru_hash", struct FLOW_KEY,  struct FLOW_FEATURE_NODE, flow_table,  1000);
BPF_TABLE("lru_hash", struct FLOW_KEY,  struct FLOW_FEATURE_NODE, result_table,  1000);
BPF_TABLE("lru_hash", struct FLOW_KEY,  u32 , exception_table,  100);
BPF_PERCPU_ARRAY(statistic, u32,
8);
BPF_ARRAY(feature_vec, u64,
FEATURE_VEC_LENGTH);

void static updateActiveIdleTime(u64 current_time, struct FLOW_FEATURE_NODE *flow) {
    if (current_time - flow->flow_end_time > activity_timeout) {
        if (flow->active_end_time - flow->active_start_time > 0) {
            u64 active_iat = flow->active_end_time - flow->active_start_time;
            flow->total_active += active_iat;
            flow->active_times++;
            if (flow->active_times == 1) {
                flow->min_active = flow->max_active = active_iat;
            } else {
                if (active_iat < flow->min_active) flow->min_active = active_iat;
                if (active_iat > flow->max_active) flow->max_active = active_iat;
            }
        }

        u64 idle_iat = current_time - flow->active_end_time;
        flow->total_idle += idle_iat;
        flow->idle_times++;

        if (flow->idle_times == 1) {
            flow->min_idle = flow->max_idle = idle_iat;
        } else {
            if (idle_iat < flow->min_idle) flow->min_idle = idle_iat;
            if (idle_iat > flow->max_idle) flow->max_idle = idle_iat;
        }
        flow->active_start_time = flow->active_end_time = current_time;
    } else {
        flow->active_end_time = current_time;
    }
}

void static checkFlag(struct FLOW_FEATURE_NODE *node, struct PACKET_INFO *packet_info) {
    node->fin += packet_info->fin;
    node->syn += packet_info->syn;
    node->rst += packet_info->rst;
    node->psh += packet_info->psh;
    node->ack += packet_info->ack;
    node->urg += packet_info->urg;
    node->cwr += packet_info->cwr;
    node->ece += packet_info->ece;
}

void static addFirstPacket(struct PACKET_INFO *packet_info) {
    statistic.increment(statistic_flow);

    struct FLOW_FEATURE_NODE zero = {};
    zero.protocol = packet_info->flow_key->protocol;


    checkFlag(&zero, packet_info);
    zero.flow_start_time = zero.flow_end_time = zero.active_start_time = zero.active_end_time = packet_info->current_time;


    zero.packet_num = 1;
    zero.min_packet_length = zero.max_packet_length = zero.packet_length = packet_info->payload;


    zero.src = packet_info->flow_key->src;
    zero.fwd_win = packet_info->win;
    zero.fwd_packet_num = 1;
    zero.fwd_min_packet_length = zero.fwd_max_packet_length = zero.fwd_packet_length = packet_info->payload;
    zero.fwd_flow_end_time = packet_info->current_time;

    flow_table.insert(packet_info->flow_key, &zero);
}

void static addPacket(struct PACKET_INFO *packet_info, struct FLOW_FEATURE_NODE *flow) {
    checkFlag(flow, packet_info);
    flow->packet_num++;
    flow->packet_length += packet_info->payload;
    if (packet_info->payload < flow->min_packet_length) flow->min_packet_length = packet_info->payload;
    if (packet_info->payload > flow->max_packet_length) flow->max_packet_length = packet_info->payload;

    u64 iat = packet_info->current_time - flow->flow_end_time;
    flow->total_iat += iat;

    if (flow->packet_num == 2) flow->min_iat = iat;
    else if (iat < flow->min_iat) flow->min_iat = iat;

    if (flow->packet_num == 2) flow->max_iat = iat;
    else if (iat > flow->max_iat) flow->max_iat = iat;

    flow->flow_end_time = packet_info->current_time;


    if (packet_info->flow_key->src == flow->src) {
        flow->fwd_packet_num++;
        flow->fwd_packet_length += packet_info->payload;

        if (packet_info->payload < flow->fwd_min_packet_length) flow->fwd_min_packet_length = packet_info->payload;
        if (packet_info->payload > flow->fwd_max_packet_length) flow->fwd_max_packet_length = packet_info->payload;

        if (flow->fwd_flow_end_time != 0) {
            u64 iat = packet_info->current_time - flow->fwd_flow_end_time;
            flow->fwd_total_iat += iat;

            if (flow->fwd_packet_num == 2) flow->fwd_min_iat = iat;
            else if (iat < flow->fwd_min_iat) flow->fwd_min_iat = iat;

            if (flow->fwd_packet_num == 2) flow->fwd_max_iat = iat;
            else if (iat > flow->fwd_max_iat) flow->fwd_max_iat = iat;
        }
        flow->fwd_flow_end_time = packet_info->current_time;
    } else {
        flow->back_packet_num++;
        if (flow->back_packet_num == 1) {
            flow->back_win = packet_info->win;
            flow->fwd_min_packet_length = flow->fwd_max_packet_length = flow->fwd_packet_length = packet_info->payload;
        } else {
            flow->back_packet_length += packet_info->payload;
            if (packet_info->payload < flow->back_min_packet_length)
                flow->back_min_packet_length = packet_info->payload;
            if (packet_info->payload > flow->back_max_packet_length)
                flow->back_max_packet_length = packet_info->payload;
        }

        if (flow->back_flow_end_time != 0) {
            u64 iat = packet_info->current_time - flow->back_flow_end_time;
            flow->back_total_iat += iat;

            if (flow->back_packet_num == 2) flow->back_min_iat = iat;
            else if (iat < flow->back_min_iat) flow->back_min_iat = iat;

            if (flow->back_packet_num == 2) flow->back_max_iat = iat;
            else if (iat > flow->back_max_iat) flow->back_max_iat = iat;
        }
        flow->back_flow_end_time = packet_info->current_time;
    }
}


u32 static analysis(struct FLOW_FEATURE_NODE *flow);


int my_program(struct __sk_buff *skb) {
    u8 *cursor = 0;
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    statistic.increment(statistic_packet_num);

    if (ip->src != 3232235891 && ip->dst != 3232235891) return 0;


    if (ip->nextp == IPPROTO_TCP || ip->nextp == IPPROTO_UDP) {
        if (ip->nextp == IPPROTO_TCP) statistic.increment(statistic_tcp);
        else statistic.increment(statistic_udp);

        u8 protocol;
        u32 src_port, dest_port;
        struct PACKET_INFO packet_info = {};
        if (ip->nextp == IPPROTO_TCP) {
            struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));
            protocol = IPPROTO_TCP;
            packet_info.payload = ip->tlen - (ip->hlen << 2) - (tcp->offset << 2);
            src_port = tcp->src_port;
            dest_port = tcp->dst_port;
            packet_info.fin = tcp->flag_fin;
            packet_info.syn = tcp->flag_syn;
            packet_info.psh = tcp->flag_psh;
            packet_info.rst = tcp->flag_rst;
            packet_info.ack = tcp->flag_ack;
            packet_info.urg = tcp->flag_urg;
            packet_info.cwr = tcp->flag_cwr;
            packet_info.ece = tcp->flag_ece;
            packet_info.win = tcp->rcv_wnd;
        } else {
            struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));
            protocol = IPPROTO_UDP;
            packet_info.payload = udp->length - 8;
//            if (ip->src == 3232235891) bpf_trace_printk("payload:%u", packet_info.payload);
            src_port = udp->sport;
            dest_port = udp->dport;
        }


        struct FLOW_KEY fwd_flow_key = {0, 0, 0, 0, 0, 0, 0};
        fwd_flow_key.protocol = protocol;
        fwd_flow_key.src = ip->src;
        fwd_flow_key.dest = ip->dst;
        fwd_flow_key.src_port = src_port;
        fwd_flow_key.dest_port = dest_port;
        struct FLOW_FEATURE_NODE *fwd_node = flow_table.lookup(&fwd_flow_key);


        struct FLOW_KEY back_flow_key = {0, 0, 0, 0, 0, 0, 0};
        back_flow_key.protocol = protocol;
        back_flow_key.src = ip->dst;
        back_flow_key.dest = ip->src;
        back_flow_key.src_port = dest_port;
        back_flow_key.dest_port = src_port;
        struct FLOW_FEATURE_NODE *back_node = flow_table.lookup(&back_flow_key);

        packet_info.current_time = bpf_ktime_get_ns() / 1000;

        if (fwd_node == back_node) {
            packet_info.flow_key = &fwd_flow_key;
            addFirstPacket(&packet_info);
            return 0;
        }

        packet_info.flow_key = &fwd_flow_key;


        struct FLOW_FEATURE_NODE *flow = fwd_node == NULL ? back_node : fwd_node;

        if (flow == NULL) return 0;

        if (packet_info.current_time - flow->flow_start_time > flow_timeout || packet_info.rst == 1) {
            if (packet_info.rst == 1) {
                addPacket(&packet_info, flow);
                statistic.increment(statistic_flow_rst);
            }
            if (analysis(flow) == 1) {
                statistic.increment(statistic_exception);
                u32 one = 1;
                u32 * val = exception_table.lookup(packet_info.flow_key);
                if (val) {
                    *val += 1;
                } else exception_table.insert(packet_info.flow_key, &one);
            }
            flow_table.delete(packet_info.flow_key);
            if (packet_info.current_time - flow->flow_start_time > flow_timeout) {
                statistic.increment(statistic_flow_timeout);
                addFirstPacket(&packet_info);
            }
            return 0;
        }

        if (packet_info.fin == 1) {
            if (fwd_flow_key.src == flow->src) {
                flow->fwd_fin = 1;
            } else flow->back_fin = 1;

            if (flow->fwd_fin + flow->back_fin == 2) {
                addPacket(&packet_info, flow);
                if (analysis(flow) == 1) {
                    statistic.increment(statistic_exception);
                    u32 one = 1;
                    u32 * val = exception_table.lookup(packet_info.flow_key);
                    if (val) {
                        *val += 1;
                    } else exception_table.insert(packet_info.flow_key, &one);
                }
                statistic.increment(statistic_flow_fin);
                flow_table.delete(packet_info.flow_key);
            } else {
                updateActiveIdleTime(packet_info.current_time, flow);
                addPacket(&packet_info, flow);
            }
            return 0;
        }


        if (flow->back_fin == 0) {
            updateActiveIdleTime(packet_info.current_time, flow);
            addPacket(&packet_info, flow);
        }
    }
    return 0;
}

u32 static analysis(struct FLOW_FEATURE_NODE *flow) {
    u64 feature_vec[FEATURE_VEC_LENGTH];
    bpf_trace_printk("duration:%llu", flow->flow_end_time - flow->flow_start_time);

    feature_vec[0] = flow->packet_length / flow->packet_num;
    bpf_trace_printk("mean_packet_length:%llu", feature_vec[0]);

    feature_vec[1] = (u64)
    flow->packet_length * 1000000 / (u64)(flow->flow_end_time - flow->flow_start_time);
    bpf_trace_printk("Flow Bytes/s:%llu", feature_vec[1]);

    feature_vec[2] = flow->urg;
    bpf_trace_printk("URG Flag Count:%llu", feature_vec[2]);

    feature_vec[3] = flow->syn;
    bpf_trace_printk("SYN Flag Count:%llu", feature_vec[3]);

    feature_vec[4] = flow->min_iat;
    bpf_trace_printk("Flow IAT Min:%llu", feature_vec[4]);

    feature_vec[5] = flow->total_iat / (flow->packet_num - 1);
    bpf_trace_printk("Flow IAT Mean:%llu", feature_vec[5]);

    feature_vec[6] = flow->total_active / flow->active_times;
    bpf_trace_printk("Active Mean:%llu", feature_vec[6]);

    feature_vec[7] = flow->max_idle;
    bpf_trace_printk("Idle Max:%llu", feature_vec[7]);

    feature_vec[8] = flow->fwd_packet_length;
    bpf_trace_printk("Total Length of Fwd Packets:%llu", feature_vec[8]);

    feature_vec[9] = flow->fwd_packet_num;
    bpf_trace_printk("Total Fwd Packets:%llu", feature_vec[9]);

    feature_vec[10] = flow->fwd_max_packet_length;
    bpf_trace_printk("Fwd Packet Length Max:%llu", feature_vec[10]);

    feature_vec[11] = flow->fwd_min_packet_length;
    bpf_trace_printk("Fwd Packet Length Min:%llu", feature_vec[11]);

    feature_vec[12] = flow->fwd_total_iat;
    bpf_trace_printk("Fwd IAT Total:%llu", feature_vec[12]);

    feature_vec[13] = flow->fwd_win;
    bpf_trace_printk("Init_Win_bytes_forward:%llu", feature_vec[13]);


    feature_vec[14] = flow->back_packet_length;
    bpf_trace_printk("Total Length of Bwd Packets:%llu", feature_vec[14]);

    feature_vec[15] = flow->back_packet_num;
    bpf_trace_printk("Total Backward Packets:%llu", feature_vec[15]);

    feature_vec[16] = flow->back_packet_length / flow->back_packet_num;
    bpf_trace_printk("Bwd Packet Length Mean:%llu", feature_vec[16]);

    feature_vec[17] = (u64)
    flow->back_packet_num * 1000000 / (u64)(flow->flow_end_time - flow->flow_start_time);
    bpf_trace_printk("Bwd Packets/s:%llu", feature_vec[17]);

    feature_vec[18] = flow->back_min_iat;
    bpf_trace_printk("Bwd IAT Min:%llu", feature_vec[18]);

    feature_vec[19] = flow->back_win;
    bpf_trace_printk("Init_Win_bytes_backward:%llu", feature_vec[19]);

    u32 current_node = 0;
    for (int i = 0; i < MAX_TREE_DEPTH; i++) {
        s32 *left_val = child_left.lookup(&current_node);
        s32 *right_val = child_right.lookup(&current_node);
        s32 *feature_val = feature.lookup(&current_node);
        u64 * threshold_val = threshold.lookup(&current_node);
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