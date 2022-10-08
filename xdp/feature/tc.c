#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include "struct.h"

#define MAX_TREE_DEPTH  15
#define TREE_LEAF -1
#define FEATURE_VEC_LENGTH 16
#define flow_timeout  120000
#define activity_timeout  5000
#define statistic_packet_num  0
#define statistic_tcp  1
#define statistic_udp  2
#define statistic_flow  3
#define statistic_flow_timeout  4
#define statistic_flow_fin  5
#define statistic_flow_rst  6
#define statistic_exception  7

BPF_TABLE("lru_hash", struct FLOW_KEY,  struct FLOW_FEATURE_NODE, flow_table,  1000);
BPF_TABLE("lru_hash", struct FLOW_KEY,  struct FLOW_FEATURE_NODE, result_table,  1000);
BPF_TABLE("lru_hash", struct FLOW_KEY,  u32 , exception_table,  100);
BPF_PERCPU_ARRAY(statistic, u32,
8);

void static increase_packet_length(struct STATISTIC_PACKET_LENGTH *statistic, u32 d) {
    if (statistic->n == 0) {
        statistic->m1 = statistic->m2 = 0;
        statistic->max = d;
    }
    statistic->n++;
    statistic->sum += d;
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

void static increase_fwd_packet_length(struct STATISTIC_FWD_PACKET_LENGTH *statistic, u32 d) {
    if (statistic->n == 0) {
        statistic->m1 = statistic->m2 = 0;
        statistic->min = d;
    }
    statistic->n++;
    if (d < statistic->min) statistic->min = d;
    if (d > statistic->m1) {
        statistic->dev = d - statistic->m1;
        statistic->m1 += statistic->dev / statistic->n;
    } else {
        statistic->dev = statistic->m1 - d;
        statistic->m1 -= statistic->dev / statistic->n;
    }
    statistic->m2 += (statistic->n - 1) * statistic->dev * statistic->dev / statistic->n;
}

void static increase_back_packet_length(struct STATISTIC_BACK_PACKET_LENGTH *statistic, u32 d) {
    if (statistic->n == 0) {
        statistic->m1 = statistic->m2 = 0;
    }
    statistic->n++;
    statistic->sum += d;
    if (d > statistic->m1) {
        statistic->dev = d - statistic->m1;
        statistic->m1 += statistic->dev / statistic->n;
    } else {
        statistic->dev = statistic->m1 - d;
        statistic->m1 -= statistic->dev / statistic->n;
    }
    statistic->m2 += (statistic->n - 1) * statistic->dev * statistic->dev / statistic->n;
}

void static increase_flow_iat(struct STATISTIC_FLOW_IAT *statistic, u32 d) {
    statistic->n++;
    statistic->sum += d;
}

void static increase_fwd_iat(struct STATISTIC_FWD_IAT *statistic, u32 d) {
    if (statistic->n == 0) {
        statistic->m1 = statistic->m2 = 0;
    }
    statistic->n++;
    if (d > statistic->m1) {
        statistic->dev = d - statistic->m1;
        statistic->m1 += statistic->dev / statistic->n;
    } else {
        statistic->dev = statistic->m1 - d;
        statistic->m1 -= statistic->dev / statistic->n;
    }
    statistic->m2 += (statistic->n - 1) * statistic->dev * statistic->dev / statistic->n;
}

void static increase_back_iat(struct STATISTIC_BACK_IAT *statistic, u32 d) {
    if (statistic->n == 0) {
        statistic->max = d;
    }
    statistic->n++;
    statistic->sum += d;
    if (d > statistic->max) statistic->max = d;
}

void static increase_active(struct STATISTIC_ACTIVE *statistic, u32 d) {
    if (statistic->n == 0) {
        statistic->max;
    }
    statistic->n++;
    if (d > statistic->max) statistic->max = d;
}

void static increase_idle(struct STATISTIC_IDLE *statistic, u32 d) {
    if (statistic->n == 0) {
        statistic->max;
    }
    statistic->n++;
    if (d > statistic->max) statistic->max = d;
}

void static updateActiveIdleTime(u32 *current_time, struct FLOW_FEATURE_NODE *flow) {
    if (*current_time - flow->flow_end_time > activity_timeout) {
        if (flow->active_end_time - flow->active_start_time > 0)
            increase_active(&flow->active, flow->active_end_time - flow->active_start_time);
        increase_idle(&flow->idle, *current_time - flow->active_end_time);
        flow->active_start_time = flow->active_end_time = *current_time;
    } else {
        flow->active_end_time = *current_time;
    }
}

void static endActiveIdleTime(u32 *current_time, struct FLOW_FEATURE_NODE *flow) {
    if (flow->active_end_time - flow->active_start_time > 0)
        increase_active(&flow->active, flow->active_end_time - flow->active_start_time);
    if (*current_time - flow->active_end_time > activity_timeout) {
        increase_idle(&flow->idle, *current_time - flow->active_end_time);
        flow->active_start_time = flow->active_end_time = *current_time;
    }
}

//void static checkFlag(struct FLOW_FEATURE_NODE *node, struct PACKET_INFO *packet_info) {
//    node->rst += packet_info->rst;
//}

void static addFirstPacket(struct PACKET_INFO *packet_info) {
    statistic.increment(statistic_flow);
    struct FLOW_FEATURE_NODE zero = {};
//    checkFlag(&zero, packet_info);
    zero.flow_start_time = zero.flow_end_time = zero.active_start_time = zero.active_end_time = packet_info->current_time;
    increase_packet_length(&zero.packet_length, packet_info->payload);
    zero.src = packet_info->flow_key->src;
    zero.fwd_win = packet_info->win;
    increase_fwd_packet_length(&zero.fwd_packet_length, packet_info->payload);
    zero.fwd_flow_end_time = packet_info->current_time;
    flow_table.insert(packet_info->flow_key, &zero);
}

void static addPacket(struct PACKET_INFO *packet_info, struct FLOW_FEATURE_NODE *flow) {
//    checkFlag(flow, packet_info);
    increase_packet_length(&flow->packet_length, packet_info->payload);
    increase_flow_iat(&flow->iat, packet_info->current_time - flow->flow_end_time);
    flow->flow_end_time = packet_info->current_time;
    if (packet_info->flow_key->src == flow->src) {
        increase_fwd_packet_length(&flow->fwd_packet_length, packet_info->payload);
        if (flow->fwd_flow_end_time != 0) {
            increase_fwd_iat(&flow->fwd_iat, packet_info->current_time - flow->fwd_flow_end_time);
        }
        flow->fwd_flow_end_time = packet_info->current_time;
    } else {
        increase_back_packet_length(&flow->back_packet_length, packet_info->payload);
        if (flow->back_flow_end_time != 0) {
            increase_back_iat(&flow->back_iat, packet_info->current_time - flow->back_flow_end_time);
        } else flow->back_win = packet_info->win;
        flow->back_flow_end_time = packet_info->current_time;
    }
}

u32 static analysis(struct FLOW_FEATURE_NODE *flow) {
    u32 feature_vec[FEATURE_VEC_LENGTH];
    feature_vec[0] = flow->fwd_packet_length.n;
    feature_vec[1] = flow->back_packet_length.n;
    feature_vec[2] = flow->fwd_packet_length.min;
    if (flow->fwd_packet_length.n < 2) feature_vec[3] = 0;
    else feature_vec[3] = flow->fwd_packet_length.m2 / (flow->fwd_packet_length.n - 1);
    feature_vec[4] = flow->back_packet_length.sum / flow->back_packet_length.n;
    if (flow->back_packet_length.n < 2) feature_vec[5] = 0;
    else feature_vec[5] = flow->back_packet_length.m2 / (flow->back_packet_length.n - 1);
    feature_vec[6] = flow->packet_length.n * 1000 / (flow->flow_end_time - flow->flow_start_time);
    feature_vec[7] = flow->iat.sum / flow->iat.n;
    if (flow->fwd_iat.n < 2) feature_vec[8] = 0;
    else feature_vec[8] = flow->fwd_iat.m2 / (flow->fwd_iat.n - 1);
    feature_vec[9] = flow->back_iat.sum / flow->back_iat.n;
    feature_vec[10] = flow->back_iat.max;
    feature_vec[11] = flow->packet_length.max;
    feature_vec[12] = flow->packet_length.sum / flow->packet_length.n;
    if (flow->packet_length.n < 2) feature_vec[13] = 0;
    else feature_vec[13] = flow->packet_length.m2 / (flow->packet_length.n - 1);
    feature_vec[14] = flow->active.max;
    feature_vec[15] = flow->idle.max;

//    for(int i = 0; i < 16; i++){
//        bpf_trace_printk("%u:%u",i,feature_vec[i]);
//    }



    u32 current_node = 0;
    for (int i = 0; i < MAX_TREE_DEPTH; i++) {
        s32 *left_val = child_left.lookup(&current_node);
        s32 *right_val = child_right.lookup(&current_node);
        s32 *feature_val = feature.lookup(&current_node);
        u32 * threshold_val = threshold.lookup(&current_node);
        if (left_val == NULL || right_val == NULL || feature_val == NULL ||
            threshold_val == NULL || *left_val == TREE_LEAF ||
            *feature_val > sizeof(feature_vec) / sizeof(feature_vec[0]) || *feature_val >= FEATURE_VEC_LENGTH) {
            break;
        }
        u32 a = feature_vec[*feature_val];
        if (a <= *threshold_val) current_node = *left_val;
        else current_node = *right_val;
        bpf_trace_printk("feature_val:%u,threshold_val:%lu,feature_vec:%lu", *feature_val, *threshold_val, a);
    }
    u32 * value_val = value.lookup(&current_node);
    u32 * impurity_val = impurity.lookup(&current_node);
    if (value_val == NULL || impurity_val == NULL || *impurity_val >= 10) return 0;
    if (*value_val == 1) bpf_trace_printk("Attack");
    bpf_trace_printk("--------------------------------------------------");
    return *value_val;
}

int my_program(struct __sk_buff *skb) {
    u8 *cursor = 0;
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));

    statistic.increment(statistic_packet_num);

//    if (ip->src != 3232235891 && ip->dst != 3232235891) return 0;

    if (ip->nextp == IPPROTO_TCP || ip->nextp == IPPROTO_UDP) {
        if (ip->nextp == IPPROTO_TCP) statistic.increment(statistic_tcp);
        else statistic.increment(statistic_udp);

        struct FLOW_KEY fwd_flow_key = {};
        struct FLOW_KEY back_flow_key = {};
        struct PACKET_INFO packet_info = {};
        fwd_flow_key.src = ip->src;
        fwd_flow_key.dest = ip->dst;
        back_flow_key.src = ip->dst;
        back_flow_key.dest = ip->src;

        if (ip->nextp == IPPROTO_TCP) {
            struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));
            fwd_flow_key.protocol = back_flow_key.protocol = IPPROTO_TCP;
            fwd_flow_key.src_port = back_flow_key.dest_port = tcp->src_port;
            fwd_flow_key.dest_port = back_flow_key.src_port = tcp->dst_port;
            packet_info.payload = ip->tlen - (ip->hlen << 2) - (tcp->offset << 2);
            packet_info.fin = tcp->flag_fin;
            packet_info.rst = tcp->flag_rst;
            packet_info.syn = tcp->flag_syn;
            packet_info.win = tcp->rcv_wnd;
        } else {
            struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));
            fwd_flow_key.protocol = back_flow_key.protocol = IPPROTO_UDP;
            fwd_flow_key.src_port = back_flow_key.dest_port = udp->sport;
            fwd_flow_key.dest_port = back_flow_key.src_port = udp->dport;
            packet_info.payload = udp->length - 8;
        }

        struct FLOW_FEATURE_NODE *fwd_node = flow_table.lookup(&fwd_flow_key);
        struct FLOW_FEATURE_NODE *back_node = flow_table.lookup(&back_flow_key);

        packet_info.current_time = bpf_ktime_get_ns() / 1000000;
        packet_info.flow_key = &fwd_flow_key;

        if (fwd_node == back_node) {
            if (packet_info.syn == 1 || ip->nextp == IPPROTO_UDP) addFirstPacket(&packet_info);
            return 0;
        }

        struct FLOW_FEATURE_NODE *flow = fwd_node == NULL ? back_node : fwd_node;

        if (flow == NULL) return 0;

        if (packet_info.current_time - flow->flow_start_time > flow_timeout || packet_info.rst == 1) {
            if (packet_info.rst == 1) {
                addPacket(&packet_info, flow);
                statistic.increment(statistic_flow_rst);
            }
            endActiveIdleTime(&packet_info.current_time, flow);
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
                if (packet_info.fin != 1 && packet_info.rst != 1) addFirstPacket(&packet_info);
            }
            return 0;
        }

        if (packet_info.fin == 1) {
            if (fwd_flow_key.src == flow->src) {
                flow->fwd_fin = 1;
            } else flow->back_fin = 1;
            if (flow->fwd_fin + flow->back_fin == 2) {
                addPacket(&packet_info, flow);
                endActiveIdleTime(&packet_info.current_time, flow);
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
                updateActiveIdleTime(&packet_info.current_time, flow);
                addPacket(&packet_info, flow);
            }
            return 0;
        }
        updateActiveIdleTime(&packet_info.current_time, flow);
        addPacket(&packet_info, flow);
    }
    return 0;
}