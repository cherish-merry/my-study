// #define KBUILD_MODNAME "program"
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>

/*
BPF_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries)
BPF_HASH(name, key_type=u64, leaf_type=u64, size=10240)
BPF_ARRAY(name, leaf_type=u64, size=10240)
BPF_PERCPU_HASH(name, key_type=u64, leaf_type=u64, size=10240)
BPF_PERCPU_ARRAY(name, leaf_type=u64, size=10240)
 *
 * */


//BPF_TABLE("percpu_array", uint32_t, long, packet_cnt, 256);


BPF_PERCPU_ARRAY(packet_cnt, long , 256);


int my_program(struct xdp_md *ctx) {
    void *data = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    long *cnt;
    __u32 idx;

    ip = data + sizeof(*eth);

    if (data + sizeof(*eth) + sizeof(struct iphdr) > data_end) {
        return XDP_DROP;
    }

    idx = ip->protocol;
    cnt = packet_cnt.lookup(&idx);
    if (cnt) {
        *cnt += 1;
    }

    if (ip->protocol == IPPROTO_TCP) {
        return XDP_DROP;
    }

    return XDP_PASS;
}
