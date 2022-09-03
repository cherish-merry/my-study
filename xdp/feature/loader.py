#!/usr/bin/python3

from bcc import BPF
import time


def addr2dec(addr):
    items = [int(x) for x in addr.split(".")]
    return sum([items[i] << [24, 16, 8, 0][i] for i in range(4)])


def dec2addr(dec):
    return ".".join([str(dec >> x & 0xff) for x in [0, 8, 16, 24]])


device = "enp3s0"
b = BPF(src_file="program.c")
fn = b.load_func("my_program", BPF.XDP)
b.attach_xdp(device, fn, 0)
packet_cnt = b.get_table("flow_table")
print("hit CTRL+C to stop")

while 1:
    try:
        count = 0
        for k, v in packet_cnt.items():
            print('({},{},{},{},{})'.format(k.protocolIdentifier, dec2addr(k.sourceIPAddress),
                                            dec2addr(k.destinationIPAddress), k.sourceTransportPort,
                                            k.destinationTransportPort))
            print('flow_start_time:{},flow_last_time:{}'.format(v.flow_start_time, v.flow_last_time))
            print('packet_num:{},fwd_packet_num:{},total_packet_length:{}'.format(v.packet_num, v.fwd_packet_num,
                                                                                  v.total_packet_length))
            print(
                'min_IAT:{},total_IAT:{},min_fwd_IAT:{},total_bak_IAT:{}'.format(v.min_IAT, v.total_IAT, v.min_fwd_IAT,
                                                                                 v.total_bak_IAT))
            print('active_start_time:{},active_end_time:{},min_active_time:{},total_active_time:{}'.format(
                v.active_start_time, v.active_end_time, v.min_active_time, v.total_active_time))
            count = count + 1
        print("count:", count)
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break

b.remove_xdp(device, 0)

'''
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
'''
