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
            print('flowStartTime:{},flowEndTime:{}'.format(v.flowStartTime, v.flowEndTime))
            print('packetNum:{},minPacketLength:{},maxPacketLength:{},totalPacketLength:{}'.
                  format(v.packetNum, v.minPacketLength, v.maxPacketLength, v.totalPacketLength))
            print('minIAT:{},maxIAT:{},totalIAT:{}'.format(v.minIAT, v.maxIAT, v.totalIAT))
            print('activeStartTime:{},activeEndTime:{},minActiveTime:{},maxActiveTime:{},totalActiveTime:{}'.
                  format(v.activeStartTime, v.activeEndTime, v.minActiveTime, v.maxActiveTime, v.totalActiveTime))
            count = count + 1
        print("count:", count)
        time.sleep(30)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break

b.remove_xdp(device, 0)
