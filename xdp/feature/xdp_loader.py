#!/usr/bin/python3

from bcc import BPF
import time
import numpy as np
import ctypes as ct


def addr2dec(addr):
    items = [int(x) for x in addr.split(".")]
    return sum([items[j] << [24, 16, 8, 0][j] for j in range(4)])


def dec2addr(dec):
    return ".".join([str(dec >> x & 0xff) for x in [0, 8, 16, 24]])


childrenLeft = np.fromfile("./result/childLeft.bin", dtype=int)
childrenRight = np.fromfile("./result/childrenRight.bin", dtype=int)
feature = np.fromfile("./result/feature.bin", dtype=int)
threshold = np.fromfile("./result/threshold.bin", dtype=int)
value = np.fromfile("./result/value.bin", dtype=int)

decide_tree_map = "BPF_ARRAY(child_left, s32," + str(childrenLeft.shape[0]) + ");\n" + \
                  "BPF_ARRAY(child_right, s32," + str(childrenRight.shape[0]) + ");\n" + \
                  "BPF_ARRAY(feature, s32," + str(feature.shape[0]) + ");\n" + \
                  "BPF_ARRAY(threshold, u64," + str(threshold.shape[0]) + ");\n" + \
                  "BPF_ARRAY(value, u32," + str(value.shape[0]) + ");\n"

with open('xdp.c', 'r', encoding='utf-8') as f:
    program = f.read()

device = "enp3s0"
#device = "wlp3s0b1"
# b = BPF(src_file="program.c")
b = BPF(text=decide_tree_map + program)

flow_table = b.get_table("flow_table")
exception_table = b.get_table("exception_table")
result_table = b.get_table("result_table")
child_left_table = b.get_table("child_left")
child_right_table = b.get_table("child_right")
feature_table = b.get_table("feature")
threshold_table = b.get_table("threshold")
value_table = b.get_table("value")
statistic_table = b.get_table("statistic")

for i in range(childrenLeft.shape[0]):
    # child_left_table[i] = ct.c_int32(childrenLeft[i])
    child_left_table[i] = child_left_table.Leaf(childrenLeft[i])

for i in range(childrenRight.shape[0]):
    child_right_table[i] = child_right_table.Leaf(childrenRight[i])

for i in range(feature.shape[0]):
    feature_table[i] = feature_table.Leaf(feature[i])

for i in range(threshold.shape[0]):
    threshold_table[i] = threshold_table.Leaf(threshold[i])

for i in range(value.shape[0]):
    value_table[i] = value_table.Leaf(value[i])

fn = b.load_func("my_program", BPF.XDP)
b.attach_xdp(device, fn, 0)

print("hit CTRL+C to stop")

# define statistic_packet_num  0
# define statistic_tcp  1
# define statistic_udp  2
# define statistic_flow  3
# define statistic_flow_timeout  4
# define statistic_flow_fin  5
# define statistic_flow_rst  6
# define statistic_exception  7

while 1:
    try:
        for k in statistic_table.keys():
            val = statistic_table.sum(k).value
            i = k.value
            if i == 0:
                print("packet_num:", val)
            if i == 1:
                print("tcp:", val)
            if i == 2:
                print("udp:", val)
            if i == 3:
                print("flow:", val)
            if i == 4:
                print("flow_timeout:", val)
            if i == 5:
                print("flow_fin:", val)
            if i == 6:
                print("flow_rst:", val)
            if i == 7:
                print("exception:", val)
        # for k, v in result_table.items():
        #     if dec2addr(k.sourceIPAddress) == "192.168.1.115":
        #         print('({},{},{},{},{})'.format(k.protocolIdentifier, dec2addr(k.sourceIPAddress),
        #                                         dec2addr(k.destinationIPAddress), k.sourceTransportPort,
        #                                         k.destinationTransportPort))
        #         print("Protocol:", k.protocolIdentifier)
        #         print("Flow Duration:", v.flowEndTime - v.flowStartTime)
        #         print("Total Fwd Packet:", v.packetNum)
        #         print("Total Length of Fwd Packet:", v.totalPacketLength)
        #         print("Fwd Packet Length Max:", v.maxPacketLength)
        #         print("Fwd Packet Length Min:", v.minPacketLength)
        #         print("Fwd Packet Length Mean:", v.totalPacketLength / v.packetNum)
        #         print("Fwd Packet Length Extreme Deviation:",
        #               100 * (v.maxPacketLength - v.minPacketLength) / (v.maxPacketLength + v.minPacketLength))
        #         if v.flowEndTime > v.flowStartTime:
        #             print("Flow Bytes/s:", v.totalPacketLength * 1000000 / (v.flowEndTime - v.flowStartTime))
        #             print("Flow Packets/s:", v.packetNum * 1000000 / (v.flowEndTime - v.flowStartTime))
        #         if v.packetNum > 1:
        #             print("Fwd IAT Mean:", v.totalIAT / (v.packetNum - 1))
        #         print("Fwd IAT Extreme Deviation:", 100 * (v.maxIAT - v.minIAT) / (v.maxIAT + v.minIAT))
        #         print("Fwd IAT Max:", v.maxIAT)
        #         print("Fwd IAT MIN:", v.minIAT)
        #         print("FIN Flag Count:", v.FIN)
        #         print("SYN Flag Count:", v.SYN)
        #         print("RST Count:", v.RST)
        #         print("PSH Flag Count:", v.PSH)
        #         print("ACK Flag Count:", v.ACK)
        #         print("URG Flag Count:", v.URG)
        #         print("CWR Flag Count:", v.CWR)
        #         print("ECE Flag Count:", v.ECE)
        #         print("FWD Init Win Bytes:", v.WIN)
        #         if v.activePackets != 0:
        #             print("Active Mean:", v.activeTotalTime / v.activePackets)
        #         print("Active Extreme Deviation:",
        #               100 * (v.maxActiveTime - v.minActiveTime) / (v.maxActiveTime + v.minActiveTime))
        #         print("Active Max:", v.maxActiveTime)
        #         print("Active MIN:", v.minActiveTime)
        #         if v.idlePackets != 0:
        #             print("Idle Mean:", v.idleTotalTime / v.idlePackets)
        #         if v.maxIdle + v.minIdle != 0:
        #             print("Idle Extreme Deviation:", 100 * (v.maxIdle - v.minIdle) / (v.maxIdle + v.minIdle))
        #         print("Idle Max:", v.maxIdle)
        #         print("Idle Min:", v.minIdle)
        #         print("End Way:", v.endWay)
        time.sleep(1)
        for k, v in exception_table.items():
            print(dec2addr(k.sourceIPAddress), ":", v)
        print("----------------------------")

    except KeyboardInterrupt:
        print("Removing filter from device")
        break

b.remove_xdp(device, 0)
