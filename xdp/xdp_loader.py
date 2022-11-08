#!/usr/bin/python3

from bcc import BPF
import time
import numpy as np


def addr2dec(addr):
    items = [int(x) for x in addr.split(".")]
    return sum([items[j] << [24, 16, 8, 0][j] for j in range(4)])


def dec2addr(dec):
    return ".".join([str(dec >> x & 0xff) for x in [0, 8, 16, 24]])


childrenLeft = np.fromfile("result/childLeft.bin", dtype=int)
childrenRight = np.fromfile("result/childrenRight.bin", dtype=int)
feature = np.fromfile("result/feature.bin", dtype=int)
threshold = np.fromfile("result/threshold.bin", dtype=int)
value = np.fromfile("result/value.bin", dtype=int)

decide_tree_map = "BPF_ARRAY(child_left, s32," + str(childrenLeft.shape[0]) + ");\n" + \
                  "BPF_ARRAY(child_right, s32," + str(childrenRight.shape[0]) + ");\n" + \
                  "BPF_ARRAY(feature, s32," + str(feature.shape[0]) + ");\n" + \
                  "BPF_ARRAY(threshold, u64," + str(threshold.shape[0]) + ");\n" + \
                  "BPF_ARRAY(value, u32," + str(value.shape[0]) + ");\n"

with open('xdp.c', 'r', encoding='utf-8') as f:
    program = f.read()
# print("device:")
# device = input()
device = "enp5s0"
b = BPF(text=decide_tree_map + program)

flow_table = b.get_table("flow_table")
exception_table = b.get_table("exception_table")
child_left_table = b.get_table("child_left")
child_right_table = b.get_table("child_right")
feature_table = b.get_table("feature")
threshold_table = b.get_table("threshold")
value_table = b.get_table("value")
statistic_table = b.get_table("statistic")

for i in range(childrenLeft.shape[0]):
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
                print("flow_end:", val)
            if i == 5:
                print("exception:", val)
        time.sleep(1)
        for k, v in exception_table.items():
            print(k, ":", v)
        print("----------------------------")

    except KeyboardInterrupt:
        print("Removing filter from device")
        break

b.remove_xdp(device, 0)
