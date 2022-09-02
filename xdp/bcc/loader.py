#!/usr/bin/python3

from bcc import BPF
import time

device = "wlp4s0b1"
b = BPF(src_file="program.c")
fn = b.load_func("my_program", BPF.XDP)
b.attach_xdp(device, fn, 0)
packet_cnt = b.get_table("packet_cnt")

prev = [0] * 256
print("Printing packet counts per IP protocol-number, hit CTRL+C to stop")
while 1:
    try:
        for k in packet_cnt.keys():
            val = packet_cnt.sum(k).value
            i = k.value
            if val:
                delta = val - prev[i]
                prev[i] = val
                print("{}: {} pkt/s".format(i, delta))
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break

b.remove_xdp(device, 0)
