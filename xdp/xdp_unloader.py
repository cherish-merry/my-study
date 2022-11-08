#!/usr/bin/python3
from bcc import BPF
device = "enp5s0"
BPF.remove_xdp(device, 0)
