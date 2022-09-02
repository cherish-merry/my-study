from scapy.all import Ether, IP, raw, TCP, UDP
from scapy.utils import PcapReader, rdpcap


def read_pcap():
    packets = rdpcap("dump.pcap")
    for data in packets:
        print(repr(data))


def hello_scapy():
    data = "Hello Scapy"
    pkt = Ether() / IP() / UDP() / data
    print(pkt)


if __name__ == '__main__':
    read_pcap()
