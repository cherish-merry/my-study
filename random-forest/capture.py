import scapy.all as scapy
import joblib

from utils import binary_process
from scapy.all import *
from scapy.layers.inet import *
from sklearn.model_selection import train_test_split
import numpy as np

columns, x, y = binary_process(None, 100)

loaded_model = joblib.load('random_forest_model.pkl')




# 存储五元组和开始时间的字典
flow_dict = {}


# 定义回调函数来处理捕获到的每个数据包
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flow_key = (src_ip, src_port, dst_ip, dst_port, proto)

            if flow_key in flow_dict:
                # 获取当前时间
                current_time = time.time()
                start_time = flow_dict[flow_key]
                elapsed_time = current_time - start_time

                if elapsed_time >= 15:
                    # 执行移除操作
                    print(f"Removing flow: {flow_key}")
                    prediction = loaded_model.predict(x.iloc[np.random.choice(x.shape[0], size=1, replace=False)])
                    print("Prediction:", prediction)
                    del flow_dict[flow_key]


            else:
                # 添加新的流到字典中
                flow_dict[flow_key] = time.time()
                # 打印添加的流信息
                print(f"Adding flow: {flow_key}")


# 使用sniff函数捕获网络流量，并调用回调函数进行处理
sniff(prn=packet_callback, filter="ip")
