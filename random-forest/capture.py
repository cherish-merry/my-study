import scapy.all as scapy
from sklearn.ensemble import RandomForestClassifier
import joblib
from utils import binary_process
from sklearn.model_selection import train_test_split

loaded_model = joblib.load('random_forest_model.pkl')

columns, x, y = binary_process(None, 100)
train_x, test_x, train_y, test_y = train_test_split(x, y, test_size=0.2, random_state=0)


# 定义一个回调函数，处理每个捕获到的数据包
def packet_callback(packet):
    # 打印数据包摘要信息
    # print(packet.summary())
    y_pred = loaded_model.predict(test_x.sample(n=1))
    print(y_pred)


# 开始捕获所有数据包
scapy.sniff(prn=packet_callback, store=0)
