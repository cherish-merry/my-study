import pandas as pd
import numpy as np
from sklearn import tree
import graphviz
from bcc.utils import printb

# sudo cat /sys/kernel/debug/tracing/trace_pipe
'''
version1.0
duration packetNum
minPacketLength maxPacketLength meanPacketLength totalPacketLength
minIAT maxIAT meanIAT  totalIAT
minActiveTime maxActiveTime

[7, 8, 10, 12, 13, 14, 22, 24, 25, 26, 77, 78, 83]

version2.0
duration  packetNum  totalPacketLength
maxPacketLength minPacketLength meanPacketLength
flow bytes/s  flow packets/s
meanIAT maxIAT minIAT
FIN SYN RST PSH ACK 
Init Win Bytes
meanActive maxActive minActive
meanIdle maxIdle minIdle

[7, 8, 10, 12, 13, 14, 20, 21, 22, 24, 25, 49, 50, 51, 52, 53, 71, 75, 77, 78, 79, 81, 82]
'''


def label(s):
    if s == "Normal":
        return 0
    else:
        return 1


if __name__ == '__main__':
    # np.set_printoptions(threshold=np.inf)
    # pd.set_option('display.max_columns', None)  # 显示完整的列
    # pd.set_option('display.max_rows', None)  # 显示完整的行

    data = pd.read_csv("wednesday.pcap_Flow.csv",
                       converters={"Label": label},
                       usecols=[7, 8, 10, 12, 13, 14, 20, 21, 22, 24, 25, 49, 50, 51, 52, 53, 71, 75, 77, 78, 79, 81,
                                82, 83])

    columns = np.array(data.columns)

    print(columns)

    array = np.array(data)

    array[np.isnan(array)] = 0

    array[np.isinf(array)] = 0

    x = array[:, :array.shape[1] - 1]
    y = array[:, array.shape[1] - 1]

    class_names = ["Normal", "Exception"]

    clf = tree.DecisionTreeClassifier(max_depth=24, max_leaf_nodes=1024)
    clf = clf.fit(x, y)

    clf.tree_.children_left.tofile("../xdp/feature/result/childLeft.bin")
    clf.tree_.children_right.tofile("../xdp/feature/result/childrenRight.bin")
    clf.tree_.feature.tofile("../xdp/feature/result/feature.bin")
    clf.tree_.threshold.astype(int).tofile("../xdp/feature/result/threshold.bin")
    value = []
    values = clf.tree_.value
    for val in values:
        value.append(np.argmax(val))
    np.array(value).tofile("../xdp/feature/result/value.bin")

    print(np.fromfile("../xdp/feature/result/childLeft.bin", dtype=int))
    print(np.fromfile("../xdp/feature/result/childrenRight.bin", dtype=int))
    print(np.fromfile("../xdp/feature/result/feature.bin", dtype=int))
    print(np.fromfile("../xdp/feature/result/threshold.bin", dtype=int))
    print(np.fromfile("../xdp/feature/result/value.bin", dtype=int))

    dot_data = tree.export_graphviz(clf, out_file=None,
                                    feature_names=columns[:columns.shape[0] - 1],
                                    class_names=class_names,
                                    filled=True, rounded=True,
                                    special_characters=True)
    graph = graphviz.Source(dot_data)
    graph.render("../xdp/feature/result/decide_tree")
