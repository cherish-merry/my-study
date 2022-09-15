import pandas as pd
import numpy as np
from sklearn import tree
import graphviz
import sys
from sklearn.metrics import accuracy_score

# sudo cat /sys/kernel/debug/tracing/trace_pipe
'''
version1.0
duration packetNum
minPacketLength maxPacketLength meanPacketLength totalPacketLength
minIAT maxIAT meanIAT  totalIAT
minActiveTime maxActiveTime

[7, 8, 10, 12, 13, 14, 22, 24, 25, 26, 77, 78, 83]

version2.0
protocol
duration  packetNum  totalPacketLength
maxPacketLength minPacketLength meanPacketLength
flow bytes/s  flow packets/s
meanIAT maxIAT minIAT
FIN SYN RST PSH ACK 
Init Win Bytes
maxActive minActive
maxIdle minIdle

[5, 7, 8, 10, 12, 13, 14, 20, 21, 22, 24, 25, 49, 50, 51, 52, 53, 71, 77, 78, 81, 82]
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

    data = pd.read_csv("/media/ckz/T7/datasets/CICIDS2017-Processed/wednesday/csv/wednesday.csv",
                       converters={"Label": label},
                       usecols=range(4, 37))

    train_data = data.sample(frac=0.6, random_state=0, axis=0)

    test_data = data[~data.index.isin(train_data.index)].sample(frac=1, random_state=0, axis=0)

    # train
    columns = np.array(train_data.columns)

    print(columns)

    train_array = np.array(train_data)

    train_array[np.isnan(train_array)] = 0

    train_array[np.isinf(train_array)] = sys.maxsize

    train_x = train_array[:, :train_array.shape[1] - 1]
    train_y = train_array[:, train_array.shape[1] - 1]

    class_names = ["Normal", "Exception"]

    clf = tree.DecisionTreeClassifier(max_depth=8, max_leaf_nodes=64)
    clf = clf.fit(train_x, train_y)

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

    # predict
    test_array = np.array(test_data)

    test_array[np.isnan(test_array)] = 0

    test_array[np.isinf(test_array)] = sys.maxsize

    test_x = test_array[:, :test_array.shape[1] - 1]
    test_y = test_array[:, test_array.shape[1] - 1]

    predict_y = clf.predict(test_x)

    print(accuracy_score(test_y, predict_y))
