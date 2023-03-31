import pandas as pd
import numpy as np
from sklearn import tree
import graphviz
import collections
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, log_loss, accuracy_score, f1_score, recall_score, precision_score, \
    roc_auc_score
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import MinMaxScaler

def binary(s):
    if (s == "BENIGN"):
        return 0
    return 1


def multi(s):
    if s == "BENIGN":
        return 0
    if s == "DoS":
        return 1
    if s == "portScan":
        return 2
    if s == "bruteForce":
        return 3
    if s == "ddos":
        return 4
    if s == "heartbleed":
        return 5
    if s == "infiltration":
        return 6
    if s == "Web Attack":
        return 7
    if s == "botnet":
        return 8


def process_data():
    # 数据预处理
    df = pd.read_csv("dataset/CICIDS2017-15s.csv", converters={"Label": binary})
    df = df.drop("Time", axis=1)
    print(df.columns)
    df[df < 0] = 0
    x = df.iloc[:, :-1]
    y = df.iloc[:, -1]
    train_x, test_x, train_y, test_y = train_test_split(x, y, test_size=0.4, random_state=0)

    columns = df.columns
    # print(columns)
    print("train_normal:", train_y.value_counts().values[0])
    print("train_exception:", train_y.value_counts().values[1])
    print("test_normal:", test_y.value_counts().values[0])
    print("test_exception:", test_y.value_counts().values[1])
    print("---------------------------------")

    return columns, train_x, test_x, train_y, test_y


def process_data2():
    # 数据预处理
    df = pd.read_csv("dataset/CICIDS2017-15s.csv", converters={"Label": binary})
    df = df.drop("Time", axis=1)
    df[df < 0] = 0
    x = df.iloc[:, :-1]
    y = df.iloc[:, -1]
    # scaler = StandardScaler()
    scaler = MinMaxScaler()
    # 对数据进行归一化处理
    x = scaler.fit_transform(x)
    columns = df.columns

    return columns, x, y


def print_score(pred, test):
    print("accuracy_score:", accuracy_score(pred, test))
    print("precision_score:", precision_score(pred, test))
    print("recall_score:", recall_score(pred, test))
    print("f1_score:", f1_score(pred, test))
    print("log_loss:", log_loss(pred, test))
    print("roc_auc_score:", roc_auc_score(pred, test))
    print("confusion_matrix", confusion_matrix(test, pred))


def export_tree(dt_tree, col):
    class_names = ["Normal", "Exception"]
    dt_tree.tree_.children_left.tofile("../xdp/dt/childLeft.bin")
    dt_tree.tree_.children_right.tofile("../xdp/dt/childrenRight.bin")
    dt_tree.tree_.feature.tofile("../xdp/dt/feature.bin")
    dt_tree.tree_.threshold.astype(int).tofile("../xdp/dt/threshold.bin")
    value = []
    values = dt_tree.tree_.value
    for val in values:
        value.append(np.argmax(val))
    np.array(value).tofile("../xdp/dt/value.bin")

    # print(np.fromfile("../xdp/dt/childLeft.bin", dtype=int))
    # print(np.fromfile("../xdp/dt/childrenRight.bin", dtype=int))
    # print(np.fromfile("../xdp/dt/feature.bin", dtype=int))
    # print(np.fromfile("../xdp/dt/threshold.bin", dtype=int))
    # print(np.fromfile("../xdp/dt/value.bin", dtype=int))
    # print(np.fromfile("../xdp/dt/impurity.bin", dtype=int))

    dot_data = tree.export_graphviz(dt_tree, out_file=None,
                                    feature_names=col[:col.shape[0] - 1],
                                    class_names=class_names,
                                    filled=True, rounded=True,
                                    special_characters=True)
    graph = graphviz.Source(dot_data)
    graph.render("../xdp/dt/decide_tree")
