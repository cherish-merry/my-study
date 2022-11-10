import pandas as pd
import numpy as np
from sklearn import tree
import graphviz
import collections
from sklearn.model_selection import train_test_split
from sklearn.metrics import log_loss, accuracy_score, f1_score, recall_score, precision_score, roc_auc_score


def label(s):
    if s == "BENIGN":
        return 0
    else:
        return 1


def process_data():
    # 数据预处理
    df = pd.read_csv("dataset/CICIDS-ip-15.csv", converters={"Label": label})
    df[df < 0] = 0
    x = df.iloc[:, :-1]
    y = df.iloc[:, -1]
    train_x, test_x, train_y, test_y = train_test_split(x, y, test_size=0.6, random_state=0)

    columns = df.columns
    # print(columns)
    print("train_normal:", train_y.value_counts().values[0])
    print("train_exception:", train_y.value_counts().values[1])
    print("test_normal:", test_y.value_counts().values[0])
    print("test_exception:", test_y.value_counts().values[1])
    print("---------------------------------")

    return columns, train_x, test_x, train_y, test_y


def print_score(pred, test):
    print("accuracy_score:", accuracy_score(pred, test))
    print("precision_score:", precision_score(pred, test))
    print("recall_score:", recall_score(pred, test))
    print("f1_score:", f1_score(pred, test))
    print("log_loss:", log_loss(pred, test))
    print("roc_auc_score:", roc_auc_score(pred, test))


def export_tree(dt_tree, col):
    class_names = ["Normal", "Exception"]
    dt_tree.tree_.children_left.tofile("../xdp/result/childLeft.bin")
    dt_tree.tree_.children_right.tofile("../xdp/result/childrenRight.bin")
    dt_tree.tree_.feature.tofile("../xdp/result/feature.bin")
    dt_tree.tree_.threshold.astype(int).tofile("../xdp/result/threshold.bin")
    (dt_tree.tree_.impurity * 100).astype(int).tofile("../xdp/result/impurity.bin")
    value = []
    values = dt_tree.tree_.value
    for val in values:
        value.append(np.argmax(val))
    np.array(value).tofile("../xdp/result/value.bin")

    # print(np.fromfile("../xdp/result/childLeft.bin", dtype=int))
    # print(np.fromfile("../xdp/result/childrenRight.bin", dtype=int))
    # print(np.fromfile("../xdp/result/feature.bin", dtype=int))
    # print(np.fromfile("../xdp/result/threshold.bin", dtype=int))
    # print(np.fromfile("../xdp/result/value.bin", dtype=int))
    # print(np.fromfile("../xdp/result/impurity.bin", dtype=int))

    dot_data = tree.export_graphviz(dt_tree, out_file=None,
                                    feature_names=col[:col.shape[0] - 1],
                                    class_names=class_names,
                                    filled=True, rounded=True,
                                    special_characters=True)
    graph = graphviz.Source(dot_data)
    graph.render("../xdp/result/decide_tree")


def export_decide_tree(dt):
    dt.children_left.tofile("../xdp/result/childLeft.bin")
    dt.children_right.tofile("../xdp/result/childrenRight.bin")
    dt.feature.tofile("../xdp/result/feature.bin")
    dt.threshold.astype(int).tofile("../xdp/result/threshold.bin")
    (dt.impurity * 100).astype(int).tofile("../xdp/result/impurity.bin")
    value = []
    values = dt.tree_.value
    for val in values:
        value.append(np.argmax(val))
    np.array(value).tofile("../xdp/result/value.bin")
