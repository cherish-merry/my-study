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
from imblearn.under_sampling import RandomUnderSampler
from imblearn.over_sampling import SMOTE


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
    df[df < 0] = 0
    x = df.iloc[:, :-1]
    y = df.iloc[:, -1]

    columns = df.columns

    counts = y.value_counts()

    # 使用RandomUnderSampler类进行下采样
    rus = RandomUnderSampler(random_state=0,
                             sampling_strategy={0: int(counts[0] / 10)})
    x, y = rus.fit_resample(x, y)

    # 插值上采样
    smote = SMOTE(random_state=0)
    x, y = smote.fit_resample(x, y)
    # print(y.value_counts())

    train_x, test_x, train_y, test_y = train_test_split(x, y, test_size=0.4, random_state=0)

    return columns, train_x, test_x, train_y, test_y


def binary_process(scaler, rate):
    # 数据预处理
    df = pd.read_csv("dataset/CICIDS2017-15s.csv", converters={"Label": binary})
    df = df.drop("Time", axis=1)
    df[df < 0] = 0
    x = df.iloc[:, :-1]
    y = df.iloc[:, -1]
    # scaler = StandardScaler()
    # scaler = MinMaxScaler()
    # 对数据进行归一化处理
    if scaler is not None:
        x = scaler.fit_transform(x)

    columns = df.columns

    counts = y.value_counts()

    # 使用RandomUnderSampler类进行下采样
    rus = RandomUnderSampler(random_state=0,
                             sampling_strategy={0: int(counts[0] / rate)})
    x, y = rus.fit_resample(x, y)

    # 插值上采样
    smote = SMOTE(random_state=0)
    x, y = smote.fit_resample(x, y)
    # print(y.value_counts())
    return columns, x, y


def multi_process(scaler, rate):
    # 数据预处理
    df = pd.read_csv("dataset/CICIDS2017-15s.csv", converters={"Label": multi})

    # 删除"Time"列
    df.drop("Time", axis=1, inplace=True)

    # 将小于0的值替换为0
    df[df < 0] = 0

    # 分割特征和标签
    x = df.iloc[:, :-1]
    y = df.iloc[:, -1]

    if scaler is not None:
        x = scaler.fit_transform(x)

    counts = y.value_counts()
    # 下采样
    rus = RandomUnderSampler(random_state=0,
                             sampling_strategy={0: int(counts[0] / rate), 1: int(counts[1]), 2: int(counts[2]),
                                                3: int(counts[3]), 4: int(counts[4]), 5: int(counts[5]),
                                                6: int(counts[6]), 7: int(counts[7]), 8: int(counts[8])})
    x, y = rus.fit_resample(x, y)

    # 计算各个标签的数量
    value_counts = y.value_counts()

    count_other = value_counts.iloc[1:].sum()

    # 计算其他数量之间的比例并修改
    ratios = value_counts.iloc[1:] / count_other
    value_counts.iloc[1:] = (ratios * value_counts.iloc[0]).astype(int)

    # 上采样
    smote = SMOTE(random_state=0,
                  sampling_strategy={0: value_counts[0], 1: value_counts[1], 2: value_counts[2], 3: value_counts[3],
                                     4: value_counts[4], 5: value_counts[5], 6: value_counts[6], 7: value_counts[7],
                                     8: value_counts[8]})
    x, y = smote.fit_resample(x, y)
    # print(y.value_counts())
    return df.columns, x, y


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
