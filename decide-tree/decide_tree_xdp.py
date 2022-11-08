import pandas as pd
import numpy as np
from sklearn import tree
import graphviz
import sys
from sklearn.metrics import accuracy_score
import matplotlib
import collections

matplotlib.use('qtagg')
import matplotlib.pyplot as plt


def label(s):
    if s == "BENIGN":
        return 0
    else:
        return 1


if __name__ == '__main__':
    df = pd.read_csv("dataset/CICIDS-ip-15.csv",
                     converters={"Label": label})
    print(df.shape)

    df = df.dropna()

    # print(df.shape)

    # df = df.drop(df[df['Flow Duration'] == 0].index)

    # df = df.drop(['Protocol'], axis=1)
    # df = df.drop(['FIN Flag Cnt'], axis=1)
    # df = df.drop(['SYN Flag Cnt'], axis=1)
    # df = df.drop(['RST Flag Cnt'], axis=1)
    # df = df.drop(['PSH Flag Cnt'], axis=1)

    # print(df.shape)

    columns = np.array(df.columns)
    print(columns)

    # train
    train_data = df.sample(frac=0.8, random_state=0, axis=0)
    test_data = df[~df.index.isin(train_data.index)].sample(frac=1, random_state=0, axis=0)
    train_array = np.array(train_data)

    train_array[np.isinf(train_array)] = 0

    train_x = train_array[:, :train_array.shape[1] - 1]
    train_y = train_array[:, train_array.shape[1] - 1]

    test_array = np.array(test_data)
    test_array[np.isinf(test_array)] = 0
    test_x = test_array[:, :test_array.shape[1] - 1]
    test_y = test_array[:, test_array.shape[1] - 1]

    exceptions = train_data.Label.value_counts().values[1]

    percentage = 0.01

    max_depth = 15

    max_leaf_nodes = 1024

    # min_samples_leaf = int(exceptions * percentage)
    min_samples_leaf = 2

    print("exceptions:", exceptions)
    print("max_depth:", max_depth)
    print("max_leaf_nodes:", max_leaf_nodes)
    print("min_samples_leaf:", min_samples_leaf)

    class_names = ["Normal", "Exception"]

    clf = tree.DecisionTreeClassifier(max_depth=max_depth, max_leaf_nodes=max_leaf_nodes,
                                      min_samples_leaf=min_samples_leaf,
                                      min_samples_split=min_samples_leaf * 2, min_impurity_decrease=0.0001)

    clf = clf.fit(train_x, train_y)

    print("\n\n feature")
    counter = collections.Counter(clf.tree_.feature)
    for key in counter:
        if key > 0:
            print(columns[key].strip())

    clf.tree_.children_left.tofile("../xdp/result/childLeft.bin")
    clf.tree_.children_right.tofile("../xdp/result/childrenRight.bin")
    clf.tree_.feature.tofile("../xdp/result/feature.bin")
    clf.tree_.threshold.astype(int).tofile("../xdp/result/threshold.bin")
    (clf.tree_.impurity * 100).astype(int).tofile("../xdp/result/impurity.bin")
    value = []
    values = clf.tree_.value
    for val in values:
        value.append(np.argmax(val))
    np.array(value).tofile("../xdp/result/value.bin")

    # print(np.fromfile("../xdp/feature/result/childLeft.bin", dtype=int))
    # print(np.fromfile("../xdp/feature/result/childrenRight.bin", dtype=int))
    # print(np.fromfile("../xdp/feature/result/feature.bin", dtype=int))
    # print(np.fromfile("../xdp/feature/result/threshold.bin", dtype=int))
    # print(np.fromfile("../xdp/feature/result/value.bin", dtype=int))
    # print(np.fromfile("../xdp/feature/result/impurity.bin", dtype=int))

    dot_data = tree.export_graphviz(clf, out_file=None,
                                    feature_names=columns[:columns.shape[0] - 1],
                                    class_names=class_names,
                                    filled=True, rounded=True,
                                    special_characters=True)
    graph = graphviz.Source(dot_data)
    graph.render("../xdp/result/decide_tree")

    # predict
    predict_y = clf.predict(test_x)

    print(accuracy_score(test_y, predict_y))

    # test = []
    # for i in range(36):
    #     clf = tree.DecisionTreeClassifier(max_depth=15
    #                                       , criterion="entropy",
    #                                       max_leaf_nodes=16 * (i + 1)
    #                                       , random_state=30
    #                                       , splitter="random",
    #                                       min_impurity_decrease=0.0001,
    #                                       min_samples_leaf=int(exceptions * percentage),
    #                                       min_samples_split=int(int(exceptions * percentage * 2))
    #                                       )
    #     clf = clf.fit(train_x, train_y)
    #     score = clf.score(test_x, test_y)
    #     test.append(score)
    # plt.plot(range(1, 37), test, color="red", label="max_depth")
    # plt.legend()
    # plt.show()
