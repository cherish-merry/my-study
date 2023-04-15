import numpy as np

from utils import process_data
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_predict
from sklearn.metrics import classification_report, log_loss
from sklearn.metrics import confusion_matrix
import matplotlib.pyplot as plt
from utils import print_score


def plot():
    log_loss_plot = []
    num = 20
    for i in range(num):
        rf_plot = RandomForestClassifier(min_impurity_decrease=(20 - i) * 0.001)
        rf_plot.fit(train_x, train_y)
        rf_pred_plot = rf_plot.predict(test_x)
        log_loss_plot.append(log_loss(rf_pred_plot, test_y))
    x = list(range(num, 0, -1))
    y = [i * 0.001 for i in x]
    plt.plot(y, log_loss_plot, color="red")

    plt.xlabel("Impurity")
    plt.ylabel("Log Loss")

    plt.savefig("rf.svg", dpi=300, format="svg")
    plt.legend()
    plt.show()


if __name__ == '__main__':
    columns, train_x, test_x, train_y, test_y = process_data()
    rf = RandomForestClassifier(max_leaf_nodes=1024, max_depth=12, n_estimators=15)
    rf.fit(train_x, train_y)

    left = np.array([])
    right = np.array([])
    feature = np.array([])
    threshold = np.array([])
    value = np.array([])
    size = np.array([])
    for dt in rf.estimators_:
        left = np.append(left, dt.tree_.children_left)
        right = np.append(right, dt.tree_.children_right)
        feature = np.append(feature, dt.tree_.feature)
        threshold = np.append(threshold, dt.tree_.threshold)
        size = np.append(size, dt.tree_.children_left.shape)
        for val in dt.tree_.value:
            value = np.append(value, np.argmax(val))

    rf_pred = rf.predict(test_x)
    print_score(rf_pred, test_y)

    # plot()

    # left.tofile("../xdp/rf/childLeft.bin")
    # right.tofile("../xdp/rf/childrenRight.bin")
    # feature.tofile("../xdp/rf/feature.bin")
    # threshold.astype(int).tofile("../xdp/rf/threshold.bin")
    # value.tofile("../xdp/rf/value.bin")
    # size.tofile("../xdp/rf/size.bin")

    # print(np.fromfile("../xdp/rf/childLeft.bin"))
    # print(np.fromfile("../xdp/rf/childrenRight.bin"))
    # print(np.fromfile("../xdp/rf/feature.bin"))
    # print(np.fromfile("../xdp/rf/threshold.bin", dtype=int))
    # print(np.fromfile("../xdp/rf/value.bin"))
    # print(np.fromfile("../xdp/rf/size.bin"))
