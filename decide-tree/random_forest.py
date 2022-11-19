import numpy as np

from utils import process_data, print_score
from sklearn.ensemble import RandomForestClassifier
import matplotlib.pyplot as plt

def plot():
    log_loss_plot = []
    num = 20
    for i in range(num):
        rf_plot = RandomForestClassifier(max_depth=9, n_estimators=i + 1, min_impurity_decrease=0.0001)
        rf_plot.fit(train_x, train_y)
        rf_pred_plot = rf_plot.predict(test_x)
        log_loss_plot.append(log_loss_plot(rf_pred_plot, test_y))
    plt.plot(range(1, num + 1), log_loss_plot, color="red", label="Log Loss")
    plt.legend()
    plt.show()


if __name__ == '__main__':
    columns, train_x, test_x, train_y, test_y = process_data()
    rf = RandomForestClassifier(max_depth=12, n_estimators=15, min_impurity_decrease=0.0001)
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

    left.tofile("../xdp/rf/childLeft.bin")
    right.tofile("../xdp/rf/childrenRight.bin")
    feature.tofile("../xdp/rf/feature.bin")
    threshold.astype(int).tofile("../xdp/rf/threshold.bin")
    value.tofile("../xdp/rf/value.bin")
    size.tofile("../xdp/rf/size.bin")

    # print(np.fromfile("../xdp/rf/childLeft.bin"))
    # print(np.fromfile("../xdp/rf/childrenRight.bin"))
    # print(np.fromfile("../xdp/rf/feature.bin"))
    # print(np.fromfile("../xdp/rf/threshold.bin", dtype=int))
    # print(np.fromfile("../xdp/rf/value.bin"))
    # print(np.fromfile("../xdp/rf/size.bin"))
