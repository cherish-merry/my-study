import numpy as np

from sklearn.ensemble import RandomForestClassifier
from utils import print_score
from utils import binary_process
from sklearn.model_selection import train_test_split
import joblib

if __name__ == '__main__':
    columns, x, y = binary_process(None, 100)
    train_x, test_x, train_y, test_y = train_test_split(x, y, test_size=0.2, random_state=0)
    rf = RandomForestClassifier(max_leaf_nodes=127, max_depth=27, n_estimators=54)
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
    joblib.dump(rf, 'random_forest_model.pkl')

    left.tofile("../xdp/rf/childLeft.bin")
    right.tofile("../xdp/rf/childrenRight.bin")
    feature.tofile("../xdp/rf/feature.bin")
    threshold.astype(int).tofile("../xdp/rf/threshold.bin")
    value.tofile("../xdp/rf/value.bin")
    size.tofile("../xdp/rf/size.bin")

    print(np.fromfile("../xdp/rf/childLeft.bin"))
    print(np.fromfile("../xdp/rf/childrenRight.bin"))
    print(np.fromfile("../xdp/rf/feature.bin"))
    print(np.fromfile("../xdp/rf/threshold.bin", dtype=int))
    print(np.fromfile("../xdp/rf/value.bin"))
    print(np.fromfile("../xdp/rf/size.bin"))
