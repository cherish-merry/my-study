import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score, recall_score, precision_score
from sklearn.metrics import log_loss
import numpy as np


def label(s):
    if s == "BENIGN":
        return 0
    else:
        return 1


df = pd.read_csv("../dataset/CICIDS.csv",
                 converters={"Label": label})

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

max_depth = 8
max_leaf_nodes = 64

dt = DecisionTreeClassifier(max_depth=max_depth, max_leaf_nodes=max_leaf_nodes)
dt.fit(train_x, train_y)

dt_pred = dt.predict(test_x)
print("log_loss:", log_loss(dt_pred, test_y))
print("accuracy_score:", accuracy_score(dt_pred, test_y))
print("f1_score:", f1_score(dt_pred, test_y))
print("recall_score:", recall_score(dt_pred, test_y))
print("precision_score:", precision_score(dt_pred, test_y))

print("-----------------------------------")

rf = RandomForestClassifier(max_depth=max_depth, max_leaf_nodes=max_leaf_nodes, n_estimators=1)
rf.fit(train_x, train_y)
rf_pred = rf.predict(test_x)
print("log_loss:", log_loss(rf_pred, test_y))
print("accuracy_score:", accuracy_score(rf_pred, test_y))
print("f1_score:", f1_score(rf_pred, test_y))
print("recall_score:", recall_score(rf_pred, test_y))
print("precision_score:", precision_score(rf_pred, test_y))

# knn = KNeighborsClassifier()
# knn.fit(train_x, train_y)
# print("knn:", knn.score(test_x, test_y))
