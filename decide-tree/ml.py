from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_predict
from utils import binary_process, multi_process
from sklearn.metrics import classification_report, log_loss
from sklearn.metrics import confusion_matrix
from sklearn.preprocessing import MinMaxScaler


def binary_classification():
    print("binary_classification")
    columns, x, y = binary_process(MinMaxScaler(), 100)
    target_names = ['Normal', 'Attack']
    predict(x, y, KNeighborsClassifier(), "knn", target_names)
    predict(x, y, GaussianNB(), "nb", target_names)
    predict(x, y, LogisticRegression(max_iter=10000), "lg", target_names)
    predict(x, y, DecisionTreeClassifier(), "dt", target_names)
    predict(x, y, RandomForestClassifier(), "rf", target_names)


def multi_classification():
    print("multi_classification")
    columns, x, y = multi_process(MinMaxScaler(), 100)
    target_names = ['Normal', 'Dos', 'PortScan', 'BruteForce', "DDOS", "HeartBleed", "Infiltration", "Web Attack",
                    "Botnet"]
    predict(x, y, KNeighborsClassifier(), "knn", target_names)
    predict(x, y, GaussianNB(), "nb", target_names)
    predict(x, y, LogisticRegression(max_iter=10000), "lg", target_names)
    predict(x, y, DecisionTreeClassifier(), "dt", target_names)
    predict(x, y, RandomForestClassifier(), "rf", target_names)


def predict(x, y, classifier, name, target_names):
    print("----------------------------------------------------------------------")
    print("classifier:", name)
    y_pred = cross_val_predict(classifier, x, y, cv=5)
    y_proba = cross_val_predict(classifier, x, y, cv=5, method='predict_proba')

    report = classification_report(y, y_pred, target_names=target_names, zero_division=1, digits=3)
    conf_mat = confusion_matrix(y, y_pred)
    print("Confusion Matrix:")
    print(conf_mat)
    print(report)
    print("Log loss: {:.3f}".format(log_loss(y, y_proba)))


if __name__ == '__main__':
    # 二分类
    binary_classification()
    # 多分类
    multi_classification()
