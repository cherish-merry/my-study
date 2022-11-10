from utils import process_data, print_score
from sklearn.ensemble import RandomForestClassifier
import matplotlib.pyplot as plt
from sklearn.metrics import log_loss

if __name__ == '__main__':
    columns, train_x, test_x, train_y, test_y = process_data()
    rf = RandomForestClassifier(max_depth=12, n_estimators=11, min_impurity_decrease=0.0001)
    rf.fit(train_x, train_y)
    rf_pred = rf.predict(test_x)
    print_score(rf_pred, test_y)

    # logLoss = []
    # num = 20
    # for i in range(num):
    #     rf = RandomForestClassifier(max_depth=12, n_estimators=i + 1, min_impurity_decrease=0.0001)
    #     rf.fit(train_x, train_y)
    #     rf_pred = rf.predict(test_x)
    #     logLoss.append(log_loss(rf_pred, test_y))
    # plt.plot(range(1, num + 1), logLoss, color="red", label="Log Loss")
    # plt.legend()
    # plt.show()
