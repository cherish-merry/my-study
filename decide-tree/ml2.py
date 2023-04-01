import warnings

from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_predict
from utils import process_data2
from sklearn.metrics import classification_report, confusion_matrix

from sklearn.model_selection import cross_validate
from sklearn.metrics import make_scorer, f1_score, recall_score, precision_score, confusion_matrix, \
    roc_auc_score
from imblearn.under_sampling import RandomUnderSampler
from imblearn.over_sampling import ADASYN

from imblearn.combine import SMOTEENN

warnings.filterwarnings("ignore")

columns, x, y = process_data2()

# 使用RandomUnderSampler类进行下采样
# rus = RandomUnderSampler(random_state=0)
# x, y = rus.fit_resample(x, y)

# 使用ADASYN类进行过采样
# adasyn = ADASYN(random_state=0)
# x, y = adasyn.fit_resample(x, y)


# SMOTE+ENN采样方法是将SMOTE过采样和ENN下采样结合起来
smote_enn = SMOTEENN(random_state=0)
x, y = smote_enn.fit_resample(x, y)


def predict(classifier, name):
    print("classifier:", name)
    y_pred = cross_val_predict(classifier, x, y, cv=5)
    report = classification_report(y, y_pred, digits=4, output_dict=True)
    conf_mat = confusion_matrix(y, y_pred)
    fpr_value = conf_mat[0, 1] / (conf_mat[0, 0] + conf_mat[0, 1])
    print("Confusion Matrix:")
    print(conf_mat)
    print("Precision:", report['macro avg']['precision'])
    print("Recall:", report['macro avg']['recall'])
    print("F1-score:", report['macro avg']['f1-score'])
    print("False Positive Rate:", fpr_value)


predict(DecisionTreeClassifier(), "dt")
predict(RandomForestClassifier(), "rf")
predict(LogisticRegression(), "lg")
predict(MultinomialNB(), "nb")
predict(KNeighborsClassifier(), "knn")
