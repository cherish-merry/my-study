import warnings

from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from utils import process_data2

from sklearn.model_selection import cross_validate
from sklearn.metrics import make_scorer, f1_score, recall_score, precision_score, confusion_matrix, \
    roc_auc_score

warnings.filterwarnings("ignore")


def false_positive_rate(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    return fp / (fp + tn)


columns, x, y = process_data2()


def predict(classifier, name):
    print("classifier:", name)
    scoring = {
        'false_positive_rate': make_scorer(false_positive_rate),
        'precision': make_scorer(precision_score),
        'recall': make_scorer(recall_score),
        'f1': make_scorer(f1_score),
        "roc_auc": make_scorer(roc_auc_score)
    }

    scores = cross_validate(classifier, x, y, cv=5, scoring=scoring)
    print('False positive rate:', scores['test_false_positive_rate'].mean())
    print('Precision:', scores['test_precision'].mean())
    print('Recall:', scores['test_recall'].mean())
    print('F1', scores['test_f1'].mean())
    print('ROC AUC', scores['test_roc_auc'].mean())


# predict(DecisionTreeClassifier(), "dt")
# predict(RandomForestClassifier(), "rf")
predict(LogisticRegression(), "lg")
predict(MultinomialNB(), "nb")
predict(KNeighborsClassifier(), "knn")
