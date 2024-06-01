import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import confusion_matrix, accuracy_score, ConfusionMatrixDisplay
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

class ScamClassier:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(stop_words='english')
        self.model = self._train()


    def _train(self):
        data = pd.read_csv('crypto_data.csv')
        x = data['Message']
        y = data['Label']

        x_train, x_test, y_train, y_test = train_test_split(self.vectorizer.fit_transform(x), y, test_size=0.3, random_state=79)

        model = MultinomialNB()
        model.fit(x_train, y_train)

        # Calculate confusion matrix
        # y_pred = model.predict(x_test)
        # cm = confusion_matrix(y_test, y_pred)
        # cm_normalized = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
        #
        # plt.figure(figsize=(8, 6))
        # sns.heatmap(cm_normalized, annot=True, fmt='.2f',  annot_kws={"size": 16}, cmap='Blues', xticklabels=['Not Scam', 'Scam'],
        #             yticklabels=['Not Scam', 'Scam'])
        # plt.xlabel('Predicted Labels')
        # plt.ylabel('True Labels')
        # plt.title('Classifier Confusion Matrix')
        # plt.show()
        '''
        [[13  1]
         [ 1 15]]
        '''

        return model

    def predict_scam(self, message):
        return self.model.predict(self.vectorizer.transform([message]))[0]
