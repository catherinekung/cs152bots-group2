import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import confusion_matrix, accuracy_score

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
        # print(confusion_matrix(y_test, y_pred))
        '''
        [[13  1]
         [ 1 15]]
        '''

        return model

    def predict_scam(self, message):
        return self.model.predict(self.vectorizer.transform([message]))[0]
