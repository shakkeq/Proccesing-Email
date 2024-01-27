import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import classification_report

# Запись приветственного сообщения в файл
with open("C:/Users/pilla/OneDrive/Рабочий стол/qqq/new_emails.txt", "w", encoding="utf-8") as f:
    f.write("Привет, это тестовое сообщения, для проверки готовности к проверки ваших писем\n")

# Функция для чтения исходных данных
def read_data(filename):
    emails = []
    labels = []
    with open(filename, 'r', encoding='utf-8') as file:
        for line in file:
            if ' 1' in line or ' 0' in line or ' 2' in line:
                content, label = line.rsplit(' ', 1)
                emails.append(content.strip())
                labels.append(int(label.strip()))
    return emails, labels

# Функция для чтения новых писем из файла
def read_new_emails(filename):
    new_emails = []
    with open(filename, 'r', encoding='utf-8') as file:
        new_emails = [line.strip() for line in file]
    return new_emails

# Функция для классификации новых писем
def classify_new_emails(model, vectorizer, new_emails):
    new_emails_vectorized = vectorizer.transform(new_emails)
    predictions = model.predict(new_emails_vectorized)
    return predictions

# Чтение и предварительная обработка данных
emails, labels = read_data('emails.txt')
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(emails)

# Разделение и обучение модели
X_train, X_test, y_train, y_test = train_test_split(X, labels, test_size=0.3, stratify=labels, random_state=42)
model = MultinomialNB()
model.fit(X_train, y_train)

# Тестирование модели
predictions = model.predict(X_test)
#print(classification_report(y_test, predictions, zero_division=1))

# Чтение и классификация новых писем из файла
new_emails_file = 'new_emails.txt'
new_emails = read_new_emails(new_emails_file)
new_predictions = classify_new_emails(model, vectorizer, new_emails)

# вывод результатов
for email, prediction in zip(new_emails, new_predictions):
    classification = 'Phishing' if prediction == 1 else 'Normal' if prediction == 0 else 'Unnecessary'
    print(f"Email: {email}\nClassified as: {classification}\n")
    with open("C:/Users/pilla/OneDrive/Рабочий стол/qqq/new_emails.txt", "w", encoding="utf-8") as f:
        f.truncate()  # Очистка файла
    
