import imaplib
import email
import os
import time
import re
import requests
import logging
from email.header import decode_header
from bs4 import BeautifulSoup

# Импорт функций из main.py
from main import read_new_emails, classify_new_emails, vectorizer, model

# Конфигурация
first_run = True
email_address = "" #почту
password = "" #пароль приложения
api_key = "" #апи вирустотал
output_file_path = "" #файл куда сохранять письма

def clean_filename(filename):
    # Декодирование, если имя файла закодировано
    decoded_string, encoding = decode_header(filename)[0]
    if encoding:
        filename = decoded_string.decode(encoding)
    
    # Удаление или замена недопустимых символов
    filename = re.sub(r'[\\/*?:"<>|]', '_', filename)
    return filename

# Функция для извлечения URL из текста письма
def extract_urls(email_body):
    link_pattern = re.compile(r'http[s]?://\S+')
    return link_pattern.findall(email_body)

def extract_text_from_html(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    text = soup.get_text(separator=' ', strip=True)
    return text

# Функция для обработки письма
def process_email(email_id, mail, output_file_path, api_key, email_address, password):
    global first_run
    attachments_directory = "C:/Users/pilla/OneDrive/Рабочий стол/qqq/attachments"
    if not os.path.exists(attachments_directory):
        os.makedirs(attachments_directory)

    print(f"Обработка письма с ID: {email_id}")
    status, data = mail.fetch(email_id, "(RFC822)")
    email_body = ""

    for response_part in data:
        if isinstance(response_part, tuple):
            message = email.message_from_bytes(response_part[1])

            email_subject = str(decode_header(message["subject"])[0][0], 'utf-8', errors='ignore') if message["subject"] else "No Subject"
            email_from = str(decode_header(message.get("from"))[0][0], 'utf-8', errors='ignore') if message.get("from") else "Unknown Sender"

            if message.is_multipart():
                for part in message.walk():
                    if part.get_content_type() in ["text/plain", "text/html"]:
                        email_body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        email_body = BeautifulSoup(email_body, 'html.parser').get_text()
                        break
            else:
                email_body = message.get_payload(decode=True).decode('utf-8', errors='ignore')
                email_body = BeautifulSoup(email_body, 'html.parser').get_text()

            # Запись в файл
            with open(output_file_path, "a", encoding="utf-8") as f:
                # Форматирование текста письма: удаляем все переносы строк и добавляем один в конце
                formatted_email_body = ' '.join(email_body.split())
                f.write(formatted_email_body + "\n")

            # Вызов функции для чтения новых писем из файла и их классификации
            new_emails = read_new_emails(output_file_path)
            if new_emails:
                new_predictions = classify_new_emails(model, vectorizer, new_emails)

                # Вывод результатов классификации
                for email_text, prediction in zip(new_emails, new_predictions):
                    classification = 'Phishing' if prediction == 1 else 'Normal' if prediction == 0 else 'Unnecessary'
                    print(f"Email: {email_text}\nClassified as: {classification}\n")

                if first_run:
                    # Очистка файла после первой обработки
                    with open(output_file_path, "w", encoding="utf-8") as f:
                        f.truncate()  # Очистка файла
                    first_run = False

            else:
                print("Нет новых писем для анализа.")

            # Проверка и сканирование URL
            urls = extract_urls(email_body)
            for url in urls:
                scan_url_with_virustotal(api_key, url)

            # Проверка и сканирование вложений
            for part in message.walk():
                if part.get_content_maintype() == 'multipart' or part.get('Content-Disposition') is None:
                    continue
                file_name = part.get_filename()
                if file_name:
                    file_name = clean_filename(file_name)
                    file_path = os.path.join(attachments_directory, file_name)
                    with open(file_path, 'wb') as file:
                        file.write(part.get_payload(decode=True))

                    # Сканирование файла с VirusTotal
                    scan_file_with_virustotal(api_key, file_path)

                    # Удаление файла после сканирования
                    try:
                        os.remove(file_path)
                        print(f"Файл '{file_name}' был удален после сканирования.")
                    except OSError as e:
                        print(f"Ошибка при удалении файла '{file_name}': {e.strerror}")
                        
    # Очистка файла после обработки письма
    with open(output_file_path, "w", encoding="utf-8") as f:
        f.truncate()

    print("Обработка письма завершена.")

# Функция для сканирования URL с VirusTotal
def scan_url_with_virustotal(api_key, url):
    url_scan = 'https://www.virustotal.com/vtapi/v2/url/scan'
    url_report = 'https://www.virustotal.com/vtapi/v2/url/report'
    
    params_scan = {'apikey': api_key, 'url': url}
    params_report = {'apikey': api_key, 'resource': url}

    try:
        response_scan = requests.post(url_scan, params=params_scan)
        scan_json_response = response_scan.json()

        if response_scan.status_code == 200 and scan_json_response['response_code'] == 1:
            scan_id = scan_json_response['scan_id']
            print(f'URL успешно отправлен на сканирование: {scan_id}')

            time.sleep(30)  # Ожидание завершения сканирования

            response_report = requests.get(url_report, params=params_report)
            report_json_response = response_report.json()

            if response_report.status_code == 200 and report_json_response['response_code'] == 1:
                positives = report_json_response['positives']
                total = report_json_response['total']
                print(f'Результаты сканирования URL: {positives}/{total} антивирусных движков обнаружили URL как подозрительный.')
            else:
                print('Не удалось получить отчет о сканировании URL.')

        else:
            print(f'Ошибка отправки URL на сканирование: HTTP {response_scan.status_code}')

    except Exception as e:
        print(f'Ошибка при сканировании URL: {e}')

# Настройка логирования
logging.basicConfig(filename='error_log.txt', level=logging.ERROR, 
                    format='%(asctime)s:%(levelname)s:%(message)s')

def scan_file_with_virustotal(api_key, file_path):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': api_key}

    try:
        with open(file_path, 'rb') as file:
            files = {'file': (file_path, file)}
            response = requests.post(url, files=files, params=params)

            if response.status_code == 200:
                json_response = response.json()
                scan_id = json_response.get('scan_id')
                print(f'Файл успешно загружен: {scan_id}')

                time.sleep(60)  # Ожидание завершения сканирования

                url_report = 'https://www.virustotal.com/vtapi/v2/file/report'
                params_report = {'apikey': api_key, 'resource': scan_id}
                response_report = requests.get(url_report, params=params_report)

                if response_report.status_code == 200:
                    report_json = response_report.json()
                    if report_json['response_code'] == 1:
                        positives = report_json['positives']
                        total = report_json['total']
                        print(f"Результаты сканирования файла: {positives}/{total}")
                        if positives > 0:
                            print(f"Файл распознан вредоносным {positives} из {total} антивирусных движков.")
                        else:
                            print("Файл не распознан вредоносным ни одним из антивирусных движков.")
                    else:
                        print("Файл не распознан ни одним антивирусным движком.")
                else:
                    print(f"Ошибка загрузки файла: HTTP {response.status_code}")
            else:
                logging.error(f'Ошибка загрузки файла: HTTP {response.status_code}, Response: {response.text}')
                    
    except Exception as e:
        logging.error(f'Ошибка при сканировании файла: {e}', exc_info=True)

# Основной цикл для обработки новых писем
def main_loop(email_address, password, output_file_path, api_key):
    mail = imaplib.IMAP4_SSL("imap.gmail.com")
    mail.login(email_address, password)

    while True:
        try:
            mail.select("inbox")  # Обновление состояния почтового ящика
            status, messages = mail.search(None, '(UNSEEN)')

            if status != 'OK':
                print("Нет новых непрочитанных писем.")
            else:
                message_ids = messages[0].split()
                print(f"Найдено {len(message_ids)} новых писем.")

                for email_id in message_ids:
                    process_email(email_id, mail, output_file_path, api_key, email_address, password)
        except Exception as e:
            print(f"Произошла ошибка: {e}")

        time.sleep(30)  # Ожидание перед следующей проверкой

    mail.logout()


if __name__ == "__main__":
    main_loop(email_address, password, output_file_path, api_key)
