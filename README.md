# Proccesing-Email
This project will help you identify phishing emails and normal emails in your Gmail mail

RU:
Описание
Данное приложение состоит из двух основных частей: pyparser.py и main.py. Эти скрипты позволяют анализировать электронные письма на предмет фишинга и вредоносного содержания с использованием сервиса VirusTotal.

Файлы
pyparser.py
Файл pyparser.py отвечает за подключение к почтовому ящику, извлечение писем и их анализ. Он использует учетные данные почтового ящика для авторизации и API ключ от VirusTotal для сканирования ссылок и вложений на вирусы.

main.py
Файл main.py включает в себя машинное обучение для классификации писем. Он использует набор данных для обучения модели и затем применяет эту модель для классификации новых писем.

Настройка
Получение API ключа от VirusTotal
Зарегистрируйтесь на сайте VirusTotal.
После регистрации перейдите в свой профиль и скопируйте ваш API ключ.
Указание пути к текстовому файлу
В файле pyparser.py найдите переменную output_file_path и укажите путь к файлу, в который будут записываться результаты анализа писем.
Вход в почту через скрипт
Для безопасного доступа к вашему почтовому ящику Gmail через скрипт, используйте пароль от приложения.

Создание пароля от приложения в Gmail
Войдите в свою учетную запись Google и перейдите в раздел "Безопасность".
В разделе "Вход в Google" найдите "Пароли приложений" и выберите "Управление паролями приложений".
Выберите "Почта" и устройство, с которого вы будете входить, затем нажмите "Генерировать".
Скопируйте сгенерированный пароль и используйте его в скрипте pyparser.py вместо обычного пароля от почты.
Использование
Для запуска приложения следует выполнить файл pyparser.py, предварительно убедившись, что все конфигурационные параметры (учетные данные почты, путь к файлу и API ключ) настроены правильно.

EN:
Description
This application consists of two main parts: pyparser.py and main.py. These scripts allow you to analyze emails for phishing and malicious content using the VirusTotal service.

The files
pyparser.py
The pyparser.py file is responsible for connecting to the mailbox, retrieving emails and analyzing them. It uses mailbox credentials for authorization and the API key from VirusTotal to scan links and attachments for viruses.

main.py
The main.py file incorporates machine learning to classify emails. It uses a dataset to train a model and then applies that model to classify new emails.

Customization
Getting an API key from VirusTotal
Register on the VirusTotal website.
After registering, go to your profile and copy your API key.
Specifying the path to the text file
In the pyparser.py file, find the output_file_path variable and specify the path to the file where the results of email analysis will be written.
Logging into mail through a script
To securely access your Gmail inbox through a script, use an application password.

Create an app password in Gmail
Sign in to your Google account and go to the "Security" section.
Under "Sign in to Google," find "App Passwords" and select "Manage app passwords."
Select "Mail" and the device you'll be logging in from, then click "Generate".
Copy the generated password and use it in the pyparser.py script instead of your regular mail password.
Usage
To run the application, run the pyparser.py file, first making sure that all configuration parameters (mail credentials, file path and API key) are set up correctly.

Translated with DeepL.com (free version)
