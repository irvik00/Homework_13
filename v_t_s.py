#!/usr/bin/env python3
"""
Описание: Скрипт выполняет авторизацию по API-ключу и получает информацию
о статусе сканирования файла или URL через VirusTotal API.

Требования:
- Python 3.6+
- Установленные библиотеки: requests, json

Установка зависимостей:
pip install requests

Запуск скрипта:
python virus_total_scanner.py
"""

import requests
import json
import os
import sys
from datetime import datetime

class VirusTotalScanner:
    """Класс для работы с VirusTotal API"""
    
    def __init__(self):
        """
        Инициализация сканера с запросом API ключа, если его нет
        """
        self.api_key = self._get_api_key()
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        print("[OK] API ключ успешно загружен")
    
    def _get_api_key(self):
        """
        Получение API ключа из переменной окружения или запрос у пользователя
        
        Returns:
            str: API ключ
        """
        # Сначала проверяем переменную окружения
        api_key = os.environ.get('VIRUSTOTAL_API_KEY')
        
        # Если нет в переменной окружения, запрашиваем у пользователя
        if not api_key:
            print("\n" + "="*50)
            print("API КЛЮЧ НЕ НАЙДЕН")
            print("="*50)
            print("\nДля работы с VirusTotal API требуется ключ.")
            print("Как получить ключ:")
            print("1. Зарегистрируйтесь на https://www.virustotal.com")
            print("2. Войдите в аккаунт")
            print("3. Перейдите в раздел 'API Key'")
            print("4. Скопируйте ваш персональный ключ")
            print("\nИли используйте тестовый ключ (ограниченный):")
            print("- Для демо-режима введите 'demo'")
            print("\n" + "="*50)
            
            api_key = input("\nВведите ваш API ключ: ").strip()
            
            if not api_key:
                print("[ERROR] API ключ не может быть пустым")
                sys.exit(1)
            
            # Сохраняем в переменную окружения для текущей сессии
            os.environ['VIRUSTOTAL_API_KEY'] = api_key
            print("[OK] API ключ сохранен для текущей сессии")
        
        return api_key
    
    def scan_url(self, url):
        """
        Отправка URL на сканирование
        
        Args:
            url (str): URL для сканирования
            
        Returns:
            dict: Ответ от API в формате JSON
        """
        print(f"\n[INFO] Отправка URL на сканирование: {url}")
        
        endpoint = f"{self.base_url}/urls"
        data = {"url": url}
        
        try:
            response = requests.post(endpoint, headers=self.headers, data=data)
            response.raise_for_status()
            
            result = response.json()
            print("[SUCCESS] URL успешно отправлен на сканирование")
            return result
            
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Ошибка при отправке запроса: {e}")
            return None
    
    def get_url_report(self, url_or_id):
        """
        Получение отчета о сканировании URL
        
        Args:
            url_or_id (str): URL или ID отчета
            
        Returns:
            dict: Отчет о сканировании
        """
        print(f"\n[INFO] Получение отчета для: {url_or_id}")
        
        # Кодируем URL для использования в запросе
        import base64
        url_id = base64.urlsafe_b64encode(url_or_id.encode()).decode().strip("=")
        
        endpoint = f"{self.base_url}/urls/{url_id}"
        
        try:
            response = requests.get(endpoint, headers=self.headers)
            response.raise_for_status()
            
            result = response.json()
            print("[SUCCESS] Отчет успешно получен")
            return result
            
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Ошибка при получении отчета: {e}")
            return None
    
    def scan_file_hash(self, file_hash):
        """
        Получение информации о файле по его хешу
        
        Args:
            file_hash (str): MD5, SHA-1 или SHA-256 хеш файла
            
        Returns:
            dict: Информация о файле
        """
        print(f"\n[INFO] Получение информации о файле по хешу: {file_hash}")
        
        endpoint = f"{self.base_url}/files/{file_hash}"
        
        try:
            response = requests.get(endpoint, headers=self.headers)
            response.raise_for_status()
            
            result = response.json()
            print("[SUCCESS] Информация о файле успешно получена")
            return result
            
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Ошибка при получении информации о файле: {e}")
            return None
    
    def get_ip_report(self, ip_address):
        """
        Получение информации об IP-адресе
        
        Args:
            ip_address (str): IP-адрес для анализа
            
        Returns:
            dict: Информация об IP
        """
        print(f"\n[INFO] Получение информации об IP: {ip_address}")
        
        endpoint = f"{self.base_url}/ip_addresses/{ip_address}"
        
        try:
            response = requests.get(endpoint, headers=self.headers)
            response.raise_for_status()
            
            result = response.json()
            print("[SUCCESS] Информация об IP успешно получена")
            return result
            
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Ошибка при получении информации об IP: {e}")
            return None

def save_json_response(data, filename_prefix="response"):
    """
    Сохранение JSON ответа в файл
    
    Args:
        data (dict): Данные для сохранения
        filename_prefix (str): Префикс имени файла
    """
    if data:
        # Создаем папку для ответов, если её нет
        if not os.path.exists("responses"):
            os.makedirs("responses")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"responses/{filename_prefix}_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"\n[INFO] JSON ответ сохранен в файл: {filename}")
        except Exception as e:
            print(f"[ERROR] Ошибка при сохранении файла: {e}")

def print_json_pretty(data):
    """
    Красивый вывод JSON в консоль
    
    Args:
        data (dict): Данные для вывода
    """
    if data:
        print("\n" + "="*50)
        print("JSON ОТВЕТ:")
        print("="*50)
        print(json.dumps(data, indent=2, ensure_ascii=False))
        print("="*50 + "\n")

def interactive_mode():
    """
    Интерактивный режим для выбора действий
    """
    scanner = VirusTotalScanner()
    
    while True:
        print("\n" + "="*50)
        print("ГЛАВНОЕ МЕНЮ")
        print("="*50)
        print("1. Сканировать URL")
        print("2. Получить отчет по URL")
        print("3. Проверить файл по хешу")
        print("4. Проверить IP-адрес")
        print("5. Запустить демо-примеры")
        print("0. Выход")
        print("="*50)
        
        choice = input("\nВыберите действие (0-5): ").strip()
        
        if choice == "0":
            print("\n[INFO] Программа завершена")
            break
        
        elif choice == "1":
            url = input("Введите URL для сканирования: ").strip()
            if url:
                result = scanner.scan_url(url)
                print_json_pretty(result)
                save = input("Сохранить результат в файл? (y/n): ").strip().lower()
                if save == 'y':
                    save_json_response(result, "url_scan")
            else:
                print("[ERROR] URL не может быть пустым")
        
        elif choice == "2":
            url = input("Введите URL для получения отчета: ").strip()
            if url:
                result = scanner.get_url_report(url)
                print_json_pretty(result)
                save = input("Сохранить результат в файл? (y/n): ").strip().lower()
                if save == 'y':
                    save_json_response(result, "url_report")
            else:
                print("[ERROR] URL не может быть пустым")
        
        elif choice == "3":
            file_hash = input("Введите хеш файла (MD5, SHA-1 или SHA-256): ").strip()
            if file_hash:
                result = scanner.scan_file_hash(file_hash)
                print_json_pretty(result)
                save = input("Сохранить результат в файл? (y/n): ").strip().lower()
                if save == 'y':
                    save_json_response(result, "file_info")
            else:
                print("[ERROR] Хеш не может быть пустым")
        
        elif choice == "4":
            ip = input("Введите IP-адрес: ").strip()
            if ip:
                result = scanner.get_ip_report(ip)
                print_json_pretty(result)
                save = input("Сохранить результат в файл? (y/n): ").strip().lower()
                if save == 'y':
                    save_json_response(result, "ip_info")
            else:
                print("[ERROR] IP-адрес не может быть пустым")
        
        elif choice == "5":
            run_demo(scanner)
        
        else:
            print("[ERROR] Неверный выбор. Пожалуйста, выберите 0-5")

def run_demo(scanner):
    """
    Запуск демонстрационных примеров
    
    Args:
        scanner (VirusTotalScanner): Экземпляр сканера
    """
    print("\n" + "="*50)
    print("ЗАПУСК ДЕМО-ПРИМЕРОВ")
    print("="*50)
    
    # Пример 1: Сканирование URL
    print("\n" + "-"*40)
    print("ПРИМЕР 1: Сканирование URL")
    print("-"*40)
    
    test_url = "https://www.google.com"
    scan_result = scanner.scan_url(test_url)
    if scan_result:
        print_json_pretty(scan_result)
        save_json_response(scan_result, "demo_url_scan")
    
    # Пример 2: Получение отчета по URL
    print("\n" + "-"*40)
    print("ПРИМЕР 2: Получение отчета по URL")
    print("-"*40)
    
    report = scanner.get_url_report(test_url)
    if report:
        print_json_pretty(report)
        save_json_response(report, "demo_url_report")
    
    # Пример 3: Получение информации по хешу файла
    print("\n" + "-"*40)
    print("ПРИМЕР 3: Информация по хешу файла")
    print("-"*40)
    
    # Пример хеша EICAR тестового файла
    test_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    file_info = scanner.scan_file_hash(test_hash)
    if file_info:
        print_json_pretty(file_info)
        save_json_response(file_info, "demo_file_info")
    
    # Пример 4: Информация по IP
    print("\n" + "-"*40)
    print("ПРИМЕР 4: Информация по IP")
    print("-"*40)
    
    ip_info = scanner.get_ip_report("8.8.8.8")
    if ip_info:
        print_json_pretty(ip_info)
        save_json_response(ip_info, "demo_ip_info")
    
    print("\n[INFO] Демо-примеры завершены")

def main():
    """
    Основная функция
    """
    print("="*60)
    print("VirusTotal API Scanner")
    print("="*60)
    print("\nДобро пожаловать! Программа для работы с VirusTotal API")
    
    try:
        # Запускаем интерактивный режим
        interactive_mode()
        
    except KeyboardInterrupt:
        print("\n\n[INFO] Программа прервана пользователем")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] Непредвиденная ошибка: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
