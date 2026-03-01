import os
import sys
import requests
import argparse
from dotenv import load_dotenv

# Загружаем переменные окружения из файла .env
load_dotenv()

# Конфигурация
VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"

def check_vt_ip(ip_address):
    """
    Запрашивает информацию об IP из VirusTotal
    """
    if not VT_API_KEY:
        print("[!] Ошибка: API ключ VirusTotal не найден в .env файле")
        return None

    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    
    endpoint = f"/ip_addresses/{ip_address}"
    url = f"{VT_BASE_URL}{endpoint}"

    try:
        print(f"[*] Запрос к VirusTotal для IP: {ip_address}...")
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            print(f"[!] IP адрес {ip_address} не найден в базе VT.")
            return None
        elif response.status_code == 429:
            print("[!] Превышен лимит запросов (Rate Limit). Подождите минуту.")
            return None
        else:
            print(f"[!] Ошибка API: {response.status_code} - {response.text}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"[!] Ошибка сети: {e}")
        return None

def parse_report(data):
    """
    Извлекает важные данные из ответа VT для аналитика
    """
    # Исправлено: добавлено 'data' в конце условия
    if not data or 'data' not in data:
        return

    attributes = data['data']['attributes']
    last_analysis_stats = attributes.get('last_analysis_stats', {})
    
    # Извлекаем статистику детектов
    malicious = last_analysis_stats.get('malicious', 0)
    suspicious = last_analysis_stats.get('suspicious', 0)
    harmless = last_analysis_stats.get('harmless', 0)
    undetected = last_analysis_stats.get('undetected', 0)
    
    # Страна и провайдер
    country = attributes.get('country', 'N/A')
    asn = attributes.get('asn', 'N/A')
    as_owner = attributes.get('as_owner', 'N/A')
    
    # Вердикт
    verdict = "CLEAN"
    if malicious > 0:
        verdict = "MALICIOUS"
    elif suspicious > 0:
        verdict = "SUSPICIOUS"

    # Вывод отчета
    print("\n" + "="*40)
    print(f"ОТЧЕТ ПО IP: {data['data']['id']}")
    print("="*40)
    print(f"[+] Вердикт: {verdict}")
    print(f"[+] Статистика детектов:")
    print(f"    - Malicious:  {malicious}")
    print(f"    - Suspicious: {suspicious}")
    print(f"    - Harmless:   {harmless}")
    print(f"    - Undetected: {undetected}")
    print(f"[+] Геоданные:")
    print(f"    - Страна: {country}")
    print(f"    - ASN: {asn}")
    print(f"    - Провайдер: {as_owner}")
    
    # Ссылка на веб-интерфейс для быстрой проверки
    print(f"[+] Ссылка: https://www.virustotal.com/gui/ip-address/{data['data']['id']}")
    print("="*40 + "\n")

def main():
    # Настройка аргументов командной строки
    parser = argparse.ArgumentParser(description="SOC IOC Enrichment Tool (VirusTotal)")
    parser.add_argument("ioc", help="IP адрес для проверки")
    parser.add_argument("--type", choices=["ip", "domain", "hash"], default="ip", help="Тип индикатора (пока поддерживается только ip)")
    
    args = parser.parse_args()

    # Простая валидация IP (можно усложнить через regex)
    if args.type == "ip":
        parts = args.ioc.split('.')
        if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            print("[!] Неверный формат IP адреса.")
            sys.exit(1)

    # Запуск проверки
    report = check_vt_ip(args.ioc)
    
    if report:
        parse_report(report)
    else:
        print("[!] Не удалось получить отчет.")

if __name__ == "__main__":
    main()