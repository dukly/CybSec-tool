import re
from collections import defaultdict

def analyze_log(log_file):
    # Паттерны для детекции атак
    patterns = {
        'SQL Injection': r"('|\"|%27|%22|UNION\s+SELECT|DROP\s+TABLE)",
        'XSS Attack': r"(<script|alert\(|onerror=|onload=)",
        'Path Traversal': r"(\.\./|\.\.\\|/etc/passwd)",
        'Scanner Detection': r"(sqlmap|nmap|nikto|wpscan)"
    }
    
    suspicious_requests = defaultdict(list)
    
    try:
        with open(log_file, 'r') as file:
            for line in file:
                for attack_type, pattern in patterns.items():
                    if re.search(pattern, line, re.IGNORECASE):
                        suspicious_requests[attack_type].append(line.strip())
    
        # Сохранение результатов
        with open('suspicious_requests.txt', 'w') as output:
            for attack_type, requests in suspicious_requests.items():
                output.write(f"=== {attack_type} ===\n")
                output.write("\n".join(requests) + "\n\n")
        
        print(f"Анализ завершён. Результаты сохранены в 'suspicious_requests.txt'.")
    
    except FileNotFoundError:
        print(f"Ошибка: файл '{log_file}' не найден.")

if __name__ == "__main__":
    log_file = input("Введите путь к файлу логов (например, access.log): ")
    analyze_log(log_file)