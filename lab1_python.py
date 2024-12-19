import re
import json
import csv
from collections import Counter

# Log faylını oxumaq
log_file = r"C:\Users\User\Desktop\python\server_logs.txt"

with open(log_file, "r") as file:
    log_data = file.read()

# Regex ilə IP ünvanlarını, tarixləri və HTTP metodlarını çıxarmaq
pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<date>\d+/[A-Za-z]+/\d+:\d+:\d+:\d+ [+-]\d+)\] \"(?P<method>\w+)'
matches = re.finditer(pattern, log_data)

# Çıxarılan məlumatlar üçün siyahı
extracted_data = []
failed_attempts = Counter()

for match in matches:
    ip = match.group("ip")
    date = match.group("date")
    method = match.group("method")

    extracted_data.append({"ip": ip, "date": date, "method": method})

    # Uğursuz giriş cəhdlərini saymaq
    if '401' in match.string[match.end():]:
        failed_attempts[ip] += 1

# 5-dən çox uğursuz giriş edən IP-ləri müəyyənləşdirmək
suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count > 5}

# JSON fayllarını yaratmaq
with open(r"C:\Users\User\Desktop\python\failed_logins.json", "w") as json_file:
    json.dump(suspicious_ips, json_file, indent=4)

# Şübhəli IP ünvanları (təhdid kəşfiyyatında olanlar üçün)
threat_intel_ips = ["192.168.1.11", "10.0.0.15"]  # Misal üçün təhdid kəşfiyyatı məlumatları
matching_ips = {ip: suspicious_ips[ip] for ip in suspicious_ips if ip in threat_intel_ips}

with open(r"C:\Users\User\Desktop\python\threat_ips.json", "w") as json_file:
    json.dump(matching_ips, json_file, indent=4)

# Uğursuz girişləri və təhdid IP-lərini birləşdirmək
combined_data = {"failed_logins": suspicious_ips, "threat_matches": matching_ips}
with open(r"C:\Users\User\Desktop\python\combined_security_data.json", "w") as json_file:
    json.dump(combined_data, json_file, indent=4)

# Log analizi mətn faylı
with open(r"C:\Users\User\Desktop\python\log_analysis.txt", "w") as txt_file:
    for ip, count in suspicious_ips.items():
        txt_file.write(f"IP: {ip}, Failed Attempts: {count}\n")

# CSV faylı yaratmaq
with open(r"C:\Users\User\Desktop\python\log_analysis.csv", "w", newline="") as csv_file:
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(["IP Address", "Date", "HTTP Method", "Failed Attempts"])
    for data in extracted_data:
        ip = data["ip"]
        date = data["date"]
        method = data["method"]
        failed_count = failed_attempts.get(ip, 0)
        csv_writer.writerow([ip, date, method, failed_count])

print("Bütün məlumatlar emal edildi və fayllara yazıldı.")

if __name__ == "__main__":
    print("Kod başqa faylı import etmədən icra edilib.")
else:
    print("Kod başqa faylı import edərək icra edilib.")
