import glob
import re
from colorama import init, Fore
init(autoreset=True)

def extract_ips(log):
    client_ip_match = re.search(r'Client_ip (\d+\.\d+\.\d+\.\d+)', log)
    source_ip_match = re.search(r'Source (\d+\.\d+\.\d+\.\d+)', log)
    username_match = re.search(r'Context ([\w.]+)@', log)

    client_ip = client_ip_match.group(1) if client_ip_match else None
    source_ip = source_ip_match.group(1) if source_ip_match else None
    username = username_match.group(1) if username_match else None

    return client_ip, source_ip, username

path = input("Enter ns.log path. (Usually /var/log) : ")

files_to_open = glob.glob(path + "/ns.log*")

files_content = ""

for files in files_to_open:
    with open(files, 'r') as file:
        content = file.read()
        files_content += content

logs = files_content.splitlines()

for log in logs:
    client_ip, source_ip, username = extract_ips(log)
    if client_ip and source_ip:
        if client_ip != source_ip:
            print(Fore.RED + f"IP mismatch showing potential exploitation of CitrixBleed (CVE-2023-4966) : Client_ip = {client_ip}, Source = {source_ip}, Username = {username}")
            print(Fore.BLUE + f"Log : {log}\n")
