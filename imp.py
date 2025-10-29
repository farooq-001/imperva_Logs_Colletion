import configparser
import requests
from requests.auth import HTTPBasicAuth
import getpass
import os
import zlib
import sys
from pathlib import Path
import re
import socket
import logging
import traceback

PROCESSED_RECORD = "processed_logs.txt"
OUTPUT_FOLDER = "imperva_logs"
MAX_FILES = 25

TCP_IP = "127.0.0.1"
TCP_PORT = 12228

def get_config():
    config = configparser.ConfigParser()
    config.read("credentials.conf")
    if "Imperva" not in config:
        print("No [Imperva] section in credentials.conf.")
        sys.exit(1)
    section = config["Imperva"]
    log_server_uri = section.get("log_server_uri") or input("Enter Log Server URI: ").strip()
    api_id = section.get("api_id") or input("Enter API ID: ").strip()
    api_key = section.get("api_key") or getpass.getpass("Enter API Key (input hidden): ").strip()
    return log_server_uri, api_id, api_key

def decompress_log_file(file_content):
    parts = file_content.split(b'|==|', 1)
    if len(parts) != 2:
        print("Separator |==| not found, skipping file.")
        return None
    header, compressed_content = parts
    compressed_content = compressed_content.strip()
    try:
        decompressed = zlib.decompress(compressed_content)
    except Exception as e:
        print(f"Failed to decompress: {e}")
        return None
    return decompressed

def extract_log_number(log_name):
    match = re.search(r'_(\d+)\.log$', log_name)
    return int(match.group(1)) if match else -1

def load_processed_logs():
    if not os.path.exists(PROCESSED_RECORD):
        return []
    with open(PROCESSED_RECORD, "r") as f:
        lines = [line.strip() for line in f if line.strip()]
    processed = [line if line.endswith(".log") else line + ".log" for line in lines]
    seen = set()
    unique_logs = []
    for p in processed:
        if p not in seen:
            unique_logs.append(p)
            seen.add(p)
    unique_logs.sort(key=extract_log_number)
    return unique_logs[-MAX_FILES:]

def save_processed_logs(log_filenames):
    seen = set()
    unique_logs = []
    for lf in log_filenames[-MAX_FILES:]:
        if not lf.endswith(".log"):
            lf = lf + ".log"
        if lf not in seen:
            unique_logs.append(lf)
            seen.add(lf)
    unique_logs.sort(key=extract_log_number)
    with open(PROCESSED_RECORD, "w") as f:
        for lf in unique_logs[-MAX_FILES:]:
            f.write(lf + "\n")

def maintain_latest_logs_folder():
    folder_path = Path(OUTPUT_FOLDER)
    log_files = sorted(folder_path.glob("*.log"), key=lambda f: f.stat().st_mtime, reverse=True)
    for old_file in log_files[MAX_FILES:]:
        try:
            old_file.unlink()
            print(f"Deleted old log file: {old_file.name}")
        except Exception as e:
            print(f"Failed to delete {old_file.name}: {e}")

def get_max_processed_log_number(processed_logs):
    if not processed_logs:
        return -1
    return max(extract_log_number(log) for log in processed_logs)

def send_log_tcp(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((TCP_IP, TCP_PORT))
            sock.sendall(data)
        print(f"Sent {file_path} to {TCP_IP}:{TCP_PORT}")
    except Exception as e:
        print(f"Failed to send {file_path} over TCP: {e}")

def main():
    log_server_uri, api_id, api_key = get_config()
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)

    processed_logs = load_processed_logs()
    processed_logs_set = set(processed_logs)
    max_processed_num = get_max_processed_log_number(processed_logs)

    index_url = f"{log_server_uri}/logs.index"
    print(f"Fetching logs index from: {index_url}")
    response = requests.get(index_url, auth=HTTPBasicAuth(api_id, api_key))
    if response.status_code != 200:
        print(f"Failed to fetch logs.index, status code: {response.status_code}")
        sys.exit(1)
    logs_index = response.text.splitlines()
    print(f"Found {len(logs_index)} log files in index.")

    for log_file in logs_index:
        log_file = log_file.strip()
        if not log_file:
            continue
        log_file_name = log_file if log_file.endswith(".log") else log_file + ".log"
        log_num = extract_log_number(log_file_name)
        if log_file_name in processed_logs_set or log_num <= max_processed_num:
            print(f"Skipping already processed or older log: {log_file_name}")
            continue
        print(f"\nProcessing {log_file_name}...")
        file_url = f"{log_server_uri}/{log_file}"
        r = requests.get(file_url, auth=HTTPBasicAuth(api_id, api_key))
        if r.status_code != 200:
            print(f"Failed to download {log_file_name}, status code: {r.status_code}")
            continue
        decompressed_content = decompress_log_file(r.content)
        if decompressed_content is None:
            continue
        output_path = os.path.join(OUTPUT_FOLDER, log_file_name)
        with open(output_path, "wb") as f:
            f.write(decompressed_content)
        print(f"Saved decompressed log to: {output_path}")

        # Send log file over TCP
        send_log_tcp(output_path)

        processed_logs.append(log_file_name)
        processed_logs_set.add(log_file_name)
        processed_logs = list(dict.fromkeys(processed_logs))
        processed_logs.sort(key=extract_log_number)
        processed_logs = processed_logs[-MAX_FILES:]
        save_processed_logs(processed_logs)
        maintain_latest_logs_folder()

    print("\nAll logs processed and sent over TCP.")

if __name__ == "__main__":
    main()

