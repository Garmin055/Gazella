import requests

# .onion 주소
onion_address = 'aywyfbvfylb3fjtzpxdpyvvrigpgewo76cb6k5w6zhbcfkdub4nnpiid.onion'
url = f'http://{onion_address}/data'
data = {'key': 'value'}

# SOCKS5 프록시
proxies = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

try:
    response = requests.post(url, json=data, proxies=proxies)
    print(response.text)
except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")
