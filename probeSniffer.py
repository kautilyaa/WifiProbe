#!/usr/bin/env python3
# -.- coding: utf-8 -.-

try:
    import os
    import sys
    import time
    import json
    import pyshark
    import datetime
    import argparse
    import threading
    import traceback
    import urllib.request as urllib2
except KeyboardInterrupt:
    print("\n[I] Stopping...")
    raise SystemExit
except:
    print("[!] Failed to import the dependencies... " +\
            "Please make sure to install all of the requirements " +\
            "and try again.")
    raise SystemExit

parser = argparse.ArgumentParser(
    usage="probeSniffer.py [monitor-mode-interface] [options]")
parser.add_argument(
    "interface", help='interface (in monitor mode) for capturing the packets')
parser.add_argument("-b", action='store_true',
                    help='do not show \'broadcast\' requests (without ssid)')
parser.add_argument("--addnicks", action='store_true',
                    help='add nicknames to mac addresses')
parser.add_argument('--noresolve', action='store_true',
                    help="skip resolving mac address")

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)
args = parser.parse_args()
showBroadcasts = not args.b
addNicks = args.addnicks
noresolve = args.noresolve

monitor_iface = args.interface
alreadyStopping = False

# Dictionary containing known MAC (Nicknames)
try:
	with open('nicknames.json') as f:
		MacNicknames = json.loads(f.read())
except:
	MacNicknames = {}



def restart_line():
    sys.stdout.write('\r')
    sys.stdout.flush()


def statusWidget(devices):
    sys.stdout.write("Devices found: [" + str(devices) + "]")
    restart_line()
    sys.stdout.flush()
    #print("Devices found: [" + str(devices) + "]")

print("[W] Make sure to use an interface in monitor mode!\n")

devices = []
script_path = os.path.dirname(os.path.realpath(__file__))
script_path = script_path + "/"

externalOptionsSet = False
if not showBroadcasts:
    externalOptionsSet = True
    print("[I] Not showing broadcasts...")
if noresolve:
    externalOptionsSet = True
    print("[I] Not resolving MAC addresses...")

if externalOptionsSet:
    print()

print("[I] Loading MAC database...")

# Loading MAC manufacturers list
with open(script_path + "oui.json", 'r') as content_file:
    obj = content_file.read()
resolveObj = json.loads(obj)

def stop():
    global alreadyStopping
    if not alreadyStopping:
        alreadyStopping = True
        print("\n[I] Stopping...")
        print("[I] probeSniffer stopped.")
        raise SystemExit



# Hopping in different frequencies
def chopping():
    while True:
        if not alreadyStopping:
            channels = [1, 6, 11]
            for channel in channels:
                os.system("iwconfig " + monitor_iface + " channel " +
                          str(channel) + " > /dev/null 2>&1")
                time.sleep(3)
        else:
            sys.exit()

def resolveMac(mac):
    try:
        global resolveObj
        for macArray in resolveObj:
            if macArray[0] == mac[:8].upper():
                return macArray[1]
        return "NOT IN DATABASE"
    except:
        return "NOT IN DATABASE"

# Colors
class bcolors:
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    OKGREEN = '\033[92m'
    OKBLUE = '\033[94m'
    WARNING = '\033[93m'

# Storing devices in disk
def storeDevice(device):
    with open('devices.list', 'a+') as f:
        f.write(device.lower() + '\n')

def packetHandler(pkt):
    statusWidget(len(devices))

    if "wlan_mgt" in pkt:
        nossid = False
        if not str(pkt.wlan_mgt.tag)[:34] == "Tag: SSID parameter set: Broadcast":
            ssid = pkt.wlan_mgt.ssid
        else:
            nossid = True
    else:
        nossid = False
        if not str(pkt[3].tag)[:34] == "Tag: SSID parameter set: Broadcast":
            ssid = pkt[3].ssid
        else:
            nossid = True


    rssi_val = pkt.radiotap.dbm_antsignal
    mac_address = pkt.wlan.ta
    bssid = pkt.wlan.da

    if not noresolve:
        vendor = resolveMac(mac_address)
        p_vendor = '(' + vendor + ')'
    else:
        vendor = "RESOLVE-OFF"
        p_vendor = ''

    
    inDevices = False
    for device in devices:
        if device == mac_address:
            inDevices = True
    if not inDevices:
        devices.append(mac_address)
        storeDevice(mac_address)
    nickname = getNickname(mac_address)

    p_nickname = bcolors.WARNING + '[NON-MEMBER]' + bcolors.ENDC
    if (nickname):
        p_nickname = bcolors.OKGREEN + '[' + nickname + ']' + bcolors.ENDC

    if not nossid:
        print(mac_address + " " + p_nickname + " " + p_vendor + " ==> '" + ssid + "'" + (" [BSSID: " + str(bssid) + "]" if not bssid == "ff:ff:ff:ff:ff:ff" else ""))

    else:
        if showBroadcasts:
            print(mac_address + (" [" + str(nickname) + "]" if nickname else "") + " " + p_vendor + " ==> BROADCAST" + (" [BSSID: " + str(bssid) + "]" if not bssid == "ff:ff:ff:ff:ff:ff" else ""))
    statusWidget(len(devices))


def setNickname(mac, nickname):
    MacNicknames[mac.lower()] = nickname
    with open('nicknames.json', 'w+') as f:
        json.dump(MacNicknames, f)


def getNickname(mac):
    try:
        return MacNicknames[mac.lower()]
    except:
        return False


def main():
    global alreadyStopping

    if addNicks:
        print("\n[NICKNAMES] Add nicknames to mac addresses.")
        while True:
            print()
            mac = input("[?] Mac address: ")
            if mac == "":
                print("[!] Please enter a mac address.")
                continue
            nick = input("[?] Nickname for mac '" + str(mac) + "': ")
            if nick == "":
                print("[!] Please enter a nickname.")
                continue
            setNickname(mac, nick)
            addAnother = input("[?] Add another nickname? Y/n: ")
            if addAnother.lower() == "y" or addAnother == "":
                pass
            else:
                break

    print("[I] Starting channelhopper in a new thread...")
    path = os.path.realpath(__file__)
    chopper = threading.Thread(target=chopping)
    chopper.daemon = True
    chopper.start()

    # Clear Device list
    with open('devices.list', 'w+') as f:
        print("[I] Nearby devices will be stored in devices.list")

    print("\n[I] Sniffing started... Please wait for requests to show up...\n")
    statusWidget(len(devices))

    while True:
        try:
            capture = pyshark.LiveCapture(interface=monitor_iface, bpf_filter='type mgt subtype probe-req')
            capture.apply_on_packets(packetHandler)
        except KeyboardInterrupt:
            stop()
        except:
            print("[!] An error occurred. Debug:")
            print(traceback.format_exc())
            print("[!] Restarting in 5 sec... Press CTRL + C to stop.")
            try:
                time.sleep(5)
            except:
                stop()

if __name__ == "__main__":
    main()
