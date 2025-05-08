# SMB * AutoEnum 

#### Features
1. Check Dependencies
2. Live host discovery in subnet
3. Scan open SMB Fileshares on default ports (139, 445)
4. Enumerate all accessible file shares
5. Download directory files recursively in to the local directory
6. Search for sensitive contents from the dumped data (to be completed)
7. Generate reports up on extracting sensitive contents (to be completed)

#### Dependencies
1. Nmap
```sh
sudo apt install nmap
```

2. Impacket
```sh
sudo apt install python3-impacket
```

#### Command to run
```python
python smb_autoenum.py
```

#### Script in Action ()
File repository in Linux attacker machine

![File repository](Attachments/Pasted%20image%2020250508152704.png)

Execution
![Execution](Attachments/Pasted%20image%2020250508153048.png)

SMB_Loot folder in directory
![SMB_Loot folder](Attachments/Pasted%20image%2020250508153156.png)

Contents in loot directory
![Contents in loot directory](Attachments/Pasted%20image%2020250508153347.png)

#### Deployable Environments
1. Linux (running fine as of now)
2. Windows (need some tweaks and modifications, facing dependency issues)

#### Development Environment
1. Dev Machine - Kali Linux in VMWare 
2. Attacker Machine - Kali Linux in VMWare 
3. Dev Environment - Vim Editor with Python 3.11.9
4. Target Host - [TryHackMe Lab Machine for SMB Enumeration](https://tryhackme.com/room/networkservices)
#### Limitations
1. Modify script to work in windows attack host
2. Remove dependencies and code from scratch as much as possible
3. Implement auto subnet scanning(Optional)
4. Complete sensitive content extraction module
5. Complete reporting module