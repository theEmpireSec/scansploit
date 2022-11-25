import os
import sys
from colorama import Fore
os.system("clear")
banner = Fore.MAGENTA + """
   _____    ______   ___       _   __   _____    ____     __       ____     ____   ______
  / ___/   / ____/  /   |     / | / /  / ___/   / __ \   / /      / __ \   /  _/  /_  __/
  \__ \   / /      / /| |    /  |/ /   \__ \   / /_/ /  / /      / / / /   / /     / /   
 ___/ /  / /___   / ___ |   / /|  /   ___/ /  / ____/  / /___   / /_/ /  _/ /     / /    
/____/   \____/  /_/  |_|  /_/ |_/   /____/  /_/      /_____/   \____/  /___/    /_/     
                                                                                         
Author    : king
Instagram : @empiresec
GitHub    : theEmpireSec
blogspot  : www.empiresec.blogspot.com

"""

print(banner)

targets = []
scan_list = ["custom port scan","open port scan","list interfaces","slow scan","fin scan","full scan","check for firewall","ping through firewall","fast scan","detect version","check for vulnerabilities","full udp scan","traceroute","full scan with script","web safe scan","ping scan"]
target = ""
sport = 0
eport = 0

usage = Fore.GREEN+"""
help                                         shows this help menu
add target                                   add target to list 
show targets                                 show targets 
set portrange <start_port> <end _port>       set port range 
set target <id>                              set target to perform recon
show args                                    show all arguments 
set scan <id> or <name>                      set scan to perform
show scans                                   show available scans 

"""

path = "/home/king/.scans"
if os.path.exists(path) == False:
    print(Fore.YELLOW + "[+] Making output directory ~/.scans")
    os.system("mkdir -p ~/.scans")

def select_scan(sscan):
    output = " -oN ~/.scans/" + str(target) + ".txt"
    if sscan == "0" or sscan == "custom port scan":
        os.system("nmap -p" + str(sport) + " " + str(eport) + " -oN ~/.scans/" + str(target) + ".txt")
    elif sscan == "1" or sscan == "open port scan":
        os.system("nmap --open " + target + output)
    elif sscan == "2" or sscan == "list interfaces":
        os.system("nmap --iflist")
    elif sscan == "3" or sscan == "slow scan":
        os.system("sudo nmap -sS -v -T1 " + target + output)
    elif sscan == "4" or sscan == "fin scan":
        os.system("sudo nmap -sF -v " + target + output)
    elif sscan == "5" or sscan == "full scan":
        os.system("sudo nmap -sS -T4 -PE -PP -PS80,443 -PY -g 53 -A -p1-65535 -v " + target + output)
    elif sscan == "6" or sscan == "check for firewall":
        os.system("sudo nmap -sA -p1-65535 -v -T4 " + target + output)
    elif sscan == "7" or sscan == "ping through firewall":
        os.system("nmap -PS -PA " + target + output)
    elif sscan == "8" or sscan == "fast scan":
        os.system("nmap -F -T5 --version-light --top-ports 300 " + target + output)
    elif sscan == "9" or sscan == "detect version":
        os.system("sudo nmap -sV -p1-65535 -O --osscan-guess -T4 -Pn " + target + output)
    elif sscan == "10" or sscan == "check for vulnerabilities":
        os.system("nmap --script=vuln " + target + output)
    elif sscan == "11" or sscan == "full udp scan":
        os.system("sudo nmap -sS -sU -T4 -A -v -PE -PS22,25,80 -PA21,23,80,443,3389 " + target + output)
    elif sscan == "12" or sscan == "traceroute":
        os.system("sudo nmap -sP -PE -PS22,25,80 -PA21,23,80,3389 -PU -PO --traceroute " + target + output)
    elif sscan == "13" or sscan == "full scan with script":
        os.system("sudo nmap -sS -sU -T4 -A -v -PE -PP -PS21,22,23,25,80,113,31339 -PA80,113,443,10042 -PO --script all " + target + output)
    elif sscan == "14" or sscan == "web safe scan":
        os.system("sudo nmap -p 80,443 -O -v --osscan-guess --fuzzy " + target + output)
    elif sscan == "15" or sscan == "ping scan":
        os.system("nmap -n -sP " + target + output)
    else:
        print(Fore.RED+"[!] Invalid scan selected ")
    print(Fore.CYAN + "[*] OUTPUT PATH : ~/.scans")




    




while True:
    scansploit = input(Fore.MAGENTA + "scansploit> " + Fore.CYAN)
    if scansploit == "q" or scansploit == "quit":
        break
    elif scansploit == "help":
        print(usage)
    elif scansploit == "":
        continue
    elif "add target" in scansploit:
        scansploit = scansploit.split()
        targets.append(scansploit[2])
    elif scansploit == "clear" or scansploit == "cl":
        os.system("clear")
    elif scansploit == "show targets":
        print(Fore.CYAN + "----------(TARGETS)----------")
        print("ID   ADDRESS/DOMAIN")
        j = 0
        for i in targets:
            print(f"[{j}]   {i}")
            j = j + 1
    elif "set target" in scansploit:
        scansploit = scansploit.split()
        target = scansploit[-1]
        target = targets[0]
    elif "set portrange" in scansploit:
        scansploit = scansploit.split()
        sport = int(scansploit[2])
        eport = int(scansploit[3])
    elif scansploit == "show args":
        print(Fore.GREEN + f"[+] TARGET     : {target}")
        print(f"[+] START PORT : {sport}")
        print(f"[+] END PORT   : {eport}")
    elif scansploit == "show scans":
        i = 0
        for scan in scan_list:
            print(Fore.CYAN + f"[+] {i} {scan}")
            i = i + 1
    elif "set scan" in scansploit:
        scansploit = scansploit.split()[-1]
        select_scan(scansploit)
    else:
        print(Fore.RED + "[!] Invalid commad")



print(Fore.RESET)




