
# imports

import socket
import os
import psutil               # needs pip
import time
import platform             # needs pip
import sys
import curses               # needs pip
import socket
import datetime         
import GPUtil               # needs pip
import shutil               # needs pip
import fnmatch              # needs pip
import re
import subprocess           # needs pip
import multiprocessing
import json
import base64
import nmap                 # needs pip
import sqlite3              # needs pip
import win32crypt           # needs pip
import uuid
import whois                # needs pip
import getpass
import speedtest            # needs pip
import webbrowser
from colorama import Fore, Back, Style, init    # needs pip
init()                                          # colorama stuff
from Crypto.Cipher import AES   # needs pip
from urllib.request import urlopen  # needs pip
from os.path import isfile, join
from os import listdir
from requests import get
from tabulate import tabulate       # needs pip
from time import sleep
from datetime import datetime, timezone, timedelta, date
from os import system, name
from subprocess import call

# variables

uname = platform.uname()
cpufreq = psutil.cpu_freq()
net_io = psutil.net_io_counters()
disk_io = psutil.disk_io_counters()
swap = psutil.swap_memory()
svmem = psutil.virtual_memory()
now = datetime.now()
if_addrs = psutil.net_if_addrs()
host_name = socket.gethostname()
host_ip = socket.gethostbyname(host_name)
gpus = GPUtil.getGPUs()
total, used, free = shutil.disk_usage("/")
ip = get('https://api.ipify.org').text
dirName = 'c:\\'
Data = subprocess.check_output(['wmic', 'process', 'list', 'brief'])
a = str(Data)
boot_time_timestamp = psutil.boot_time()
bt = datetime.fromtimestamp(boot_time_timestamp)
s = speedtest.Speedtest()
closest_servers = s.get_closest_servers()
weekNumber = date.today().isocalendar()[1]
currentdir = os.getcwd()
appid = os.getpid()


# functions

def get_size(bytes, suffix="B"):
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < factor:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= factor

def osinfo():
    print("System Informations")
    print(" ")
    print("User Account Name: ", getpass.getuser())
    print("Current Directory: ", currentdir)
    print("Process ID: ", appid)
    print(f"System: {uname.system}")
    print(f"Node Name: {uname.node}")
    print(f"Release: {uname.release}")
    print(f"Version: {uname.version}")
    print(f"Machine: {uname.machine}")
    print(f"Processor: {uname.processor}")
    print(" ")
    print("--------------------------------------------")
    print(" ")
    print("Platform Informations")
    print(" ")
    print('Normal :', platform.platform())
    print('Aliased:', platform.platform(aliased=True))
    print('Terse  :', platform.platform(terse=True))
    print("Hardware-type identifyer :", uname.machine) # not str callable !!!!
    print("For Specs Informations Type 'pcs info' ")
    time.sleep(1)
    start()

def cpuinfo():
    print("Cpu Informations")
    print(" ")
    print("Physical cores:", psutil.cpu_count(logical=False))
    print("Total cores:", psutil.cpu_count(logical=True))
    print(f"Max Frequency: {cpufreq.max:.2f}Mhz")
    print(f"Min Frequency: {cpufreq.min:.2f}Mhz")
    print(f"Current Frequency: {cpufreq.current:.2f}Mhz")
    time.sleep(1)
    start()

def ioinfo():
    print("Total Data send / recieved since boot")
    print("---------------------------------------------------")
    print(f"Total Bytes Sent: {get_size(net_io.bytes_sent)}")
    print(f"Total Bytes Received: {get_size(net_io.bytes_recv)}")
    print(" ")
    print("Total Data read / wrote since boot")
    print("---------------------------------------------------")
    print(f"Total read: {get_size(disk_io.read_bytes)}")
    print(f"Total write: {get_size(disk_io.write_bytes)}")
    time.sleep(1)
    start()

def raminfo():
    print("Random Application Memory Informations")
    print(" ")
    print(f"Total: {get_size(svmem.total)}")
    print(f"Available: {get_size(svmem.available)}")
    print(f"Used: {get_size(svmem.used)}")
    print(f"Percentage: {svmem.percent}%")
    time.sleep(1)
    start()

def info():
    print("Programm Information")
    time.sleep(1)
    print(" ")
    print("Version = 0.1")
    print("Creator = Lucas Bencych")
    print("Made in Python 3.8.5 32-bit")
    print(""""For used imports use "import info" """)
    time.sleep(1)
    start()

def importinfo():
    print("""
    Used Imports:

import socket
import os
import psutil               # needs pip
import time
import platform
import sys
import curses               # needs pip
import socket
import datetime         
import GPUtil               # needs pip
import shutil               # needs pip
import fnmatch              # needs pip
import re
import subprocess           # needs pip
import multiprocessing
import nmap                 # needs pip
import json
import base64
import sqlite3              # needs pip
import win32crypt           # needs pip
import shutil               # needs pip
import uuid
import pyqrcode             # needs pip
import wifi_qrcode_generator   # needs pip
import png                  # needs pip
import whois                # needs pip
import getpass
import speedtest            # needs pip
import webbrowser
from colorama import Fore, Back, Style, init    # needs pip
init()                                          # colorama stuff
from Crypto.Cipher import AES   # needs pip
from urllib.request import urlopen  # needs pip
from os.path import isfile, join
from os import listdir
from requests import get
from tabulate import tabulate       # needs pip
from time import sleep
from datetime import datetime, timezone, timedelta, date
from os import system, name
from subprocess import call

    """)
    time.sleep(1)
    start()

def currentworld():
    print("System Time = ", datetime.today().strftime("%c"))
    print(" ")
    print ('Week number:', weekNumber)
    time.sleep(1)
    start()

def netinfoall():
    for interface_name, interface_addresses in if_addrs.items():
        for address in interface_addresses:
            print(f"=== Interface: {interface_name} ===")
            if str(address.family) == 'AddressFamily.AF_INET':
                print(f"  IP Address: {address.address}")
                print(f"  Netmask: {address.netmask}")
                print(f"  Broadcast IP: {address.broadcast}")
            elif str(address.family) == 'AddressFamily.AF_PACKET':
                print(f"  MAC Address: {address.address}")
                print(f"  Netmask: {address.netmask}")
                print(f"  Broadcast MAC: {address.broadcast}")
    time.sleep(1)
    start()

def netinfo():
    print("Domain Host Name = ", socket.getfqdn())
    print("Local IP = ", host_ip)
    print('Public IP = ', ip)
    time.sleep(1)
    start()

def gpuinfo():
    print("="*40, "GPU Details", "="*40)
    list_gpus = []
    for gpu in gpus:
        # get the GPU id
        gpu_id = gpu.id
        # name of GPU
        gpu_name = gpu.name
        # get % percentage of GPU usage of that GPU
        gpu_load = f"{gpu.load*100}%"
        # get free memory in MB format
        gpu_free_memory = f"{gpu.memoryFree}MB"
        # get used memory
        gpu_used_memory = f"{gpu.memoryUsed}MB"
        # get total memory
        gpu_total_memory = f"{gpu.memoryTotal}MB"
        # get GPU temperature in Celsius
        gpu_temperature = f"{gpu.temperature} °C"
        gpu_uuid = gpu.uuid
        list_gpus.append((
            gpu_id, gpu_name, gpu_load, gpu_free_memory, gpu_used_memory,
            gpu_total_memory, gpu_temperature, gpu_uuid
    ))

    print(tabulate(list_gpus, headers=("id", "name", "load", "free memory", "used memory", "total memory",
                                    "temperature", "uuid")))
    time.sleep(1)
    start()

def pcsinfo():
    print("""

    CPU Info = 'cpu'
    RAM Info = 'ram'
    GPU Info = 'gpu'
    
    """)
    time.sleep(1)
    start()

def storage():
    print("Main Storage / OS Installation")
    print(" ")
    print("Total: %d GiB" % (total // (2**30)))
    print("Used: %d GiB" % (used // (2**30)))
    print("Free: %d GiB" % (free // (2**30)))
    time.sleep(1)
    start()

def tasklist():
    def getListOfProcessSortedByMemory():
        listOfProcObjects = []
        # Iterate over the list
        for proc in psutil.process_iter():
            try:
            # Fetch process details as dict
                pinfo = proc.as_dict(attrs=['pid', 'name', 'username'])
                pinfo['vms'] = proc.memory_info().vms / (1024 * 1024)
                # Append dict to list
                listOfProcObjects.append(pinfo)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
            # Sort list of dict by key vms i.e. memory usage
        listOfProcObjects = sorted(listOfProcObjects, key=lambda procObj: procObj['vms'], reverse=True)
        return listOfProcObjects
    def main():
        print("*** Iterate over all running process and print process ID & Name ***")
        # Iterate over all running process
        for proc in psutil.process_iter():
            try:
                # Get process name & pid from process object.
                processName = proc.name()
                processID = proc.pid
                print(processName , ' ::: ', processID)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        print('*** Create a list of all running processes ***')
        listOfProcessNames = list()
        # Iterate over all running processes
        for proc in psutil.process_iter():
            # Get process detail as dictionary
            pInfoDict = proc.as_dict(attrs=['pid', 'name', 'cpu_percent'])
            # Append dict of process detail in list
            listOfProcessNames.append(pInfoDict)
        # Iterate over the list of dictionary and print each elem
        for elem in listOfProcessNames:
            print(elem)
        print('*** Top 5 process with highest memory usage ***')
        listOfRunningProcess = getListOfProcessSortedByMemory()
        for elem in listOfRunningProcess[:5] :
            print(elem)
    if __name__ == '__main__':
        main()
    time.sleep(1)
    start()

def iplookup():
    k = input(" IP to Domain 'ipdomain' \n Domain to IP 'domainip' ")
    if k == ("domainip"):
        p = input("Enter Domain : ")
        print (socket.gethostbyname(p))
        time.sleep(0.5)
        i = input("Again ? 'y' 'n' : ")
        if i == "y":
            iplookup()
        if i == "n":
            start()
        else:
            print("Invalid returning")
            start()
    if k == ("ipdomain"):
        p = input("Enter IP : ")
        print (socket.getfqdn(p))
        i = input("Again ? 'y' 'n' : ")
        if i == "y":
            iplookup()
        if i == "n":
            start()
        else:
            print("Invalid returning")
            start()

def webopen():
    print("Will get the Source code of the Website 1:1")
    print(" ")
    i = input("Enter Web Url : ")
    html = urlopen(i)
    print(html.read())
    time.sleep(1)
    start()

def portscann():
    print("Will scann port 21 - 443")
    time.sleep(1)
    print("Scann cannot get stopped,  stop programm by Typing 'CTRL + C' ")
    begin = 21
    end = 443
    target = '127.0.0.1'
    scanner = nmap.PortScanner()
    for i in range(begin,end+1):
        res = scanner.scan(target,str(i))
        res = res['scan'][target]['tcp'][i]['state']
        print(f'port {i} is {res}.')
    time.sleep(1)
    start()


def helpcmd():
    print("""
      ----------- System -----------

    pc              Simple Informations of the pc
    cpu             outputs cpu informations
    io              outputs io informations
    ram             outputs ram informations
    gpu             outputs gpu informations
    storage         outputs storage informations
    tasklist        outputs running tasks informations
    time            outputs the system time
    boot info       outputs boot informations
    pyinfo         outputs python information

      ----------- Network -----------

    net             outputs basic ip informations
    net all         outputs all network informations
    iplookup        outputs terminal for ip / domain tools
    portscann       outputs a small port scanner for the local ip range
    get mac         outputs the mac adress of the computer


      ----------- Exploit -----------

    google pass    outputs google chrome stored passwords ( bypass the password if set )
    wlan pass      outputs saved wlan passwords with SSID ( might don't work )


      ----------- Internet -----------

    webcode         outputs the source code of a website 1:1
    websearch       opens the given webiste url
    whois           give whois informations for a domain
    internet speed  outputs your download / upload speed


      ----------- Programm -----------

    info            outputs programm informations
    import info     outputs the used imports
    help            outputs this
    cls             clear all recent outputs

    exit            closes the programm 

      ----------- Unnecessary -----------

    pcs info        used in a function
    
    
    """)
    time.sleep(1)
    start()



def googlepass():
    def get_chrome_datetime(chromedate):
        return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)

    def get_encryption_key():
        local_state_path = os.path.join(os.environ["USERPROFILE"],
                                        "AppData", "Local", "Google", "Chrome",
                                        "User Data", "Local State")
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = f.read()
            local_state = json.loads(local_state)

    # decode the encryption key from Base64
        key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    # remove DPAPI str
        key = key[5:]
    # return decrypted key that was originally encrypted
    # using a session key derived from current user's logon credentials
    # doc: http://timgolden.me.uk/pywin32-docs/win32crypt.html
        return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

    def decrypt_password(password, key):
        try:
        # get the initialization vector
            iv = password[3:15]
            password = password[15:]
        # generate cipher
            cipher = AES.new(key, AES.MODE_GCM, iv)
        # decrypt password
            return cipher.decrypt(password)[:-16].decode()
        except:
            try:
                return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
            except:
            # not supported
                return ""
    def main():
    # get the AES key
        key = get_encryption_key()
    # local sqlite Chrome database path
        db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                                "Google", "Chrome", "User Data", "default", "Login Data")
    # copy the file to another location
    # as the database will be locked if chrome is currently running
        filename = "ChromeData.db"
        shutil.copyfile(db_path, filename)
    # connect to the database
        db = sqlite3.connect(filename)
        cursor = db.cursor()
    # `logins` table has the data we need
        cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
    # iterate over all rows
        for row in cursor.fetchall():
            origin_url = row[0]
            action_url = row[1]
            username = row[2]
            password = decrypt_password(row[3], key)
            date_created = row[4]
            date_last_used = row[5]        
            if username or password:
                print(f"Origin URL: {origin_url}")
                print(f"Action URL: {action_url}")
                print(f"Username: {username}")
                print(f"Password: {password}")
            else:
                continue
            if date_created != 86400000000 and date_created:
                print(f"Creation date: {str(get_chrome_datetime(date_created))}")
            if date_last_used != 86400000000 and date_last_used:
                print(f"Last Used: {str(get_chrome_datetime(date_last_used))}")
            print("="*50)
        cursor.close()
        db.close()
        try:
        # try to remove the copied db file
            os.remove(filename)
        except:
            pass
    if __name__ == "__main__":
        main()
    time.sleep(1)
    start()

def wlanpass():
    print("Might crash if feature is disabled")
    time.sleep(2)
    data = subprocess.check_output(['netsh','wlan','show','profiles']).decode('utf-8').split('\n')  # might give error
    profiles = [i.split(":")[1][1:-1] for i in data if "All User Profile" in i]
    for i in profiles:
        results = subprocess.check_output(['netsh','wlan','show','profiles',i,'key=clear']).decode('utf-8').split('\n')
        results = [b.split(":")[1][1:-1] for b in results if "Key Content" in b]
        try:
            print("{:<30}|   {:<}".format(i,results[0]))
        except IndexError:
            print(i,"Index Error")
    time.sleep(1)
    start()

def getmac():
    print ("MAC Adress : ", end="")
    print (':'.join(re.findall('..', '%012x' % uuid.getnode())))
    time.sleep(1)
    start()

def boot():
    print(f"Boot Time: {bt.year}/{bt.month}/{bt.day} {bt.hour}:{bt.minute}:{bt.second}")
    print(" ")
    print("For more bootrelated informations use 'io' ")
    time.sleep(1)
    start()

def whoisnet():
    def is_registered(domain_name):
        try:
            w = whois.whois(domain_name)
        except Exception:
            return False
        else:
            return bool(w.domain_name)


    domain_name = input("Enter Domain : ")
    if is_registered(domain_name):
        whois_info = whois.whois(domain_name)
    # print the registrar
        print("Domain registrar:", whois_info.registrar)
        print(" ")
    # print the WHOIS server
        print("WHOIS server:", whois_info.whois_server)
        print(" ")
    # get the creation time
        print("Domain creation date:", whois_info.creation_date)
        print(" ")
    # get expiration date
        print("Expiration date:", whois_info.expiration_date)
        print(" ")
    # print all other info
        print(whois_info)
    time.sleep(1)
    start()

def intspeed():
    print("Checking closest server")
    print(" ")
    for key, value in closest_servers[1].items():
        print(key, ' : ', value)
    # gets informations for the closest server
    print("This can take a bit of time")
    print(" ")
    time.sleep(0.2)
    print("Checking Download")
    print('My download speed is:', s.download())
    print(" ")
    print("Checking Upload")
    print('My upload speed is:', s.upload())
    time.sleep(1)
    start()

def websearch():
    url = input("Enter URL : ")
    webbrowser.open_new(url)

def startafterclear():
    print(Fore.LIGHTCYAN_EX + r" _          _ _       ")
    print(Fore.LIGHTCYAN_EX + r"| |        | | |      ")
    print(Fore.LIGHTCYAN_EX + r"| |__   ___| | | ___  ")
    print(Fore.LIGHTCYAN_EX + r"| '_ \ / _ \ | |/ _ \ ")
    print(Fore.LIGHTCYAN_EX + r"| | | |  __/ | | (_) |")
    print(Fore.LIGHTCYAN_EX + r"|_| |_|\___|_|_|\___/ ")
    print(Fore.LIGHTCYAN_EX + r"                      ")

    # now the start text for the beginning

    print(Fore.LIGHTRED_EX + "Python based Command Prompt [Version 0.1]")
    print(Fore.LIGHTRED_EX + "Copyright 2020, lubnc4261, All rights reserved.")
    print(Fore.LIGHTGREEN_EX + "---------------------------------------------------")
    print(Fore.GREEN + "type " + Fore.YELLOW + "'help'" + Fore.GREEN + " for all commands listed")
    print(Fore.GREEN + "type " + Fore.YELLOW + "'exit'" + Fore.GREEN + " to close the program")
    start()

def clear():
    os.system("cls")    # need to be changed for other os / os.system('clear')  # on linux / os x
    time.sleep(1)
    startafterclear()

def pyinfo():
    print ('Version      :', platform.python_version())
    print ('Version tuple:', platform.python_version_tuple())
    print ('Compiler     :', platform.python_compiler())
    print ('Build        :', platform.python_build())
    time.sleep(1)
    start()

# main process

def start():
    i = input(""" 
-->  """)
    print(" ")
    if i == ("pc"):     # done pc # 
        osinfo()
    if i == ("cpu"):    # done cpu # 
        cpuinfo()
    if i == ("io"):     # done io #
        ioinfo()
    if i == ("ram"):    # done ram #
        raminfo()
    if i == ("info"):   # done info
        info()
    if i == ("import info"):  # done import info
        importinfo()
    if i == ("time"):   # done time #
        currentworld()
    if i == ("net all"):  # done net all #
        netinfoall()
    if i == ("net"):    # done net
        netinfo()
    if i == ("gpu"):    # done gpu
        gpuinfo()
    if i == ("pcs info"):  # done pcs info
        pcsinfo()
    if i == ("storage"):  # done storage
        storage()
    if i == ("tasklist"):  # done tasklist
        tasklist()
    if i == ("iplookup"):  # done iplookup
        iplookup()
    if i == ("webcode"):  # done webcode
        webopen()
    if i == ("portscann"):  # done portscann
        portscann()
    if i == ("exit"):   # done exit
        exit()
    if i == ("help"):  # done help
        helpcmd()
    if i == ("google pass"): # done google pass
        googlepass()
    if i == ("wlan pass"): # done wlan pass
        wlanpass()
    if i == ("get mac"): # done get mac
        getmac()
    if i == ("boot info"): # done boot info
        boot()
    if i == ("whois"):  # done whois
        whoisnet()
    if i == ("int speed"): # done internet speed
        intspeed()
    if i == ("webopen"): # done webopen 
        websearch()
    if i == ("cls"): # done clear
        clear()
    if i == ("pyinfo"): # done pyinfo
        pyinfo()
    else:
        print("Command wrong or doesn't exist")
        start()

    # welcome logo 

print(Fore.LIGHTCYAN_EX + r" _          _ _       ")
print(Fore.LIGHTCYAN_EX + r"| |        | | |      ")
print(Fore.LIGHTCYAN_EX + r"| |__   ___| | | ___  ")
print(Fore.LIGHTCYAN_EX + r"| '_ \ / _ \ | |/ _ \ ")
print(Fore.LIGHTCYAN_EX + r"| | | |  __/ | | (_) |")
print(Fore.LIGHTCYAN_EX + r"|_| |_|\___|_|_|\___/ ")
print(Fore.LIGHTCYAN_EX + r"                      ")

    # now the start text for the beginning

print(Fore.LIGHTRED_EX + "Python based Command Prompt [Version 0.1]")
print(Fore.LIGHTRED_EX + "Copyright 2020, lubnc4261, All rights reserved.")
print(Fore.LIGHTGREEN_EX + "---------------------------------------------------")
print(Fore.GREEN + "type " + Fore.YELLOW + "'help'" + Fore.GREEN + " for all commands listed")
print(Fore.GREEN + "type " + Fore.YELLOW + "'exit'" + Fore.GREEN + " to close the program")
start()