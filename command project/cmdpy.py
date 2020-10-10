
# imports

import socket
import os
import psutil
import time
import platform
import sys
import curses
import datetime
import GPUtil
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

# from imports

from colorama import Fore, Back, Style, init
init()                                
from urllib.request import urlopen 
from os.path import isfile, join
from os import listdir
from requests import get
from tabulate import tabulate
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
    print("UUID ID: ",current_machine_id)   # only on Windows
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
    print("Version = 0.2")
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

def helpcmd():
    print("""
      ----------- System -----------

    pc              Simple Informations of the pc
    cpu             outputs cpu informations
    io              outputs io informations
    ram             outputs ram informations
    gpu             outputs gpu informations
    
    tree            Storage Dir Diagramm
    storage         outputs storage informations

    tasklist        outputs running tasks informations
    time            outputs the system time
    boot            outputs boot informations

    pyinfo          outputs python information


      ----------- Network -----------

    net             small overview of the IP
    net all         every network adapter informations
    iplookup        convert domain to ip or otherwise
    mac             shows used mac adress

      ----------- Internet -----------

    whois           give whois informations for a domain

      ----------- Programm -----------

    info            programm informations
    help            this
    cls             clear all recent outputs

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
    print ('Version      :', platform.python_version())     # only if python is installed
    print ('Version tuple:', platform.python_version_tuple())
    print ('Compiler     :', platform.python_compiler())
    print ('Build        :', platform.python_build())
    time.sleep(1)
    start()

def clear():
    os.system("cls")    # need to be changed for other os / os.system('clear')  # on linux / os x
    time.sleep(1)
    welcome()

def tree():
    p = input("Basic 'b' or custom 'c' tree ?")
    if p == "b":
        rootDir = 'c:\\'
        for dirName, subdirList, fileList in os.walk(rootDir):
            print('Found directory: %s' % dirName)
            for fname in fileList:
                print('\t%s' % fname)
            if len(subdirList) > 0:
                del subdirList[0]
    if p == "c":
        rootDir = input(r"Enter Storage Letter (eg. c:\\) return blank if doesnt exist : ")
        for dirName, subdirList, fileList in os.walk(rootDir):
            print('Found directory: %s' % dirName)
            for fname in fileList:
                print('\t%s' % fname)
            if len(subdirList) > 0:
                del subdirList[0]
    time.sleep(1)
    start()


def start():
    askstr = ("\n" + getpass.getuser() + " "  r"$ " " ")
    i = input(askstr)
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
    if i == ("time"):   # done time #
        currentworld()
    if i == ("net all"):  # done net all #
        netinfoall()
    if i == ("net"):    # done net #
        netinfo()
    if i == ("gpu"):    # done gpu #
        gpuinfo()
    if i == ("pcs info"):  # done pcs info
        pcsinfo()
    if i == ("storage"):  # done storage #
        storage()
    if i == ("tasklist"):  # done tasklist #
        tasklist()
    if i == ("iplookup"):  # done iplookup #
        iplookup()
    if i == ("exit"):   # done exit
        exit()
    if i == ("help"):  # done help
        helpcmd()
    if i == ("mac"): # done get mac #
        getmac()
    if i == ("boot"): # done boot info #
        boot()
    if i == ("whois"):  # done whois #
        whoisnet()
    if i == ("cls"): # done clear
        clear()
    if i == ("pyinfo"): # done pyinfo #
        pyinfo()
    if i == ("tree"): # done tree
        tree()
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
    print(" ")
    print(" ")
    print(Fore.LIGHTRED_EX + "Python based Command Prompt [Version 0.2]")
    print(Fore.LIGHTRED_EX + "Copyright 2020, lubnc4261, All rights reserved.")
    print(Fore.LIGHTGREEN_EX + "---------------------------------------------------")
    print(Fore.GREEN + "type " + Fore.YELLOW + "'help'" + Fore.GREEN + " for all commands listed")
    print(Fore.GREEN + "type " + Fore.YELLOW + "'exit'" + Fore.GREEN + " to close the program")
    print(" ")
    start()

welcome()