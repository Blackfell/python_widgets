#!/usr/bin/env python3

from argparse import ArgumentParser
from socket import socket, timeout, SHUT_RD, AF_INET, SOCK_STREAM
from multiprocessing import Queue, Process, Event
from time import sleep
from sys import exit, argv
from hexdump import hexdump

def get_args():

    parser = ArgumentParser()
    parser.add_argument('-l', '--listen', action='append', nargs='+', help='Listen on a given port. Format -l <port>')
    parser.add_argument('-c', '--connect', action='append', nargs='+', help='Connect to a given host & port. Format : -c <host> <port>')
    parser.add_argument('-t', '--tee', action='store_true', help='Also print all traffic on Stdout.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Print more stuff during execution.')
    args = parser.parse_args()

    #Count how many connections have been provided
    conns = len(args.listen) if args.listen else 0
    conns = conns + len(args.connect) if args.connect else conns

    if conns != 2:
        print("")
        print("[!] - Incorrect number of relay endpoints. You must specify two endpoints to relay.")
        print("\tYou can specify either two local ports, two ports to connect remote, or one local one remote.\n")
        print("Example - relay local listener on port 4444 to local connection to port 445:")
        print("\t{} -l 4444 -c 127.0.0.1 445\n".format(argv[0]))
        print("Example - relay local listener on port 4444 to local listener on port 445:")
        print("\t{} -l 4444 -l 445\n".format(argv[0]))
        print("Example - relay connection to remote server (10.10.10.10) port 5555 to local connection to port 445:")
        print("\t{} -c 10.10.10.10 5555 -c 127.0.0.1 445\n".format(argv[0]))
        parser.print_help()
        exit(0)

    bind1 = args.listen[0] if args.listen else None
    bind2 = args.listen[1] if (args.listen and len(args.listen) > 1) else None
    connect1 = args.connect[0] if args.connect else None
    connect2 = args.connect[1] if (args.connect and len(args.connect) > 1) else None

    #Format bind and conenct parameters into socket compatible tuples
    try:
        bind1 = ("0.0.0.0", int(bind1[0])) if bind1 else None
        bind2 = ("0.0.0.0", int(bind2[0])) if bind2 else None
        connect1 = (str(connect1[0]), int(connect1[1])) if connect1 else None
        connect2 = (str(connect2[0]), int(connect2[1])) if connect2 else None
    except Exception as e:
        print("")
        print("[!] - Error converting arguments:\n\t{}".format(e))
        print("\tAre your ports and IP addresses formatted correctly?\n")
        parser.print_help()
        exit(0)

    print("bind1 : {}, bind2 : {}, connect1 : {}, connect 2 : {}".format(bind1, bind2, connect1, connect2))

    if bind1 and bind2:
        if args.verbose:
            print("[+] - Relay combo good - bind to bind")
    elif connect1 and connect2:
        if args.verbose:
            print("[+] - Relay combo good - connect to connect")
    elif connect1 and bind1:
        if args.verbose:
            print("[+] - Relay Combo good - bind to connect")
    else:
        print("[!] - Bad relay combo!")
        exit(0)

    return bind1, bind2, connect1, connect2, args.verbose, args.tee

def recv_from(connection):
    connection.settimeout(1)
    try:
        buffer = b""
        while True:
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
    except timeout as e:
        pass
    except Exception as e:
            print("[!] - Exception while receiving : {}".format(e))
    return buffer

def connect_relay(host, q_in, q_out, tee, kill):
    s = socket(AF_INET, SOCK_STREAM)
    s.settimeout(0.5)
    while True:
        try:
            if kill.is_set():
                print("[!] - Killing connection to {}".format(host))
                s.shutdown(SHUT_RD)
                s.close()
            s.connect(host)
            break
        except timeout:
            pass
        except Exception as e:
            print("[!!] - Can't connect to {}: {}".format(host, e))
            kill.set()
            return
    print("[+] - Connected to {}".format(host))
    while True:
        if kill.is_set():
            print("[!] - Killing connection to {}".format(host))
            s.shutdown(SHUT_RD)
            s.close()
            return
	#if we got data on the sister socket, send that first
        if not q_in.empty():
            to_send = q_in.get()
            s.sendall(to_send)
	#Then receive data and give to sister
        recv_data = recv_from(s)
        if tee and recv_data:
            print("---- FROM {} ----".format(host))
            hexdump(recv_data)
        q_out.put(recv_data)

def bind_relay(host, q_in, q_out, tee, kill):
    try:
        server = socket(AF_INET, SOCK_STREAM)
        try:
            server.bind(host)
        except Exception as e:
            print("[!!] - Can't bind on {}: {}".format(host, e))
            exit(0)
        print("[+] - Listening on {}".format(host))
        server.listen(0)
        server.settimeout(0.5)
        while True:
            try:
                if kill.is_set():
                    print("[!] - Killing listener on {}".format(host))
                    server.shutdown(SHUT_RD)
                    server.close()
                    return
                clnt_sock, addr = server.accept()
                break
            except timeout:
                pass
            except Exception as e:
                print("[!] - Exception accepting connections : {}".format(e))
        print("[+] - Connection received from {}".format(addr))
        while True:
            if kill.is_set():
                print("[!] - Killing listener on {}".format(host))
                server.shutdown(SHUT_RD)
                server.close()
                return
            #if we got data on the sister socket, send that first
            if not q_in.empty():
                to_send = q_in.get()
                clnt_sock.sendall(to_send)
            #Then receive data and give to sister
            recv_data = recv_from(clnt_sock)
            if tee and recv_data:
                print("---- FROM {} ----".format(addr))
                hexdump(recv_data)
            q_out.put(recv_data)
    except Exception as e:
        print("\n[!] - Exception in bind relay thread : {}".format(e))
        kill_flag.set()
        sleep(1)
        return


def main():
    #Setup queue data structures for relayed data
    q_1_2 = Queue()
    q_2_1 = Queue()
    kill_flag = Event()

    #Get args
    bind1, bind2, conn1, conn2, v, t = get_args()

    #Setup relay
    if bind1 and bind2:
        host1 = Process(target=bind_relay, args=(bind1, q_2_1, q_1_2, t, kill_flag))
        host2 = Process(target=bind_relay, args=(bind2, q_1_2, q_2_1, t, kill_flag))
    elif conn1 and conn2:
        host1 = Process(target=connect_relay, args=(conn1, q_2_1, q_1_2, t, kill_flag))
        host2 = Process(target=connect_relay, args=(conn2, q_1_2, q_2_1, t, kill_flag))
    else:
        host1 = Process(target=bind_relay, args=(bind1, q_2_1, q_1_2, t, kill_flag))
        host2 = Process(target=connect_relay, args=(conn1, q_1_2, q_2_1, t, kill_flag))
    try:
        #Start relay
        host1.daemon=True
        host2.deamon=True
        host1.start()
        host2.start()
        while True:
            if kill_flag.is_set():
                #We've been told to die by another thread.
                print("[!] - Terminating relays. Please wait.")
                sleep(3)
                exit(0)
            sleep(1)
    except KeyboardInterrupt:
        print("\n[!] - Interrupted - please wait.")
        kill_flag.set()
        sleep(3)
        exit(0)
    except Exception as e:
        print("Exception in main : {}".format(e))
        exit(0)

if __name__ == '__main__':
    main()
