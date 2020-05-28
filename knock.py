#!/usr/bin/env python3

'''

A simple port knocking script, with brute forcing/permutation options

Author : Blackfell
Twitter : @blackf3ll
Email: info@blackfell.net

'''

import argparse
import sys
import os
import time
import socket

from scapy.all import sr, IP, TCP

from resources import bcolors as bc

#Fancier argument parsing than I usually use
args = None
#Now do the thing
def get_args():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    parser.add_argument("-H", "--host", type = str, required = True, help = "Hostname or IP address to knock against.")
    group.add_argument("-kT", "--tcp-connect", action = "store_true",default = True, help = "Knock with a full TCP connect (default if not set).")
    group.add_argument("-kS", "--syn", action = "store_true", help = "Knock with Syn packets by default.")
    group.add_argument("-kU", "--udp", action = "store_true", help = "Knock with UDP packets by default.")
    parser.add_argument("-b", "--brute", action = "store_true", help = "Permute through knocking combinations until target port is open. REQUIRES specification of --target-port.")
    parser.add_argument("-p", "--knock-ports", type = str , required = True, help = "Ports to knock on, comma delimited.")
    parser.add_argument("-t", "--target-port", type = str , help = "Port to check status of after knocking; REQUIRED if using --brute. Will default to knock protocol, unless specified with colon delimiter - e.g. -t 80:TCP.")
    parser.add_argument("-d", "--delay", type = int ,default = 0,  help = "Time to wait between knocks in seconds (default 0).")
    parser.add_argument("-v", "--verbose", action = "store_true", default = False , help = "Show detailed knock information.")
    #Now do args stuff
    args = parser.parse_args()

    #If we have brute forcing, we need a port to test for success
    if args.brute and (args.target_port == None):
        parser.error("If --brute is specified, a target port (-t/--target-port) must be provided.")

    return args


def tcp_connect(host, port):
    try:
        #Instantiate socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)    #Timeouts are bad
        socket_addr = (host, port)  #Setting up socket address
        result = s.connect_ex(socket_addr)
        if not s.connect_ex(socket_addr):
            return 0
        #select.select([s], [s], [s], self.timeout)
        #Close socket
        s.close()
    except:
        bc.err("Could not TCP connect to host on port {}.".format(port))

    return 1

def send_syn(host,port):
    syn_response=None
    try:
        #Send it, no waiting!
        syn_response = sr(IP(dst=host)/TCP(dport=port,flags='S'),timeout=0)
    except Exception as e:
        bc.err("Could not send SYN to {}:{} : \n{}".format(host, port, e))
        bc.warn("Check you have permissions to craft packets.")
        bc.err("Exiting.")
        sys.exit(0)
    #TODO validate Syn response and return 0 open, or 1 for closed/filtered
    return syn_response

def send_udp(host,port,message):
    #Todo - consider ICMP dest unreach as a filtered option
    try:
        #Instantiate socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        socket_addr = (host, port)  #Setting up socket address
        data = b'/?help\n'
        s.sendto(data, socket_addr)
        #Test for UDP response - Quick and dirty
        s.settimeout(5)
        try:
            s.recvfrom(1024)
            return 0
        except:
            return 1
        #Close socket
        s.close()
    except:
        bc.err("Could not send UDP packet to host on port {}.".format(port))

def knock(host, ports, syn, default_proto, delay, verbose):
    for port in ports:
        #Handle tcp vs udp settings, either getting from global or port-specific setting
        if len(port.split(':')) == 2:
            port,proto=port.split(':')
        else:
            proto = default_proto

        #Now we're rid of proto, convert ports to integer
        try:
            port = int(port)
        except:
            bc.info("Unexpected error in port integer conversion:", sys.exc_info()[0])
            raise
        if verbose:
            bc.info("Hitting Port {} with Proto {}".format(port,proto.upper()))
        if proto.lower() == "tcp" and not syn:
            result = tcp_connect(host, port)
        elif proto.lower() == "tcp":
            result = send_syn(host,port)
        elif proto.lower() == "syn":
            result = send_syn(host,port)
        elif proto.lower() == "udp":
            result = send_udp(host,port,b"")
        else:
            bc.err("Improper protocol '{}' set for port {}.".format(proto, port))

        #Wait
        if delay > 0:
            time.sleep(delay)
    return result

def check_root() :
    if os.getuid() != 0:
        bc.err("You're not running at root, you may not be able to knock properly.")
        decision = 'decision_placeholder'
        while decision != "y" or decision !="n":
            decision=input("Would you like to continue anyway?(y/n)").lower()
            if decision.lower() == "n":
                sys.exit(0)
            elif decision.lower() == 'y':
                break


def print_banner():
    banner = """
                              /\\
                             /^^\\_
                     /\\     /^^^^^\\
                    /^^\\   /^^^^^^^\\_
                   /^^^^\\_/^^^^^^^^^^\\
                 _/  \\ /    /  | \\ \\   \\
                /   /   \\    |  \\    \\ \\
               /                        \\
              /   #    #   /     #  #    |
             / #  |  # |    #    |  |  #  \\
            /  |  #  |   #  |#  #    # |#  \\

                  Blackfell Port Knocker
                   Author : Blackfell
               Email : info@blackfell.net
    """
    print(bc.HEADER + banner +bc.ENDC)


def main():

    args = get_args()
    print_banner()
    check_root()

    #Set scan type, remove default TCP connect if Syn Scan
    #Also setup default protocols and TCP flags (if applicable)
    if args.syn:
        args.tcp_connect = False
    if args.udp:
        default_proto="udp"
    else:
        default_proto="tcp"

    #Format ports into list, check number of ports first
    if len(args.knock_ports.split(',')) < 2:
        bc.err("Error parsing knock ports!\t" + bc.UNDERLINE + \
                "Did you supply comma delimited ports?" + bc.ENDC)
        sys.exit(0)
    else:
        knock_ports=args.knock_ports.split(',')

   #If not brute, knock
    if not args.brute:
        if args.verbose:
            bc.success("Starting knock against ports: {}".format(knock_ports))
        knock(args.host, knock_ports, args.syn, default_proto, args.delay, args.verbose)
    else:
        #BRUTE!
        bc.info("Bruting...")

    #If port to test - NOTE syn set to False, because we're looking for connection
    if args.target_port and knock(args.host, [args.target_port], False, \
            default_proto, args.delay, args.verbose) == 0:
        bc.success("Knock complete - {}, test port open!".format(
                bc.bold_format("success")))
    elif args.target_port:
        bc.err("Knock complete - {} - test port filtered or closed... BEWARE UDP.".format(
                bc.bold_format("Failure")))
    else:
        bc.info("Knock complete.")

if __name__ == "__main__":
  main()
