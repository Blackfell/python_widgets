#!/usr/bin/env python3

'''

A simple email parser, takes webpages, finds emails

Author : Blackfell
Twitter : @blackf3ll
Email: info@blackfell.net

Usage:

Argument one is the URL to scrape, argument two is optional
and is the out-file to write results to.

'''

import requests
import re
import sys

from os.path import basename, exists

from resources import bcolors as bc

def find_emails(some_text):
    #Configure regex, one or more groups of no whitespaces, @ or html tags trailing an address
    #with a single @ and a . escaped for our email addresses
    regex = '[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+'
    #Now match the string and return it
    return re.findall(regex, some_text)

def scrape_emails(some_site):
    r = requests.get(some_site)
    return find_emails(r.text)

def main():
    #Mega basic command line parsing will do fine for our purposes
    try:
        if len(sys.argv[1:]) == 1:
            addresses = scrape_emails(sys.argv[1])
            if addresses is not None:
                bc.success("Found addresses :")
                for a in addresses:
                    print("\t{}".format(a))
        elif len(sys.argv[1:]) == 2:
            addresses = scrape_emails(sys.argv[1])
            if addresses is not None and not exists(sys.argv[2]):
                with open(sys.argv[2], "w") as f:
                    for address in addresses:
                        f.write(address + '\n')
            elif addresses is not None and exists(sys.argv[2]):
                answer = 'placeholder'
                fmt_str = bc.blue_format(
                        "[!] ", "- {} exists, overwrite, append or cancel [o/a/c]? :".format(
                                sys.argv[2]))
                while answer.lower() not in ['o','a','c']:
                    answer = input(fmt_str)
                if answer == 'c':
                    bc.info("Exiting.")
                    sys.exit(0)
                else:
                    mode = 'w' if answer == 'o' else 'a'
                    with open(sys.argv[2], mode) as f:
                        for address in addanswerresses:
                            f.write(address + '\n')

        else:
            app = basename(__file__)
            print('Usage: {} [target_url] [outfile (optional)]'.format(app))
    except Exception as e:
        bc.err("Error parsing emails: {}".format(e))

if __name__ == '__main__':
    main()
