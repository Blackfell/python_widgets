#!/usr/bin/env python3

#####################################################
#       Wrangle usernames - Takes first and         #
#     last names and makes candidate user names     #
#           By github@blackfell.net                 #
#####################################################

import sys
import argparse

from resources import bcolors as bc

def get_args():
    """Get command line arguments, setting default delimeters and More
    while we're at it!"""
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--case-sensitive", default=False, action='store_true',\
            help = "Vary the casing options (username Username UserName userName) \
                    for case-sensitive logon systems.")
    parser.add_argument("-d", "--delims", type = str, default = "'','.','-'", \
            help = "List of delimeters - default '','.','.' Supply comma delimited.")
    parser.add_argument("-i", "--input-file", type = str, required = True, \
            help = "Text file with first names and surnames, space separated.")
    parser.add_argument("-o", "--out-file", type = str, \
            help = "Optionally write out results to a file.")
    parser.add_argument("-a", "--append-numbers", type = int, default=0, \
            help = "Append numbers up to this value. Appends nothing if zero or not set.")
    args = parser.parse_args()

    return args

def case_iteration(str_1, str_2, delim=''):
    """Iterates casing options for two words, varies Pascal,
    camel, first cap only and no caps for any two strings."""
    v_caps = []
    # string1string2
    v_caps.append(str_1.lower() + delim + str_2.lower())
    # String1string2
    v_caps.append(str_1[0].upper() + str_1.lower()[1:] + delim + str_2.lower())
    # string1String2
    v_caps.append(str_1.lower() + delim + str_2[0].upper() + str_2.lower()[1:])
    # String1String2
    v_caps.append(str_1[0].upper() + str_1.lower()[1:] + delim + \
            str_2[0].upper() + str_2.lower()[1:])

    return v_caps


def concatenate_strs(str_1, str_2, caps, delims, suffx):
    """"Concatenate two strings, around a list of delimeters
    append a list of suffixes to the options and retun a list        if not args.out_file:
            out_file = None
        else:
            out_file = args.out_file
    of resulting strings"""
    candidates = []
    for d in delims:
        if not caps:
            #Simple concat without delims first
            candidates.append(str_1 + d + str_2)
        else:
            #Alternate all the cases
            candidates += case_iteration(str_1, str_2, d)

    #Now append all suffixes
    num_cands = []
    for c in candidates:
        for s in suffx:
            num_cands.append(c + str(s))
    candidates += num_cands

    return candidates

def iterate_single_user(first_name, last_name, caps, delims, suffx):
    """Just manually iterate through some common user formats
    there's not that many, we'll be fine! - Famous last words?
    """
    names=[]
    #Full names
    names += concatenate_strs(first_name, last_name, caps, delims, suffx)
    #First initial last name
    names += concatenate_strs(first_name[0], last_name, caps, delims, suffx)
    #First name last initial
    names += concatenate_strs(first_name, last_name[0], caps, delims, suffx)
    #Three and three
    names += concatenate_strs(first_name[:3], last_name[:3], caps, delims, suffx)

    return names


def main():
    """Creates user options for each user in a group retains data structure so
    that each user can still be tied to candidate username options"""

    #get arguments first
    args = get_args()
    delims = [i.split("'")[1] for i in args.delims.split(',')]
    suffx = [i + 1 for i in range(args.append_numbers)]


    #Get the names from file and process them
    try:
        with open(args.input_file, "r") as f:
            total_names = {}
            for names in f:
                names = names.strip()
                if len(names.split()) > 2:
                    bc.err("Error, name {} is more than 2 words. Skipping.".format(
                            names))
                    continue
                first_name = names.split()[0]
                last_name = names.split()[1]
                total_names[names] = iterate_single_user(first_name, last_name,\
                        args.case_sensitive, delims, suffx)

        #Output the names
        if not args.out_file:
            for name, logins in total_names.items():
                bc.info("Iterations for name : {}".format(name))
                for login in logins:
                    print("\t{}".format(login))
        else:
            #now creat an outfile
            with open(args.out_file, "w") as f:
                #Print, seemingly out of order, because it might be quicker!
                for logins in total_names.values():
                    for login in logins:
                        f.write(login + '\n')


    except Exception as e:
        bc.err("Error while processing usernames:\n{}".format(e))

if __name__ == '__main__':
    main()
