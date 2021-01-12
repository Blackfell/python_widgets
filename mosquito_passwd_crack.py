#!/usr/bin/env python3

import re
import argparse

from hashlib import pbkdf2_hmac, sha512
from base64 import b64encode, b64decode
from sys import exit

import resources.bcolors as bc

def parse_hashfile(filename):
    """Reads a hashfile and tries to load any valid mosquito_passwd
    hashes"""

    hashes = [[], []]   # first element hmacs, second 512s

    # Hashes are always username:$[HASHNO]$SALT[$ITER(HMAC ONLY)]$HASH
    # Where salt and hash are always B64 encoded, assume usernames are .+
    # Try https://github.com/eclipse/mosquitto/search?q=pw_sha512_pbkdf2
    # This is probably bloody close enough to being a good regex for the job
    regex = re.compile(r".+:\$[6-7]\$[a-zA-Z0-9+/=]+(\$[0-9]+)*\$[a-zA-Z0-9+/=]{80,90}")
    with open(filename, 'r') as h:
        for line in h:
            m = regex.match(line)
            if m: 
                hash_info = format_hash(m.group(), hashes)
                if hash_info[0] == 'sha512':
                    hashes[1].append(hash_info[1:4])    #Snip off iterations
                else:
                    hashes[0].append(hash_info[1:])

    return hashes

def format_hash(hash_string, hash_dict):
    """Takes the input hash string from our file and rationalises it
    into the algo salt, digest and if applicable, iterations for HMAC."""
    
    # We know mosquito_passwd bans colons in the name and B64 is safe, so split
    user, hash_info = hash_string.split(":")
    if hash_info.count("$") == 4:
        junk, morejunk, salt, iterations, digest = hash_info.split("$")
        hash_type = 'pw_sha512_pbkdf2'
    elif hash_info.count("$") == 3:
        junk, morejunk, salt, digest = hash_info.split("$")
        hash_type = 'sha512'
        iterations = "1"
    else:
        bc.err("Error parsing hash - bad format:\n{}".format(hash_string))
        exit(0)

    return [hash_type, b64decode(salt), digest, user, iterations]

def get_args():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("-w", "--wordlist", type = str, \
            help = "Path to wordlist file.")
    mode.add_argument("-c", "--convert-hashcat", action = "store_true", \
            help = "Don't crack, just convert to hashcat.")
    mode.add_argument("-j", "--convert-john", action = "store_true", \
            help = "Don't crack, just convert to John.")
    parser.add_argument("-f", "--hashfile", type = str, \
            help = "File containing candidate hashes", required = True)
    parser.add_argument("-o", "--out-file", type = str, \
            help = "File name for converted hashes - default - 'converted'",\
            default = 'converted')
    
    return parser.parse_args()

def sha512_to_hashcat(hash_data):
    """Takes my hash list and turns it into a hashcat compatible
    format"""

    salt = hash_data[0]
    b64_digest = hash_data[1]
    user = hash_data[2]
    
    fmt_str = "{}:{}"

    hex_digest = ""
    for byte in b64decode(b64_digest):
        h = hex(byte)[2:]
        hex_digest += h if len(h) == 2 else  "0" + h 

    hex_salt = ""
    for byte in salt:
        h = hex(byte)[2:]
        hex_salt += h if len(h) == 2 else  "0" + h 
    
    return fmt_str.format(hex_digest.upper(), hex_salt.upper())

def hmac_to_hashcat(hash_data):
    """Take a hash and return a valid hashcat hash for the 
    PBKDF2-HMAC-SHA512 hash mode (12100)"""

    salt = hash_data[0]
    b64_digest = hash_data[1]
    user = hash_data[2]
    iterations = hash_data[3]
    
    fmt_str = "sha512:{}:{}:{}"

    return fmt_str.format(iterations, b64encode(salt).decode(), b64_digest)

def convert_hashcat(args, sha512_to_crack, hmac_to_crack):
    """Take a mosquitto_passwd file and convert it to hashcat format
    can handle both SHA512 and PBKDF2_HMAC_SHA512 output formats"""

    sha512s = []
    hmacs = []
    for h in sha512_to_crack:
        sha512s.append(sha512_to_hashcat(h))
    for h in hmac_to_crack:
        hmacs.append(hmac_to_hashcat(h))
    if len(sha512s) > 0:
        with open("{}.1710.hcat".format(args.out_file), "w") as o:
            for h in sha512s:
                o.write(h + "\n")
    if len(hmacs) > 0:
        with open("{}.12100.hcat".format(args.out_file), "w") as o:
            for h in hmacs:
                o.write(h + "\n")
    bc.success("Hashes written out to files starting '{}'".format(
        args.out_file))
    bc.info("Run SHA512s in mode 1710 with --hex-salt.", strong=True)
    bc.info("Run HMAC-SHA512s in mode 12100.", strong=True)

def hmac_to_john(hash_data):
    """Take a hash and return a valid john hash for the 
    PBKDF2-HMAC-SHA512 hash dynamic mode ()"""

    salt = hash_data[0]
    b64_digest = hash_data[1]
    user = hash_data[2]
    iterns = hash_data[3]
    
    fmt_str = "{}:$pbkdf2-hmac-sha512${}.{}.{}"
    
    hex_digest = ""
    for byte in b64decode(b64_digest):
        h = hex(byte)[2:]
        hex_digest += h if len(h) == 2 else  "0" + h 

    hex_salt = ""
    for byte in salt:
        h = hex(byte)[2:]
        hex_salt += h if len(h) == 2 else  "0" + h 
    
    return fmt_str.format(user, iterns, hex_salt.upper(), hex_digest.upper())

def sha512_to_john(hash_data):
    """Takes my hash list and turns it into a john compatible format"""

    salt = hash_data[0]
    b64_digest = hash_data[1]
    user = hash_data[2]
    
    fmt_str = "{}:$dynamic_82${}$HEX${}"

    hex_digest = ""
    for byte in b64decode(b64_digest):
        h = hex(byte)[2:]
        hex_digest += h if len(h) == 2 else  "0" + h 

    hex_salt = ""
    for byte in salt:
        h = hex(byte)[2:]
        hex_salt += h if len(h) == 2 else  "0" + h 
    
    return fmt_str.format(user, hex_digest.upper(), hex_salt.upper())

def convert_john(args, sha512_to_crack, hmac_to_crack):
    """Take a mosquitto_passwd file and convert it to John's dynamic 82
    format. Can handle both SHA512 and PBKDF2_HMAC_SHA512 output formats.
    Using raw hex for hash and salt because bad bytes."""

    sha512s = []
    hmacs = []
    for h in sha512_to_crack:
        sha512s.append(sha512_to_john(h))
    for h in hmac_to_crack:
        hmacs.append(hmac_to_john(h))
    if len(sha512s) > 0:
        with open("{}.sha512s.john".format(args.out_file), "w") as o:
            for h in sha512s:
                o.write(h + "\n")
    if len(hmacs) > 0:
        with open("{}.hmacs.john".format(args.out_file), "w") as o:
            for h in hmacs:
                o.write(h + "\n")
    bc.success("Hashes written out to files starting '{}'".format(
        args.out_file))
    bc.info("Run separate sessions for each hash type. " + \
            "No format specification needed.", strong=True)


def main():
    args = get_args()
    
    hashes = parse_hashfile(args.hashfile)
    hmac_to_crack = hashes[0]
    sha512_to_crack = hashes[1]
    bc.info("Parsed {} HMAC and {} SHA512 Hashes from {}".format(
        len(hmac_to_crack), len(sha512_to_crack), args.hashfile))

    #Hashcat conversion operation
    if args.convert_hashcat:
        convert_hashcat(args, sha512_to_crack, hmac_to_crack)
        exit(0)

    # John conversion operation
    elif args.convert_john:
        convert_john(args, sha512_to_crack, hmac_to_crack)
        exit(0)
    
    with open(args.wordlist, 'r', encoding='latin-1') as w:
        for word in w:
            if not word: continue
            word = word.strip()
            if len(sha512_to_crack) == 0 and len(hmac_to_crack) == 0:
                bc.info("No more hashes to crack, exiting.")
                break

            # crack any straight 512s
            if len(sha512_to_crack) > 0:
                for h in sha512_to_crack:
                    this_hash = sha512(word.encode() + h[0]).digest()
                    if b64encode(this_hash).decode() == h[1]:
                        bc.success("{} : {}".format(
                            h[2], word), strong=True)
                        sha512_to_crack.remove(h)

            # Now for any HMACS
            if len(hmac_to_crack) > 0:
                for h in hmac_to_crack:
                    this_hash = pbkdf2_hmac('sha512', word.encode(), h[0], int(h[3]))
                    if b64encode(this_hash).decode() == h[1]:
                        bc.success("{} : {}".format(
                            h[2], word), strong=True)
                        hmac_to_crack.remove(h)

    bc.info("{} HMAC and {} SHA512 hashes left to be cracked.".format(
        len(hmac_to_crack), len(sha512_to_crack)))

if __name__ == '__main__':

    try:
        main()
    except KeyboardInterrupt:
        bc.info("Interrupted, exiting.")
