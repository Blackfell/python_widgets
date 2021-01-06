#!/usr/bin/env python

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
    parser.add_argument("-w", "--wordlist", type = str, \
            help = "Wordlist file.", required = True)
    parser.add_argument("-f", "--hashfile", type = str, \
            help = "File containing candidate hashes", required = True)
    return parser.parse_args()

def main():
    args = get_args()
    
    hashes = parse_hashfile(args.hashfile)
    hmac_to_crack = hashes[0]
    sha512_to_crack = hashes[1]
    bc.info("Parsed {} HMAC and {} SHA512 Hashes from {}".format(
        len(hmac_to_crack), len(sha512_to_crack), args.hashfile))

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
                            h[2], word))
                        sha512_to_crack.remove(h)

            # Now for any HMACS
            if len(hmac_to_crack) > 0:
                for h in hmac_to_crack:
                    this_hash = pbkdf2_hmac('sha512', word.encode(), h[0], int(h[3]))
                    if b64encode(this_hash).decode() == h[1]:
                        bc.success("{} : {}".format(
                            h[2], word))
                        hmac_to_crack.remove(h)

    bc.info("{} HMAC and {} SHA512 hashes left to be cracked.".format(
        len(hmac_to_crack), len(sha512_to_crack)))

if __name__ == '__main__':

    try:
        main()
    except KeyboardInterrupt:
        bc.info("Interrupted, exiting.")
    except Exception as e:
        bc.err("Unexpected error:\n{}".format(e))
