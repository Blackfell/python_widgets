#!/usr/bin/env python3

"""
                             /\\
                            /^^\_
                    /\     /^^^^^\\
                   /^^|   /^^^^^^^\_
                  /^^^^\_/^^^^^^^^^^\\
                _/  \ /    /  |  \   \\
               /   /   \    |  \    \ \\
              /                        \\
             /   $    $   /     $  $    |
            / $  |  $ |    $    |  |  $  \\
           /  |  $  |   $  |$  $    $ |$  \\
        ######################################
        #                                    #
        #              rot hunter            #
        #                 by                 #
        #             @blackf3ll             #
        #         info@blackfell.net         #
        #                                    #
        ######################################

DESCRIPTION:

Encodes and decodes rot cyphers when passed as arguments
Will show you the output in order of confidence that the
plaintext is made up of valid dictionary words.

USAGE:

Place candidate rot text in a file, get hold of a list
of valid dictionary words that may be in your output.
Basic usage is:

~$ rot_hunter.py dictionary_wrods.txt ciphertext.txt

EXAMPLES:

supplied in the resources folder is a list courtesy of:

Josh Kaufman : https://github.com/first20hours

I've also provided an example file 'test.txt' in the same
directory. You can test drive with:

~$ ./bin/rot_hunter.py ./resources/rot_hunter/google-10000-english.txt ./resources/rot_hunter/test.txt

Enjoy!

"""

import string
import sys

def rot(plaintext, rotation_index=13):
    charset = 'abcdefghijklmnopqrstuvwxyz'
    ciphertext = ''
    for char in plaintext:
        if char == ' ':
            ciphertext = ciphertext + ' '
        if char == '':
            ciphertext = ciphertext + ''
        if char == '\n':
            ciphertext = ciphertext + '\n'
        if char in string.punctuation:
            ciphertext = ciphertext + char
        if char in charset:
            new_char = charset.index(char) + int(rotation_index)
            if new_char < 26:
                ciphertext = ciphertext + charset[new_char]
            else:
                ciphertext = ciphertext + charset[new_char % 26]
        else:
            ciphertext = ciphertext
    return ciphertext

def get_confidence(plaintext, dictionary):
    matches=0
    fails=0
    for word in plaintext.split(' '):
        if word in dictionary.split('\n'):
            if not word:
                pass
            elif word==" ":
                pass
            elif word=="\n":
                pass
            else:
                matches += 1
        else:
            fails += 1
    confidence = (matches/(matches +fails))*100
    return round(confidence,2)

def sort_messages(messages):
    sorted_messages = {}
    count = 0
    for key in sorted(messages, key=lambda key: messages[key][1], reverse=True):
        sorted_messages[count]= [ key + 1,  messages[key][0], messages[key][1] ]
        count += 1
    return sorted_messages

def display_output(sorted_messages):
    see_more = 'y'
    count = 0
    while see_more != 'n':
        if count == 0 :
            print("Top Result is rot by {}, giving confidence of: {} percent".format(sorted_messages[count][0],sorted_messages[count][2]))
            print("")
            print(sorted_messages[count][1])
        else:
            print("Rot by {}, gives confidence of: {} percent".format(sorted_messages[count][0],sorted_messages[count][2]))
            print("")
            print(sorted_messages[count][1])
        count += 1
        see_more = input("See more results? [y/n]: ").lower()

if __name__ == '__main__':
    #CLI Parsing - simple and dirty:
    if len(sys.argv[1:]) != 2:
        print("Usage: {} [wordlist_filepath] [ciphertext_filepath]".format(sys.argv[0]))
        sys.exit(0)
    #Set up variables from CLI
    word_list=sys.argv[1]
    plaintext_file=sys.argv[2]
    #Read in plaintext and lower case it
    with open(plaintext_file, 'r') as p:
          plaintext = p.read()
          plaintext = plaintext.lower()
    #Read in wordlist and lower case it
    with open(word_list, 'r') as w:
          dictionary = w.read()
          dictionary = dictionary.lower()
    #Loop alphabet, try rot and build score
    messages={}
    for i in range(25, -1, -1):
        rotated_pt = rot(plaintext, i+1)
        confidence = get_confidence(rotated_pt, dictionary)
        messages[i] = [rotated_pt, confidence]
    #sort messages by confidence and print
    #display_output(sort_messages(messages))
    sorted_messages = sort_messages(messages)
    display_output(sorted_messages)
