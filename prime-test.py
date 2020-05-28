#!/usr/bin/env python3

'''

A script to brute force http forms (or any post request for that matter!)

Author : Blackfell
Twitter : @blackf3ll
Email: info@blackfell.net

'''

from sys import argv, exit, executable
from os.path import basename

from resources import bcolors as bc

def is_prime(n):
	if (n <= 1) :
		return False
	if (n <= 3) :
		return True
	if (n % 2 == 0 or n % 3 == 0) :
		return False
	i = 5
	while(i * i <= n) :
		if (n % i == 0 or n % (i + 2) == 0) :
			return False
		i = i + 6
	return True

def main():
	#CLI Parsing - simple and dirty:
	if len(argv[1:]) != 1:
		app = basename(__file__)
		print("Usage: {} [number]".format(app))
		exit(0)
    	#Set up variables from CLI
	try:
		num=int(argv[1])
	except:
		bc.err('Cannot process argument. Is your input an integer?')
		exit(0)
	if is_prime(num):
		bc.success('Yes, {} is prime!'.format(num), True)
	else:
		bc.info('No, {} is not prime, sorry!'.format(num), True)

if __name__ == '__main__':
	main()
