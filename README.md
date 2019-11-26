# python_widgets
A collection of small helper scripts I've used during CTF challenges; all scripts are made with the quick-and-dirty principle, but that doesn't mean they're not useful!

More to follow in time.

## rot_hunter

This is the first tool I've published so far and is somehting I use when feeling too lazy to try different rot encodings during CTFs. This tool takes two files as command line arguments, one containing your ciphertext, one containing a dictinary of valid words; the tool will find the most likely rot key and allow you to parse all other options in decreasing order of confidence the solution is good.

I've inluded a couple of test files for your enjoyment; check out the file header or usage info and get started!
