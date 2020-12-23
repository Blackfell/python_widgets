#!/usr/bin/env python3

import subprocess, argparse, yaml, threading, multiprocessing

from discord_webhook import DiscordWebhook, DiscordEmbed
from sys import exit
from time import time, sleep
from queue import Queue

from resources import bcolors

def get_args():
    """Parse known command line arguments, read in any unknown arguments as the 
            commadn line of the job to be monitored."""

    parser = argparse.ArgumentParser()
    hooks = parser.add_mutually_exclusive_group()
    parser.add_argument("-f", "--file", type = str, \
            help = "Attach this file with the job completion report.")
    parser.add_argument("-i", "--image", type = str, \
            help = "Embed this image with the job completion report.")
    parser.add_argument("-s ", "--stdout", action="store_true", default = False, \
            help = "Include a summary of Stdout (console output) on copletion of the job.")
    parser.add_argument("-b", "--beat", type=int, action="store", nargs="?", const=15, \
            help = "Check STDOUT regularly and report any changes. Defaults to 15 mins if blank.")
    parser.add_argument("-C", "--config", type=str, default="discordnotify.yml", \
            help = "YAML configuration file, containing webhhok information.")
    parser.add_argument("-c", "--command", type=str, required=True, \
            help = "Command line to execute. Quote and escape as appropriate for your shell.")
    hooks.add_argument("-w", "--web-hook", type=str, action="store", default="default", \
            help = "The YAML key for the webhook to be used for this report, defaul is 'default'.")
    hooks.add_argument("-u", "--web-hook-url", type=str, \
            help = "The web hook URL can be overriden on the CLI instead of from config file.")
    #args, unknown = parser.parse_known_args()
    args = parser.parse_args()
    #if not unknown:
    #    bcolors.err("No job has been speficied, quitting.")
    #    exit()
    return args

def get_config(config_file):
    try:
        with open(config_file, 'r') as y:
            config = yaml.load(y, Loader=yaml.FullLoader)
    except Exception as e:
        bcolors.err("Error getting yaml configuration:\n{}".format(e))
        bcolors.warn("Exiting")
        exit()
    return config

def check_config(args, config):
    """Parse all our settings and return sanitised hook information, also check
            for argument and config file correct-ness"""
    
    # Work out what hook is being used and report
    if args.web_hook_url:
        job_hook = args.web_hook_url
        nm = job_hook
    else:
        try:
            nm = config['default_hook'] if args.web_hook == 'default' else args.web_hook
            job_hook = config['hook_urls'][nm]
        except Exception as e:
            bcolors.err("Error parsing webhook from config file:\n{}".format(e))
            bcolors.warn("Exiting")
            exit()

    # Get user information from config

    try:
        job_user = config['instance_info']
    except Exception as e:
        bcolors.err("Error getting User Config:\n{}".format(e))
        bcolors.warn("Continuing without user information")
        job_user = None

    return nm, job_hook, job_user


def cut_middle_lines(lines):
    """Cut out the middle two lines if even, or three if odd
    place a SNIP indicator in teh middle of the list"""

    length = float(len(lines))
    mid = round(float(len(lines))/2)    #rounds up!
    if length % 2 != 0:
        #It's odd, so cut out three
        first = lines[:(mid-1)]
        last = lines[(mid+2):]
        return first + ["[..SNIP..]"] + last
    else:
        #It's even do cut out two
        first = lines[:(mid-1)]
        last = lines[(mid+1):]
        return first + ["[..SNIP..]"] + last




def trim_output(thing, line_lim=20):
    """ensure our output meets discord 1024 character limit for fields
    and also configure a user defined (TODO) line limit for field updates"""

    half1=[]
    half2=[]
    i = 0 
    thingd=thing.split('\n')
    # Trim output, starting with line lim for readability
    while len(thingd) > line_lim:
        thingd = cut_middle_lines(thingd)
    while len('\n'.join(thingd)) > 1024:
        thingd = cut_middle_lines(thingd)

    return '\n'.join(thingd) 

def stdout_reader(proc, stdout_q):
    while True:
        line = proc.stdout.readline()
        print(line, end="")
        stdout_q.put(line)

def main():
    """Do the main lifting!"""

    # Configuration and config stuff
    args = get_args()
    config = get_config(args.config)
    hook_name, hook, user = check_config(args, config)
    bcolors.info("Executing job: {}".format(
        bcolors.bold_format(args.command)), strong=True)
    
    #Create main webhook for proc completion
    wh = DiscordWebhook(url=hook, \
            content="You've just started a job. Brace for updates...",\
            username=user['username'])
    embed = DiscordEmbed(title="Process running",\
            description="Full command line: {}".format(args.command), color=242424)
    if user['image'] :
        embed.set_author(name="Job: {}".format(
            args.command.split(' ')[0]), icon_url=user['image'])
    else:
        embed.set_author(name="Job: {}".format(args.command.split(' ')[0]))
    embed.set_footer(text="Sent with DiscordNotify by @blackf3ll - github@blackfell.net")
    wh.add_embed(embed)
    sent_wh = wh.execute()
    
    #Pre-ampble and process start
    t1 = time()
    t2 = time()
    output=''
    p = subprocess.Popen(
            args.command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,\
            shell=True , encoding='utf-8', errors='replace')

    # Manage beat updates
    if args.beat:
        embed.add_embed_field(name="Job ongoing", value="No updates yet...", inline=False) 
        stdout_q = multiprocessing.Queue()
        stdout_worker = multiprocessing.Process(target=stdout_reader, args=(p, stdout_q))
        stdout_worker.start()
        while p.poll() == None:
            try:
                #o = p.stdout.readline()#.decode() 
                #if o is not None and o != "": print(o, end="")
                #output += o
                while not stdout_q.empty():
                    output+= stdout_q.get()
                t3=time()
                if round(t3-t2) >= args.beat:
                    t2=int(t3)
                    # update embed summary data with stdout summary and time info
                    embed.fields[0]['value'] = \
                            "Started: {} Elapsed : {}s Output summary:\n{}".format(
                            time.ctime(), round(t3-t1),trim_output(
                            output, config.user['max_embed_lines']))
                    wh.edit(sent_wh)   # and send it
            except Exception as e:
                bcolors.err("Error sending update:\n{}".format(e))
    
    # Mop up any un-read stdout and print to console
    output += p.stdout.read()#.decode() 
    duration = round(time() - t1)
    print(output)
    
    #Configure final report & embed in webhook
    was_error= "with errors" if p.returncode !=0 else "without errors"
    embed.add_embed_field(name="Process Complete", value="Completed {} \
            (exit code {}) in {} Seconds".format(
            was_error, p.returncode, duration), inline=False)
    if output:
        out_summary = trim_output(output, config.user['max_embed_lines']) 
    else:
        out_summary = "No data on STDOUT or STDERR."
    embed.add_embed_field(name="Stdout Summary", value=out_summary, inline=False) 
    
    # Add any requested image - TODO - fix this add to file attachment?
    if args.image: 
        embed.set_thumbnail(url='attachment://{}'.format(args.image))
    # Now send
    try:
        wh.edit(sent_wh)
    except Exception as e:
        bcolors.err("Failed to send update to Discord:\n{}".format(e))
    
    # Send any file on afterwards, to avoid conflictings file space/embed requirements
    if args.file:
        # Use a fresh webhook to avoid API limits and issues with large embeds
        filewh = DiscordWebhook(url=hook, \
                content="Here's the associated file for your job: {}.".format(
                args.command), username=user['username'])
        try:
            with open(args.file, "rb") as f:
                filewh.add_file(file=f.read(), filename=args.file)
                filewh.execute()
        except Exception as e:
            bcolors.err("Couldn't attach file : {} :\n{}".format(args.file, e))
    
    # Worker process cleanup
    stdout_worker.terminate()
    stdout_worker.join(5)


if __name__ == '__main__':
    main()
