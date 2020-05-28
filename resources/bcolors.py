#Class for implementing colors in terminal apps.

HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

def two_format(c1_text, c2_Text, c1, c2=ENDC):
    return c1 + c1_text + ENDC + c2 + c2_tex2 + ENDC

def two_print(c1_text, c2_Text, c1, c2=ENDC):
    print(c1 + c2_text + ENDC + c2 + c2_text +ENDC)

def err_format(emphasis_text , body_text):
    return FAIL + emphasis_text + ENDC  + body_text + ENDC

def err_print(emphasis_text , body_text):
    print(FAIL + emphasis_text + ENDC  + body_text +ENDC)

def warn_format(emphasis_text , body_text):
    return WARNING + emphasis_text + ENDC  + body_text + ENDC

def warn_print(emphasis_text , body_text):
    print(WARNING + emphasis_text + ENDC + body_text +ENDC)

def green_format(emphasis_text , body_text):
    return OKGREEN + emphasis_text + ENDC +  body_text + ENDC

def green_print(emphasis_text , body_text):
    print(OKGREEN + emphasis_text + ENDC + body_text +ENDC)

def blue_format(emphasis_text , body_text):
    return OKBLUE + emphasis_text + ENDC +  body_text + ENDC

def blue_print(emphasis_text , body_text):
    print(OKBLUE + emphasis_text + ENDC + body_text +ENDC)

def bold_format(text):
    return BOLD + text + ENDC

def bold_print(emphasis_text, body_text):
    print(BOLD + emphasis_text + ENDC + body_text)

def warn(text, strong = True):
    warn_print("[!] ", "- " + text)

def err(text, strong = True):
    err_print("[!] ", "- " + text)

def success(text, strong = False):
    symb = '[+] ' if strong else '[-] '
    green_print(symb , "- " + text)

def info(text, strong = False):
    symb = '[+] ' if strong else '[-] '
    blue_print(symb, "- " + text)



if __name__ == '__main__':
    blue_print("[!] - ", "Welcome to main!")
