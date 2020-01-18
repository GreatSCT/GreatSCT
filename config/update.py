#!/usr/bin/python

import platform, os, sys, pwd

def which(program):
    path = os.getenv('PATH')
    for p in path.split(os.path.pathsep):
        p = os.path.realpath(os.path.join(p, program))
        if os.path.exists(p) and os.access(p, os.X_OK):
            return p
    return False


def validate_msfpath():
    msfpath = None
    while not msfpath:
        msfpath = input(" [>] Please enter the path of your metasploit installation: ")
        if not os.path.isfile(os.path.join(msfpath, 'msfvenom')):
            print("[!] Unable to detect metasploit at this path")
            msfpath = None
    options["METASPLOIT_PATH"] = msfpath
    options["MSFVENOM_PATH"] = msfpath

"""

Take an options dictionary and update /etc/greatsct/settings.py

"""
def generateConfig(options):

    config = """#!/usr/bin/python

##################################################################################################
#
# Great Scott configuration file
#
# Run update.py to automatically set all these options to their defaults.
#
##################################################################################################



#################################################
#
# General system options
#
#################################################

"""
    print("\n Great Scott configuration:")

    config += '# OS to use (Kali/Backtrack/Debian/Windows)\n'
    config += 'OPERATING_SYSTEM="' + options['OPERATING_SYSTEM'] + '"\n\n'
    print("\n [*] OPERATING_SYSTEM = " + options['OPERATING_SYSTEM'])

    config += '# Specific Linux distro\n'
    # check /etc/issue for the exact linux distro
    issue = open("/etc/issue").read()
    if issue.startswith("Debian"):
        config += 'DISTRO="Debian"\n\n'
    else:
        config += 'DISTRO="Linux"\n\n'

    config += '# Terminal clearing method to use (use "false" to disable it)\n'
    config += 'TERMINAL_CLEAR="' + options['TERMINAL_CLEAR'] + '"\n\n'
    print(" [*] TERMINAL_CLEAR = " + options['TERMINAL_CLEAR'])

    config += '# Wine environment\n'
    config += 'WINEPREFIX="' + options["WINEPREFIX"] + '"\n\n'
    print(" [*] WINEPREFIX = " + options["WINEPREFIX"])

    config += '# Path to temporary directory\n'
    config += 'TEMP_DIR="' + options["TEMP_DIR"] + '"\n\n'
    print(" [*] TEMP_DIR = " + options["TEMP_DIR"])

    config += '# Default options to pass to msfvenom for shellcode creation\n'
    config += 'MSFVENOM_OPTIONS="' + options['MSFVENOM_OPTIONS'] + '"\n\n'
    print(" [*] MSFVENOM_OPTIONS = " + options['MSFVENOM_OPTIONS'])

    config += '# The path to the metasploit framework, for example: /usr/share/metasploit-framework/\n'
    config += 'METASPLOIT_PATH="' + options['METASPLOIT_PATH'] + '"\n\n'
    print(" [*] METASPLOIT_PATH = " + options['METASPLOIT_PATH'])

    config += '# The path to msfvenom for shellcode generation purposes\n'
    config += 'MSFVENOM_PATH="' + options["MSFVENOM_PATH"] + '"\n\n'
    print(" [*] MSFVENOM_PATH = " + options["MSFVENOM_PATH"])


    config += """
#################################################
#
# GreatSCT-Bypass specific options
#
#################################################

"""
    config += '# GreatSCT-Bypass install path\n'
    config += 'GREATSCT_BYPASS_PATH="' + options['GREATSCT_BYPASS_PATH'] + '"\n\n'
    print(" [*] GREATSCT_BYPASS_PATH = " + options['GREATSCT_BYPASS_PATH'])

    source_path = os.path.expanduser(options["PAYLOAD_SOURCE_PATH"])
    config += '# Path to output the source of payloads\n'
    config += 'PAYLOAD_SOURCE_PATH="' + source_path + '"\n\n'
    print(" [*] PAYLOAD_SOURCE_PATH = " + source_path)

    # create the output source path if it doesn't exist
    if not os.path.exists(source_path):
        os.makedirs(source_path)
        print(" [*] Path '" + source_path + "' Created")

    compiled_path = os.path.expanduser(options["PAYLOAD_COMPILED_PATH"])
    config += '# Path to output compiled payloads\n'
    config += 'PAYLOAD_COMPILED_PATH="' + compiled_path +'"\n\n'
    print(" [*] PAYLOAD_COMPILED_PATH = " + compiled_path)

    # create the output compiled path if it doesn't exist
    if not os.path.exists( compiled_path ):
        os.makedirs( compiled_path )
        print(" [*] Path '" + compiled_path + "' Created")

    handler_path = os.path.expanduser(options["HANDLER_PATH"])
    # create the output compiled path if it doesn't exist
    if not os.path.exists( handler_path ):
        os.makedirs( handler_path )
        print(" [*] Path '" + handler_path + "' Created")

    config += '# Whether to generate a msf handler script and where to place it\n'
    config += 'GENERATE_HANDLER_SCRIPT="' + options['GENERATE_HANDLER_SCRIPT'] + '"\n'
    print(" [*] GENERATE_HANDLER_SCRIPT = " + options['GENERATE_HANDLER_SCRIPT'])
    config += 'HANDLER_PATH="' + handler_path + '"\n\n'
    print(" [*] HANDLER_PATH = " + handler_path)

    hash_path = os.path.expanduser(options["HASH_LIST"])
    config += '# Running hash list of all payloads generated\n'
    config += 'HASH_LIST="' + hash_path + '"\n\n'
    print(" [*] HASH_LIST = " + hash_path + "\n")

    if platform.system() == "Linux":
        # create the output compiled path if it doesn't exist
        if not os.path.exists("/etc/greatsct/"):
            os.system("sudo mkdir /etc/greatsct/")
            os.system("sudo touch /etc/greatsct/settings.py")
            os.system("sudo chmod 777 /etc/greatsct/settings.py")
            print(" [*] Path '/etc/greatsct/' Created")
        f = open("/etc/greatsct/settings.py", 'w')
        f.write(config)
        f.close()
        print(" Configuration File Written To '/etc/greatsct/settings.py'\n")
    else:
        print(" [!] ERROR: PLATFORM NOT CURRENTLY SUPPORTED")
        sys.exit()


if __name__ == '__main__':

    options = {}

    if platform.system() == "Linux":

        # check /etc/issue for the exact linux distro
        issue = open("/etc/issue").read()

        # resolve metasploit & msfvenom paths
        msfpath = os.path.dirname(which('msfvenom'))
        if os.path.isdir(msfpath) and os.path.isfile(os.path.join(msfpath, 'msfconsole')):
            options["METASPLOIT_PATH"] = msfpath
            if os.path.isfile(os.path.join(msfpath, 'msfvenom')):
                options["MSFVENOM_PATH"] = msfpath
            else:
                validate_msfpath()
        else:
            validate_msfpath()

        if issue.startswith("Kali"):
            options["OPERATING_SYSTEM"] = "Kali"
            options["TERMINAL_CLEAR"] = "clear"
        else:
            options["OPERATING_SYSTEM"] = "Linux"
            options["TERMINAL_CLEAR"] = "clear"

        # last of the general options
        options["TEMP_DIR"] = "/tmp/"
        options["MSFVENOM_OPTIONS"] = ""

        # Get the real user if we're being ran under sudo
        wineprefix = ""
        user = os.environ.get("SUDO_USER", pwd.getpwuid(os.getuid()).pw_name)
        if user == 'root':
            wineprefix = "/root/.greatsct/"
        else:
            wineprefix = "/home/{0}/.greatsct/".format(user)
        
        options["WINEPREFIX"] = wineprefix

        # GreatSCT-Bypass specific options
        greatsct_bypass_path = "/".join(os.getcwd().split("/")[:-1]) + "/"
        options["GREATSCT_BYPASS_PATH"] = greatsct_bypass_path
        options["PAYLOAD_SOURCE_PATH"] = "/usr/share/greatsct-output/source/"
        options["PAYLOAD_COMPILED_PATH"] = "/usr/share/greatsct-output/compiled/"
        options["GENERATE_HANDLER_SCRIPT"] = "True"
        options["HANDLER_PATH"] = "/usr/share/greatsct-output/handlers/"
        options["HASH_LIST"] = "/usr/share/greatsct-output/hashes.txt"

    # unsupported platform...
    else:
        print(" [!] ERROR: PLATFORM NOT CURRENTLY SUPPORTED")
        sys.exit()

    generateConfig(options)
