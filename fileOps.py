import os
import socket
from configparser import ConfigParser, ExtendedInterpolation
from generator import Generator

"""
This module is used for file operations.
"""


class FileOps():
    """
    This class is used for file operations.
    """
    configDir = ''
    selectedConfig = None

    def __init__(self, configDir):
        """
        Initalize the FileOps class

        :params configDir: the config directory
        :type configDir: string
        """
        FileOps.configDir = configDir

    def getConfigs(self):
        """
        Get the configuration files and return them

        :returns: configs
        :rtype: list
        """
        fileList = []

        # http://stackoverflow.com/questions/16953842/using-os-walk-to-recursively-traverse-directories-in-python
        for base, dirs, files in os.walk(FileOps.configDir):
            path = base.split(FileOps.configDir)[-1]
            for f in files:
                filePath = "{0}/{1}".format(path, f)
                fileList.append(filePath)
        return(fileList)

    def getConfigDir(self):
        """
        Get the config directory

        :returns: FileOps.configDir
        :rtype: string
        """
        return(FileOps.configDir)

    def loadConfig(self, configName):
        """
        Loads a config file

        :param configName: name of the config file
        :type configName: string
        :returns: FileOps.selectedConfig
        :rtype: ConfigParser.Object
        """
        FileOps.selectedConfig = ConfigParser(interpolation=ExtendedInterpolation(), comment_prefixes=None)
        FileOps.selectedConfig.optionxform = str  # disable configparser convert data to lowercase
        FileOps.selectedConfig.read("{0}{1}".format(FileOps.configDir, configName))

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            FileOps.updateCurrentConfig(self, "ListenerDomain", ip)
            FileOps.updateCurrentConfig(self, "HostedDomain", "http://" + ip)
        except:
            pass

        return(FileOps.selectedConfig)

    def setCurrentConfig(self, configObj):
        """
        Sets the current config

        :param configObj: config object
        :type configObj: ConfigParser.Object
        """
        FileOps.selectedConfig = configObj

    def updateCurrentConfig(self, option, value):
        """
        Updates the current config

        :param option: config option to update
        :param value: value to change config option
        :type option: string
        :type value: string
        """
        FileOps.selectedConfig[option]["var"] = value

    def getCurrentConfig(self):
        """
        Gets the current config

        :returns: FileOps.selectedConfig
        :rtype: ConfigParser.Object
        """
        return(FileOps.selectedConfig)

    def generate(self, config):
        """
        Generates a payload from a config file

        :param config: config file to generate
        :type config: string
        :returns: template
        :rtype: ConfigParser.Object
        """
        template = ConfigParser(interpolation=ExtendedInterpolation(), comment_prefixes=None)
        template.optionxform = str
        template.read(FileOps.selectedConfig["Type"]["template"])

        return (self.genFromTemplate(template))

    def genFromTemplate(self, template):
        """
        Generates a payload from a template

        :param template: template
        :type template: string
        :returns: runInfo
        :rtype: string

        """
        processingMap = {"chrEncode": FileOps.genChrArray}

        framework = ''
        domain = ''
        port = ''
        params = []
        outfile = "output.gr8sct"
        runInfo = ''
        preserveWhitespace = False

        for config_section in FileOps.selectedConfig:
            if config_section != "DEFAULT" and config_section != "Type":
                var = FileOps.selectedConfig[config_section]["var"]
                params.append([config_section, var])

            if config_section == "Type":
                runInfo = FileOps.selectedConfig[config_section]["runInfo"]
                name = FileOps.selectedConfig[config_section]["name"]

            if config_section == "Output":
                outfile = FileOps.selectedConfig[config_section]["var"]

            if config_section == "Framework":
                framework = FileOps.selectedConfig[config_section]["var"]
            elif config_section == "ListenerDomain":
                domain = FileOps.selectedConfig[config_section]["var"]
            elif config_section == "ListenerPort":
                port = FileOps.selectedConfig[config_section]["var"]
            elif config_section == "Payload":
                payload = FileOps.selectedConfig[config_section]["var"]

        generator = Generator()

        for template_section in template:
            section = template[template_section]
            if template_section == "ShellCodex64":
                extraProcessing = None
                try:
                    extraProcessing = section["process"]
                except KeyError:
                    extraProcessing = None

                if framework == "CobaltStrike":
                    shellcodex64 = generator.encodeShellcode(section["value"], payload, extraProcessing)
                    section["value"] = shellcodex64
                else:
                    # Metasploit 64 bit shellcode generation
                    shellcodex64 = generator.genShellcode(domain, port, "x64", name, payload, extraProcessing)
                    section["value"] = shellcodex64

            elif template_section == "ShellCodex86" or template_section == "ShellCode":
                extraProcessing = None
                try:
                    extraProcessing = section["process"]
                except KeyError:
                    extraProcessing = None

                if framework == "CobaltStrike":
                    # shellcodex86 = input('Paste your CobaltStrike shellcode')
                    # section["value"] = shellcodex86
                    shellcodex86 = generator.encodeShellcode(section["value"], payload, extraProcessing)
                    section["value"] = str(shellcodex86)
                else:
                    shellcodex86 = generator.genShellcode(domain, port, "x86", name, payload, extraProcessing)
                    section["value"] = shellcodex86

            elif template_section == "Processing":
                try:
                    section["value"] = processingMap[section["process"]](section["value"])
                except KeyError:
                    print("Error: Template Processing type {0} is not supported".format(section["process"]))

            elif template_section == "PreserveWhitespace":
                preserveWhitespace = section["value"]

            else:
                for param in params:
                    if template_section == param[0]:
                        section["value"] = param[1]

        payload = template.get("Template", "data")

        f = open(outfile, "w+")

        if preserveWhitespace == "True":
            payloadLines = payload.splitlines(keepends=True)
            for line in payloadLines:
                f.write(line[1:])

        else:
            f.write(payload)

        return runInfo

    def genChrArray(text):
        """
        Generate a Chr array for VBScript payloads

        :param text: text to convert to chr array
        :type text: string
        :returns: newText
        :rtype: string
        """
        i = 0
        newText = ''
        for character in text:
            if i < 31:
                newText += "Chr({0})&".format(ord(character))
                i = i+1
            else:
                newText += "Chr({0})& _ \n".format(ord(character))
                i = 0

        if i != 0:
            newText = newText[0:-1]

        else:
            newText = newText[0:-5]

        return newText

    def fileCleanUp(self):
        """
        Cleans up files written to disk
        """
        files = ["./GenerateAll/gr8sct.rc", "./GenerateAll/analyst.csv",
                 "./GenerateAll/gr8sct.bat"]
        for f in files:
            try:
                os.remove(f)
            except FileNotFoundError:
                pass
