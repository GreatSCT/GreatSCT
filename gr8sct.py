from display import *
from fileOps import *
from completer import *

import readline
import threading
import time

configDir = "./config/"

display = Display()
fileOps = FileOps(configDir)
completer = Completer()

class State():
	prevState = None
	currentState = None
	selection = None
	suppliedVal = None
	transMap = {}
	
	def transition(self, selection, suppliedVal = None):
	
		try:
			nextState = eval(self.transMap[selection])
		except KeyError:
			nextState = eval(self.currentState)

		nextState.selection = selection
		nextState.suppliedVal = suppliedVal
		nextState.prevState = self.__class__.__name__
		nextState.currentState = nextState().__class__.__name__

		return(nextState().run())

	def run(self):
		readline.set_completer(completer.check)
		readline.set_completer_delims("")
		readline.parse_and_bind("tab: complete")


class Intro(State):
	transMap = {"help": "Help", "exit": "Exit", "generateAll": "ConfigAllEdit"}

	def firstRun(self):
		self.currentState = "Intro" #seed currentState to return here if invalid selection is set, this is auto preformed in transistion() for future states 
		display.clear()
		display.init()
		input("{0}Enter any key to begin, \"help\", or \"exit\" at any time: {1}".format(display.GREEN, display.ENDC))
		self.run()

	def run(self):
		super().run()

		display.clear()
		display.prompt("Loaded modules from: {0}\n".format(fileOps.getConfigDir()))

		configs = fileOps.getConfigs()
		for i, f in enumerate(configs):
			display.prompt("{0}\t[{1}]{2}  ".format(display.GREEN, i, display.ENDC), '')
			display.prompt(f)
			self.transMap[f] = "ConfigEdit"

		display.prompt("\n\tor\n\n\t{0}generateAll{1}".format(display.GREEN, display.ENDC))
		completer.setCommands(list(self.transMap.keys()))

		#display.prompt("\nPlease select a module to use: ", '')

		selection = input("\nPlease select a module to use: ")
		if selection.isdigit():
			selection = configs[int(selection)]

		fileOps.loadConfig(selection)
		self.transition(selection)

class ConfigAllEdit(State):
	#This code intentionally obfuscated to prevent IP theft... no really, why are you laughing...
	#luckily this can be added withouut changing any other code
	#once there's time an actually designed class with the same inputs/outputs can be swapped in

	transMap = {"exit": "Exit", "menu": "Intro", "help": "Help", "generate": "GenerationPrompt"}
	optionsMap = {}
	multipleApplicable = {}
	configMap = []
	configsLoaded = False
	multipleSelection = False
	multipleOption = ''
	multipleIndex = []
	setValue = ''
	genInProgress = False
	generationIndex = []

	def run(self):
		super().run()
		display.clear()
		completer.setCommands(list(self.transMap.keys()))
		
		if ConfigAllEdit.genInProgress:
			self.generateAll()

		display.prompt("Configure all supported payloads for network detection testing\n")

		optionNum = 0
		if not self.configsLoaded:
			for config in fileOps.getConfigs():
				curConfig = fileOps.loadConfig(config)
				display.prompt("{0}\n{1}\n".format(config, curConfig.get("Type", "info")))
				optionNum = self.parse(curConfig, optionNum)
				self.configMap.append({curConfig.get("Type", "name"): config, "config": curConfig}) #sometimes you write a line and it's hard to keep a straight face
			ConfigAllEdit.configsLoaded = True

		elif self.configsLoaded:
			name = ''
			for entry in self.configMap:
				for i in list(entry.keys()):
					if i != "config":
						name = entry[i]
				curConfig = entry["config"]
				display.prompt("{0}\n{1}\n".format(name, curConfig.get("Type", "info")))
				optionNum = self.parse(curConfig, optionNum)

		display.prompt("Or\nSet for all applicable payloads\n")


		tempDict = {}
		for option in self.multipleApplicable:
			numSpaces = 40
			numSpaces = numSpaces - (len(str(optionNum))+len(option))
			display.prompt("\t{0}[{1}] {2}:{3}{4}{5}".format(display.GREEN, optionNum, option, 
									  display.ENDC, ' '*numSpaces, self.multipleApplicable[option]))
			tempDict[str(optionNum)] = option
			optionNum = optionNum+1
		self.multipleApplicable = {**self.multipleApplicable, **tempDict} #...I have nothing to say for myself
	
		

		if self.multipleSelection:
			self.editMultipleEntries()
	
		selection = input("\nSelect an option to edit, {0}generate{1}, or {2}exit{3}: ".format(display.GREEN, display.ENDC, display.GREEN, display.ENDC))
	
		singleSelection = False
	
		if selection.startswith("set "):
			option = selection.split(" ")[1]
			self.suppliedVal = selection.split(option+" ", 1)[-1]
	
			if self.suppliedVal == "":
				selection = "invalid"

			selection = option
		
		if selection.isdigit():
			try:
				selection = self.optionsMap[selection]
				singleSelection = True
				for i in self.configMap:
					try:
						if i[selection["config"]]:
							fileOps.setCurrentConfig(i["config"]) #Donald Knuth forgive me
					except KeyError:
						continue
				selection = selection["option"]
			except KeyError:
				try:
					selection = self.multipleApplicable[selection]
					ConfigAllEdit.multipleSelection = True
					ConfigAllEdit.multipleOption = selection
					ConfigAllEdit.setValue = self.suppliedVal
				except KeyError:
					selection = "invalid"

		else: 
			if selection == "generate":
				ConfigAllEdit.genInProgress = True
				self.generateAll()

			#TODO: burn this with fire also it exits if you enter a bad option name
			elif selection == "exit" or selection == "help" or selection == "menu" or selection == "":
				self.transition(selection)
				
			elif selection in list(self.multipleApplicable.keys()):
				ConfigAllEdit.multipleSelection = True
				ConfigAllEdit.multipleOption = selection
				ConfigAllEdit.setValue = self.suppliedVal

			else:
				for i in list(self.optionsMap.keys()):
					name = selection[:selection.find('.')]
					option = selection[selection.find('.')+1:]
					if self.optionsMap[i]["config"] == name and self.optionsMap[i]["option"] == option:
						for j in self.configMap:
							try:
								if j[name]:
									fileOps.setCurrentConfig(j["config"])
									selection = option
									singleSelection = True
							except KeyError:
								continue
			
					


		if singleSelection:
			self.transition(selection, self.suppliedVal)
		
		if self.multipleSelection:
			self.editMultipleEntries()


	def editMultipleEntries(self): #Marcus did a bad thing
			if ConfigAllEdit.setValue == '' or ConfigAllEdit.setValue == None:
				ConfigAllEdit.setValue = input("Please enter a value for "+ConfigAllEdit.multipleOption+": ")

			for option in self.optionsMap:
				#input(self.optionsMap[option]["option"]+" "+self.optionsMap[option]["config"]+" "+ConfigAllEdit.multipleOption)
				if self.optionsMap[option]["option"] == ConfigAllEdit.multipleOption:
					for j in self.configMap:
						try:
							if j[self.optionsMap[option]["config"]] not in ConfigAllEdit.multipleIndex:
								fileOps.setCurrentConfig(j["config"])
								ConfigAllEdit.multipleIndex.append(j[self.optionsMap[option]["config"]])
								self.transition(self.multipleOption, ConfigAllEdit.setValue)
						except KeyError:
							continue
			ConfigAllEdit.multipleSelection = False
			ConfigAllEdit.multipleIndex = []
			ConfigAllEdit.multipleOption = ''
			ConfigAllEdit.setValue = ''
			
	def parse(self, config, curOptionNum):

		cfgName = ''
		for section_name in config:

			section = config[section_name]
			if section_name == "DEFAULT":
				continue

			if section_name == "Type":
				cfgName = section["name"]
				continue

			if section_name == "Output":
				continue
			

			#TODO: this dies if one of the cfgs has a .swp file in the same dir
			numTabs = 50
			numTabs = numTabs - (len(cfgName)+len(section_name)+len(str(curOptionNum)))

			
			display.prompt("{0}\t[{1}] {2}.{3}:{4}{5}{6}".format(display.GREEN, curOptionNum, cfgName, section_name, display.ENDC, '-'*numTabs, section["var"]))
		
			
			self.transMap[section_name] = "OptionEdit"
			self.optionsMap[str(curOptionNum)] = {"config": cfgName, "option": section_name}
			completer.addCommand(cfgName+'.'+section_name)
			completer.addCommand("set " + cfgName+'.'+section_name)
			completer.addCommand("set " + str(curOptionNum))
			curOptionNum += 1
			
			#if list(self.optionsMap.values()).count(section_name) > 1 and section_name not in self.multipleApplicable.values():
			#	self.multipleApplicable[section_name] = section["var"]

			if section_name not in self.multipleApplicable.values():
				count = 0
				for i in list(self.optionsMap.values()):
					if i["option"] == section_name:
						count = count+1
					if count > 1:
						self.multipleApplicable[section_name] = section["var"]

		display.prompt("")


		return(curOptionNum)

	def generateAll(self):
		for i in self.configMap:
			if i["config"] not in ConfigAllEdit.generationIndex:
				fileOps.setCurrentConfig(i["config"])
				i["config"]["Output"]["var"] = "./GenerateAll/" + i["config"]["Output"]["var"]
				ConfigAllEdit.generationIndex.append(i["config"])
				self.transition("generate")
		ConfigAllEdit.genInProgress = False
		ConfigAllEdit.generationIndex = []
		self.transition("exit")

class ConfigEdit(State):
	transMap = {"exit": "Exit", "menu": "Intro", "help": "Help", "generate": "GenerationPrompt"}	
	optionsMap = {}	#will become a dict of {"0": "optionA" "1": "optionB"}
			#allows number input since the 0th actual content of config
			#will likely be DEFAULT, help or type data	
	
	def run(self):
		super().run()

		display.clear()
		display.prompt("Payload Editor\n")
		
		config = fileOps.getCurrentConfig()

		completer.setCommands(list(self.transMap.keys()))
		self.parse(config)

		selection = input("Select an option to edit, {0}generate{1}, or {2}exit{3}: ".format(display.GREEN, display.ENDC, display.GREEN, display.ENDC))
	
		#Not sure if these checks are needed	
		if selection.startswith("set "):
			option = selection.split(" ")[1]
			self.suppliedVal = selection.split(option+" ", 1)[-1]
	
			if self.suppliedVal == "":
				selection = "invalid"

			selection = option
		
		if selection.isdigit():
			try:
				selection = self.optionsMap[selection]
			except KeyError:
				selection = "invalid"

		self.transition(selection, self.suppliedVal)
			

	def parse(self, config):

		optionNum = 0
		for section_name in config:

			if section_name == "DEFAULT":
				continue

			section = config[section_name]
			if section_name == "Type":
				display.prompt("Selected Payload: {0}\n".format(section["info"]))

			else:
				numTabs = 1
				if len(section_name) < 12: numTabs = 2

				display.prompt("{0}\t[{1}] {2}:{3}{4}{5}".format(display.GREEN, optionNum, section_name, display.ENDC, '\t'*numTabs, section["var"]))
				
				self.transMap[section_name] = "OptionEdit"
				self.optionsMap[chr(optionNum+48)] = section_name
				completer.addCommand(section_name)
				completer.addCommand("set " + section_name)
				completer.addCommand("set " + chr(optionNum+48))
				optionNum += 1
			
			section = config[section_name]
		display.prompt("")


class OptionEdit(State):
	transMap = {"exit": "Exit", "ConfigEdit": "ConfigEdit", "ConfigAllEdit": "ConfigAllEdit"}

	validParams = []
	
	def run(self):
		config = fileOps.getCurrentConfig()
		option = config[self.selection]
		self.validParams = self.parseOptions(option)

		if self.suppliedVal == None:
			outstring = ''
			outstring = outstring + "Enter a value for [{0}]: (Valid options are: [".format(self.selection)
			for param in self.validParams:
				outstring = outstring + "\'{0}{1}{2}\'".format(display.GREEN, param, display.ENDC)
				
				if param != self.validParams[-1]:
					outstring = outstring + ', '

			outstring = outstring + "]): "			

			self.suppliedVal = input(outstring)

		if self.suppliedVal in self.validParams or "allowWilds" in self.validParams:
			fileOps.updateCurrentConfig(self.selection, self.suppliedVal)

		self.transition(self.prevState)

		
		#TODO: Move valid param checking to fileops	
	def parseOptions(self, option):
		validParams = []

		#TODO: just found this var, I don't know why it's here	
		optionString = 	""
		for validParam in option:

			if validParam == "var" or validParam == "help":
				continue

			validParams.append(validParam)

		return validParams				



class GenerationPrompt(State):

	def run(self):
		config = fileOps.getCurrentConfig()
		t1 = threading.Thread(target = fileOps.generate, args = [config])

		t1.start()

		i = 1
		end = ['/', '-', '\\', '|']
		while t1.is_alive():
			display.prompt("Generating: "+"="*i+end[i%4], '\r')
			time.sleep(0.3)
			i = i+1

		t1.join()
		display.prompt("{0}Generating: 8{1}D{2}\n".format(display.GREEN, '='*i, display.ENDC))

		info = config["Type"]["runInfo"]
		display.prompt("{0}Execute with: {1}".format(display.GREEN, display.ENDC), '')
		display.prompt(info, '\n\n')
		

class Help(State):
	transMap = {"Help": "Help", "Intro": "Intro", "ConfigEdit": "ConfigEdit", "ConfigAllEdit": "ConfigAllEdit", "GenerationPrompt": "GenerationPrompt"}
	
	def run(self):
		display.clear()
			
		if self.prevState == "Intro":
			display.prompt("Select a payload module by index ['#'] or name\n\tValid options are:\n")
		
			#TODO this is used in multiple states, move it to super	
			configs = fileOps.getConfigs()
			for i, f in enumerate(configs):
				conf = fileOps.loadConfig(f)
				helpStr = ''
				numTabs = 1
				if len(f) < 19: numTabs = 2

				try:
					helpStr = conf.get("Type", "info")	
				except Exception:
					helpStr = ''

				display.prompt("{0}\t[{1}]  {2}{3}{4}{5}".format(display.GREEN, i, f, display.ENDC, '\t'*numTabs, helpStr))

			display.prompt("\n{0}\tgenerateAll{1}\t\t\tGenerate all payloads for network testing".format(display.GREEN, display.ENDC))
			

		elif self.prevState == "ConfigEdit":
			config = fileOps.getCurrentConfig()
			optionNum = 0
			for section_name in config:

				if section_name == "DEFAULT":
					continue

				section = config[section_name]
				if section_name == "Type":
					display.prompt("The selected payload: {0}{1}{2}\nhas the following options:\n".format(display.GREEN, section["info"], display.ENDC))
					display.prompt("\tOptionName\t\tDefault Value\t\tAllowed Values")

				else:
					allowedValSpaces = 24
					allowedValSpaces = allowedValSpaces-len(str(section["var"]))
					validParams = []
				
					for validParam in section:

						if validParam == "var" or validParam == "help":
							continue

						validParams.append(validParam)
					
					helpStrSpaces = 43-len(str(validParams))

					numTabs = 1
					if len(section_name) < 12: numTabs = 2

					helpStr = ""
					try:
						helpStr = section["help"]
					except KeyError:
						helpStr = ""

					display.prompt("{0}\t[{1}] {2}:{3}{4}{5}{6}{7}{8}{9}".format(display.GREEN, optionNum, section_name, display.ENDC, 
												'\t'*numTabs, section["var"], ' '*allowedValSpaces, str(validParams),
												' '*helpStrSpaces, helpStr))
					optionNum += 1
				
				section = config[section_name]

			#TODO: just realized we can reuse color vars {0} and {1}, need to apply throughout
			display.prompt("\nValues may be changed by entering: {0}#{1}, {0}OptionName{1}, {0}set # value{1}, or {0}set OptionName value{1}".format(display.GREEN, display.ENDC))


			
		
		elif self.prevState == "ConfigAllEdit":
			display.prompt("The Generate All editor is used to generate all payloads, and an accompanying execution script.")
			display.prompt("It's primary use is to test the application whitlisting solution on your network against the")
			display.prompt("newest application whitelisting bypasses.\n")

			display.prompt("After setting each payload for a testing C2 server, {0}generate{1} can be entered.".format(display.GREEN, display.ENDC))
			display.prompt("The payloads, and an accompanying powershell test script, will be output in ./GenerateAll/")
			display.prompt("Copy this folder to a testing Windows box and execute the script to see which bypasses you are vulnerable to.")
			
	
			display.prompt("\n\nFor detailed information on each payload's options enter {0}menu{1}, select the payload, then enter {0}help{1}".format(display.GREEN, display.ENDC))

		elif self.prevState == "GenerationPrompt":
			display.prompt("Shouldn't be able to get here")

		elif self.prevState == "Help":
			display.prompt("Shouldn't be able to get here")

		display.prompt("\nYou may enter {0}menu{1} at any time to return to the inital payload selection.\n".format(display.GREEN, display.ENDC))

		#hacky
		selection = input("Enter any key to return to the previous menu: ")
		if selection == "menu":
			self.prevState = "Intro"

		self.transition(self.prevState)



class Exit(State):

	def run(self):
		exit(0)
	

def main():
	intro = Intro()
	intro.firstRun()
	


if __name__ == '__main__':
	try:
		main()

	except KeyboardInterrupt:
		print('')
		exit(0)
	
	except EOFError:
		print('')
		exit(0)
