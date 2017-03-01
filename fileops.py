#!/usr/bin/env python
import fileinput
from os import listdir

'''
This module is used for file operations.
'''

def fileFindReplace(filename, find, replace):
	'''
	Find and replace a string in a file.

	Args:
		filename (string): name of the file
		find  (string): string to find
		replace (string): string to replace
	'''
	for line in fileinput.input(filename, inplace=True):
		line = line.rstrip().replace(find, replace)
		print(line)

def parse(config):
	'''
	Function to dynamically parse configparser.ConfigParser object

	Args:
		config (object): configparser.ConfigParser object
	'''
	for section_name in config:
	    print('Section:', section_name)
	    section = config[section_name]
	    print('  Options:', list(section.keys()))
	    for name in section:
	        print('  {} = {}'.format(name, section[name]))
	    print()

def getFramework(config):
	'''
	Gets the framework from the config file.

	Args:
		config (object): configparser.ConfigParser object
	Returns:
		config (string): the Framework config value
	'''
	if 'CobaltStrike' in config['Framework']['framework']:
		return config['Framework']['framework']
	elif 'Metasploit' in config['Framework']['framework']:
		return config['Framework']['framework']
	elif 'Empire' in config['Framework']['framework']:
		return config['Framework']['framework']
	else:
		print('Invalid configuration option for framework. \
			Please provide a valid framework, \
			i.e. CobaltStrike, Metasploit, Empire')

def getShellCode(config):
	'''
	Gets the shellcode from the config file.

	Args:
		config (object): configparser.ConfigParser object
	Returns:
		config (string): the shellcode config value
	'''
	if config['Framework']['shellcode'] is not None:
		return config['Framework']['shellcode']

def getStagingMethod(config):
	'''
	Gets the staging method from the config file.

	Args:
		config (object): configparser.ConfigParser object
	Returns:
		config (string): the StagingMethod config value
	'''
	if 'regsvr32' in config['StagingMethod']['method']:
		return config['StagingMethod']['regsvr32']
	elif 'VBGetObject' in config['StagingMethod']['method']:
		return config['StagingMethod']['VBGetObject']
	elif 'VBAMacro' in config['StagingMethod']['method']:
		return config['StagingMethod']['VBAMacro']
	elif 'DLLInject' in config['StagingMethod']['method']:
		return config['StagingMethod']['DLLInject']
	else:
		print('[StagingMethod] --> method must be one of the \
			following options: regsvr32, VBGetObject, VBAMacro, DLLInject')

def getRedirector(config):
	'''
	Gets the redirector info from the config file.

	Args:
		config (object): configparser.ConfigParser object
	Returns:
		config (list): ip address and port strings
	'''
	if config['RedirectorDomain']['ip'] is not None and config['RedirectorDomain']['port'] is not None:
		return config['RedirectorDomain']['ip'], config['RedirectorDomain']['port']

def getX86Process(config):
	'''
	Gets the x86 process to replace from the config file.

	Args:
		config (object): configparser.ConfigParser object
	Returns:
		config (string): the ProcessInjection x86 config value
	'''
	if config['ProcessInjection']['x86'] is not None:
		return config['ProcessInjection']['x86']

def getX64Process(config):
	'''
	Gets the x64 process to replace from the config file.

	Args:
		config (object): configparser.ConfigParser object
	Returns:
		config (string): the ProcessInjection x64 config value
	'''
	if config['ProcessInjection']['x64'] is not None:
		return config['ProcessInjection']['x64']

def getAvailableConfigs():
	'''
	Gets all of the available cfg files in ./config

	Returns:
		configs (list): config file names
	'''

	configs = []

	for file in listdir("./config"):
		if file.endswith(".cfg"):
			configs.append(file.strip('.cfg'))

	return configs

def getFileStringLineNum(find):
	'''
	Gets the line number of a string in a file

	Returns:
		num (int): line number
	'''
	with open('payload.sct', 'r') as payloadFile:
		for num, line in enumerate(payloadFile, 1):
			if find in line:
				return num
