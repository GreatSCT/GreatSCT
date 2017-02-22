#!/usr/bin/env python
import fileinput
from os import listdir

'''
This module is used for file operations.
'''

def fileFindReplace(filename, find, replace):
	'''
	Find and replace a string in a file.
	'''
	for line in fileinput.input(filename, inplace=True):
		line = line.rstrip().replace(find, replace)
		print(line)

def parse(config):
	'''
	Function to dynamically parse configparser.ConfigParser object
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

	Returns a shellcode string
	'''
	if config['Framework']['shellcode'] is not None:
		return config['Framework']['shellcode']

def getStagingMethod(config):
	'''
	Gets the staging method from the config file.

	Returns stagingMethod string
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

	Returns a list of ip address and port
	'''
	if config['RedirectorDomain']['ip'] is not None and config['RedirectorDomain']['port'] is not None:
		return config['RedirectorDomain']['ip'], config['RedirectorDomain']['port']

def getX86Process(config):
	'''
	Gets the x86 process to replace from the config file.

	Returns x86 process string
	'''
	if config['ProcessInjection']['x86'] is not None:
		return config['ProcessInjection']['x86']

def getX64Process(config):
	'''
	Gets the x64 process to replace from the config file.

	Returns x64 process string
	'''
	if config['ProcessInjection']['x64'] is not None:
		return config['ProcessInjection']['x64']

def getAvailableConfigs():
	'''
	Gets all of the available cfg files in ./config

	Returns a list of the config files.
	'''

	configs = []

	for file in listdir("./config"):
		if file.endswith(".cfg"):
			configs.append(file)

	return configs
