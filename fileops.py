#!/usr/bin/env python
import fileinput
from os import listdir
import itertools
import configparser

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
	Raises:
		configparser.NoOptionError: config option doesn't exist
	'''
	try:
		if config.has_option('Framework', 'framework'):
			if 'CobaltStrike' in config.get('Framework', 'framework'):
				return config.get('Framework', 'framework')
			elif 'Metasploit' in config.get('Framework', 'framework'):
				return config.get('Framework', 'framework')
			elif 'Empire' in config.get('Framework', 'framework'):
				return config.get('Framework', 'framework')
			else:
				print('Invalid configuration option for framework. \
					Please provide a valid framework, \
					i.e. CobaltStrike, Metasploit, Empire')
	except configparser.NoOptionError:
		print('Not a valid option')


def getShellCode(config):
	'''
	Gets the shellcode from the config file.

	Args:
		config (object): configparser.ConfigParser object
	Returns:
		config (string): the shellcode config value
	Raises:
		configparser.NoSectionError: config section doesn't exist
	'''
	try:
		if config.get('Framework', 'shellcode'):
			return config.get('Framework', 'shellcode')
	except configparser.NoSectionError:
		print('Not a valid option')

def getStagingMethod(config):
	'''
	Gets the staging method from the config file.

	Args:
		config (object): configparser.ConfigParser object
	Returns:
		config (string): the StagingMethod config value
	Raises:
		configparser.NoSectionError: config section doesn't exist
	'''
	try:
		if 'regsvr32' in config.get('StagingMethod', 'method'):
			return config.get('StagingMethod', 'regsvr32')
		elif 'VBGetObject' in config.get('StagingMethod', 'method'):
			return config.get('StagingMethod', 'VBGetObject')
		elif 'VBAMacro' in config.get('StagingMethod', 'method'):
			return config.get('StagingMethod', 'VBAMacro')
		elif 'DLLInject' in config.get('StagingMethod', 'method'):
			return config.get('StagingMethod', 'DLLInject')
		else:
			print('[StagingMethod] --> method must be one of the \
				following options: regsvr32, VBGetObject, VBAMacro, DLLInject')
	except configparser.NoSectionError:
		print('Not a valid option')

def getRedirector(config):
	'''
	Gets the redirector info from the config file.

	Args:
		config (object): configparser.ConfigParser object
	Returns:
		config (list): ip address and port strings
	Raises:
		configparser.NoSectionError: config section doesn't exist
	'''
	try:
		if config.get('RedirectorDomain', 'ip') and config.get('RedirectorDomain', 'port'):
			return config.get('RedirectorDomain', 'ip'), config.get('RedirectorDomain', 'port')
	except configparser.NoSectionError:
		print('Not a valid option')

def getX86Process(config):
	'''
	Gets the x86 process to replace from the config file.

	Args:
		config (object): configparser.ConfigParser object
	Returns:
		config (string): the ProcessInjection x86 config value
	Raises:
		configparser.NoSectionError: config section doesn't exist
	'''
	try:
		if config.get('ProcessInjection', 'x86'):
			return config.get('ProcessInjection', 'x86')
	except configparser.NoSectionError:
		print('Not a valid option')

def getX64Process(config):
	'''
	Gets the x64 process to replace from the config file.

	Args:
		config (object): configparser.ConfigParser object
	Returns:
		config (string): the ProcessInjection x64 config value
	Raises:
		configparser.NoSectionError: config section doesn't exist
	'''
	try:
		if config.get('ProcessInjection', 'x64'):
			return config.get('ProcessInjection', 'x64')
	except configparser.NoSectionError:
		print('Not a valid option')

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

def getFileSectionByLineNum(file, begidx, endidx):
	'''
	Gets a section or chunk of a file based on line numbers

	Args:
		file (string): name of the file
		begidx (int): line number
		endidx (int): line number
	Returns:
		values (list): returns a list of the file section's strings
	'''
	with open(file, 'r') as payloadFile:
		values = []
		for line in itertools.islice(payloadFile, begidx, endidx):
			values.append(line)

	return values
