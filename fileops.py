#!/usr/bin/env python
import fileinput
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
	for i in config:
		print(config[i]);
		if 'default' in config[i]:
			method = config[i]['default'];
			print('Default method: {0}'.format(method));
			if method in config[i]:
				value = config[i][method];
				print("Method allowed and has a default value of:\n\t{0}".format(value));
			elif 'allowWilds' in config[i]:	
				value = config[i]['default'];
				print("Method allows wildcards, current value is:\n\t{0}".format(value));
			else:
				print("Default method set to {0}, but supported methods are:\n\t{1}".format(method, list(config[i])));
		input();

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
	if config['Shellcode']['shellcode'] is not None:
		return config['Shellcode']['shellcode']

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
	if config['Redirector']['ip'] is not None and config['Redirector']['port'] is not None:
		return config['Redirector']['ip'], config['Redirector']['port']

def getX86Process(config):
	'''
	Gets the x86 process to replace from the config file.

	Returns x86 process string
	'''
	if config['Process']['x86'] is not None:
		return config['Process']['x86']

def getX64Process(config):
	'''
	Gets the x64 process to replace from the config file.

	Returns x64 process string
	'''
	if config['Process']['x64'] is not None:
		return config['Process']['x64']

def getSSLCache(config):
	'''
	Gets the SSLCache from the config file.

	returns SSLCache string
	'''
	if config['SSLCache']['SSL'] is not None:
		return config['SSLCache']['SSL']

