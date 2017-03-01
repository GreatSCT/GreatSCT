#!/usr/bin/env python
import re
import random
import string
from fileops import fileFindReplace

def encodeStringAsChr(shellCode):
	''' 
	Converts a string to VBA Chr() Encoding.

	Returns a encoded string
	'''
	encoded_string = ''
	i = 0
	for code in shellCode:
		i += 1
		if len(shellCode) == i:
			encoded_string += 'Chr(' + str(ord(code)) + ')'
		else:
			encoded_string += 'Chr(' + str(ord(code)) + ')&'

	return encoded_string

def convertToVBAFormat(intext):
	'''
	Converts a Chr() Encoded string into a VBA Array
	
	Returns list of strings
	'''
	chars = list(str(intext))

	chunks = []
	temp = []

	x = 0
	cont = True

	while cont == True:
		if x == len(chars):
			cont = False
			chunks.append(''.join(temp))
		elif x % 256 == 0 and x > 1:
			while chars[x] != '&':
				temp.append(chars[x])
				x += 1
			temp.append(chars[x])
			temp.append(' _\n')
			x += 1
			chunks.append(''.join(temp))
			temp = []
		else:
			temp.append(chars[x])
			x += 1

	return chunks

def getVBFunctions(file):
	functions = {}
	prog = re.compile(r'(function (\w+))', re.IGNORECASE)
	with open(file, 'r') as file:
		for line in file:
			if 'Function'in line:
				func = re.search(prog, line)
				if func:
					functions.update({func.groups()[1]:''.join(random.SystemRandom().choice(string.ascii_lowercase) for _ in range(10))})
			elif 'function' in line:
				func = re.search(prog, line)
				if func:
					functions.update({func.groups()[1]:''.join(random.SystemRandom().choice(string.ascii_lowercase) for _ in range(10))})
			else:
				pass

	return functions

def getVBVariables(file):
	variables = {}
	prog = re.compile(r'(Set (\w+))')
	prog2 = re.compile(r'(Dim (\w+))')

	with open(file, 'r') as file:
		for line in file:
			if 'Set' in line:
				var = re.search(prog, line)
				variables.update({var.groups()[1]:''.join(random.SystemRandom().choice(string.ascii_lowercase) for _ in range(10))})
			if 'Dim' in line:
				var2 = re.search(prog2, line)
				variables.update({var2.groups()[1]:''.join(random.SystemRandom().choice(string.ascii_lowercase) for _ in range(10))})
	return variables

def obfuscateVBFunctions(file):
	functions = getVBFunctions(file)

	for key, value in functions.items():
		fileFindReplace(file, key, value)

def obfuscateVBVariables(file):
	variables = getVBVariables(file)

	for key, value in variables.items():
		fileFindReplace(file, key, value)

