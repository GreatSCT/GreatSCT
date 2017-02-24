#!/usr/bin/env python
import re

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
