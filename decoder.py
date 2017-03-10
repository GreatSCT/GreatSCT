#!/usr/bin/env python

def decodeChrArray(text):
	encoded_list = text.replace('C', 'c').split('&')
	d = []
	for char in encoded_list:
		if "xlmodule.codeModule.AddFromString" in char:
			d.append(eval(char.replace('xlmodule.codeModule.AddFromString ', '')))
		elif '_' in char:
			continue
		else:
			d.append(eval(char))

	decoded_text = ''.join(d)

	return decoded_text