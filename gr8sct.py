#!/usr/bin/env python
from uuid import uuid4
from string import ascii_uppercase, digits
from random import choice
import fileinput
from shutil import copyfile

def genClassID():
	return uuid4()

def genSCT():
	copyfile('payload_template.sct', 'payload.sct')
	fileFindReplace('payload.sct', 'exampleprogid', genProgID())
	fileFindReplace('payload.sct', 'exampleclassid', str(genClassID()))


def genProgID(size=8, chars=ascii_uppercase + digits):
	progid = ''.join(choice(chars) for _ in range(size))
	return progid


def fileFindReplace(filename, find, replace):
	for line in fileinput.input(filename, inplace=True):
		line = line.rstrip().replace(find, replace)
		print(line)

genSCT()
