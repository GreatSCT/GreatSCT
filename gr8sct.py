#!/usr/bin/env python
import configparser
from fileops import *
from generator import genSCT

'''
The main program for Great SCT. Great Scott Marty, this project 
aims to make COM scriptlet payloads great agian.

See config/default.cfg for an example configuration file.
'''

# Global Variables
config = configparser.ConfigParser()
# Read the default configuration file
config.read('./config/default.cfg')
parse(config);
input();
# Get and set the config options
framework = getFramework(config)
shellcode = getShellCode(config)
stagingMethod = getStagingMethod(config)
redirector = getRedirector(config)
x86process = getX86Process(config)
x64process = getX64Process(config)
sslCache = getSSLCache(config)

# Main
genSCT(framework, stagingMethod, redirector, x86process, x64process)
