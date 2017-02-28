#!/usr/bin/env python
import os
import cmd
from fileops import *
from configparser import ConfigParser
from generator import genSCT

'''
This module is used for displaying information and interactive cli.
'''


class Display(cmd.Cmd):
	'''
	Initialize the object to clear the screen
	'''
	prompt = '(Great SCT) '
	intro = """                     ______,------'--"-.
                    /                    \                 
                .--'      ,____,------.__/-._              
             ,-/         |                   \_            
          _/              \                    \           
        -'                 |                     \         
     _/                    |       __            |         
    /                    /       / ,------.   ,-----.      
   / /                  /      -' |        \-|       |     
    /                  |      '   |        | \       '     
     /                 |_____|    |        |  \      /     
    /           ,----./_______\_.  \       /   \    /      
    /          /      \           \_`-----/     \--'       
   / /        |                          / 0  0 / /        
    /\        |                                /  |        
     |         \                                  \        
      /          \                          ,---. |        
     / \_         \     \                  /    / /        
         \        |\____/                /     | |         
          \       |                     /     '  '         
            \     /                    /     /  /          
             \   /                    |      | |           
              /.-                     \______/ |           
         .__'    \                             |           
      /-`         \            \              /______      
  .--`             \            `------------/       `--.  
 /                  \                     /              \ 
___________________________________________________________
___________________________________________________________
                          ,-----.-----.                    
             ,------.----\ __   /__   /                    
            /  ,____//|  //_/  //,-----.------.            
           /  /   / /_/_/     / /  ____/_____/-----.       
--  --  --/  /___/_   \/__   /_/  /_/_ / /__   ___/-- -- --
         /  //_  _//\  \_/  //_\__   //    /  /            
_________\______/_/  \__|__/_,---/  //____/  /             
____________________________/______/______/_/              
___________________________________________________________
___________________________________________________________
Lopi                                               Dietrich
	A COM Scriptlet Payload Generation Tool"""

	def clear(self):
		'''
		Clear the display
		'''
		if(os.name == 'nt'):
			self.clearSc = 'cls'
		else:
			self.clearSc = 'clear'
		os.system(self.clearSc)

	def do_EOF(self, line):
		'''Control + D aka EOF exits cleanly'''
		return True

	def do_exit(self, line):
		'''Type 'exit' to quit Great SCT'''
		return True

	def do_configs(self, line):
		'''Displays all the available configuration files from config directory'''
		configs = getAvailableConfigs()
		for i in configs:
			print(i)

	def do_generate(self, text):
		'''Generates a payload from a configuration file. i.e. generate default'''
		if text:
			config = ConfigParser()
			config.read('./config/{0}.cfg'.format(text))
			framework = getFramework(config)
			shellcode = getShellCode(config)
			stagingMethod = getStagingMethod(config)
			redirector = getRedirector(config)
			x86process = getX86Process(config)
			x64process = getX64Process(config)

			genSCT(framework, stagingMethod, redirector, x86process, x64process)
			print('Generated a Great SCT payload named payload.sct from {0} config.'.format(text))
		else:
			config = ConfigParser()
			config.read('./config/default.cfg')
			framework = getFramework(config)
			shellcode = getShellCode(config)
			stagingMethod = getStagingMethod(config)
			redirector = getRedirector(config)
			x86process = getX86Process(config)
			x64process = getX64Process(config)

			genSCT(framework, stagingMethod, redirector, x86process, x64process)
			print('Generated a Great SCT payload named payload.sct from default config.'.format(text))

	def complete_generate(self, text, line, begidx, endidx):
		if not text:
			completions = getAvailableConfigs()
		else:
			completions = [
				f
				for f in getAvailableConfigs()
				if f.startswith(text)
			]
		return completions