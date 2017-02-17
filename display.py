#!/usr/bin/env python
import os
'''
This module is used for displaying information and interactive cli.
'''


class Display:
	'''
	Initialize the object to clear the screen
	'''
	def __init__(self):
		if(os.name == 'nt'):
			self.clearSc = 'cls'
		else:
			self.clearSc = 'clear'

	self.clear()
		#The following is 100% functionally necessary
		print("""                     ______,------'--"-.                   
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
Lopi                                               Dietrich""")
	

	def getOptions(self, configFile):
		'''
		Get the config file options
		'''
		self.clear()	
		print('Please select an option')

	def help(self):
		'''
		Display help menu
		'''
		self.clear()
		print("Help Menu")

	def show(self, info):
		'''
		Show info about the display
		'''
		print(info)
	
	def error(self, error):
		'''
		Print errors via the display
		'''
		print(error)

	def clear(self):
		'''
		Clear the display
		'''
		os.system(self.clearSc)
