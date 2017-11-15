#!/usr/bin/env python
import os

'''
This module is used for displaying information and interactive cli.
'''


class Color:
    colorMap = {"GREEN": "\033[92m", "RED": "\033[31m", "ENDC": "\033[0m"}

    def setColor(self, text, color):
        try:
            text = "{0}{1}{2}".format(self.colorMap[color], text, self.colorMap["ENDC"])
        except KeyError:  # supplied nondefined color
            text = text

        return text


class Display:

    GREEN = "\033[92m"
    ENDC = "\033[0m"

    color = Color()
    clearCMD = ''
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
	An App Whitlisting Bypass Generation Tool"""

    def init(self):
        if (os.name == 'nt'):
            Display.clearCMD = 'cls'
        else:
            Display.clearCMD = 'clear'

        self.clear()

        print(self.intro)

    def clear(self):
        os.system(Display.clearCMD)

    def prompt(self, item, term="\n"):
        print(item, end=term)
