#!/usr/bin/env python
import os

"""
This module is used for displaying information and interactive cli.
"""


class Color:
    """This class is used for displaying colors"""
    colorMap = {"GREEN": "\033[92m", "RED": "\033[31m", "ENDC": "\033[0m"}

    def setColor(self, text, color):
        """
        Sets the color and returns the colored text

        :param text: the text to color
        :param color: the color of the text
        :type text: string
        :type color: string
        :returns: text
        :rtype: string
        """
        try:
            text = "{0}{1}{2}".format(self.colorMap[color], text, self.colorMap["ENDC"])
        except KeyError:  # supplied nondefined color
            text = text

        return text


class Display:
    """This class is used to display text"""
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
        """
        Initalizes the class
        """
        if (os.name == 'nt'):
            Display.clearCMD = 'cls'
        else:
            Display.clearCMD = 'clear'

        self.clear()

        print(self.intro)

    def clear(self):
        """
        Clears the screen
        """
        os.system(Display.clearCMD)

    def prompt(self, item, term="\n"):
        """
        The text prompt

        :param item: item to display
        :param term: terminal new line
        :type item: string
        :type term: string
        """
        print(item, end=term)
