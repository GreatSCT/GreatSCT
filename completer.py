import readline

"""This module is used to provide tab auto-completion."""


class Completer(object):
    """This class is used to provide tab auto-completion.

    -
    """

    commands = []

    def check(self, text, state):
        """
        Checks for tab auto-completion.

        :param text: the raw text of the command
        :param state: the current state
        :type text: string
        :type state: string
        :returns: None
        :rtype: None

        .. note::
            Description: Tab auto-completion for the main menu
            Original Source: http://stackoverflow.com/questions/20691102/readline-autocomplete-and-whitespace
            Modified Author: Hunter Hardman @t3ntman
            Modifieded Author: Dietrich
        """

        options = [x for x in self.commands if x.startswith(text)]

        try:
            return options[state]

        except IndexError:
            return None

    def setCommands(self, commandList):
        """
        Sets the list of commands.

        :param commandList: list of commands
        :type commandList: list
        """
        self.commands = commandList

    def addCommands(self, commandList):
        self.commands.append(commandList)
        """
        Adds a list of commands.

        :param commandList: list of commands
        :type commandList: list
        """

    def addCommand(self, command):
        """
        Adds a command.

        :param command: a single command
        :type command: string
        """
        self.commands.append(command)
