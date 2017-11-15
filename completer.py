import readline


class Completer(object):

    commands = []

    def check(self, text, state):
        """
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
        self.commands = commandList

    def addCommands(self, commandList):
        self.commands.append(commandList)

    def addCommand(self, command):
        self.commands.append(command)
