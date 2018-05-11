'''

This file is used for messages that will be displayed to the user at some
point

'''

import os
import sys
from lib.common import helpers

# try to find and import the settings.py config file
if os.path.exists("/etc/greatsct/settings.py"):
    try:
        sys.path.append("/etc/greatsct/")
        import settings
    except:
        print("Error importing GreatSCT Settings!")
        sys.exit(1)

# Current version of Veil
greatsct_version = "1.0"


def title_screen():
    """
    Print the framework title, with version.
    """
    os.system('clear')
    print('=' * 79)
    print(' ' * 29 + helpers.color('GreatSCT', status=False, bold=True) + ' | [Version]: ' + greatsct_version)
    print('=' * 79)
    print('      [Web]: https://github.com/GreatSCT/GreatSCT | [Twitter]: @ConsciousHacker')
    print('=' * 79 + '\n')
    return
