#!/usr/bin/env python3

import argparse
import sys
from lib.common import helpers
from lib.common import messages
from lib.common import orchestra
sys.dont_write_bytecode = True


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        add_help=False, description="GreatSCT is a framework to generate application\
         whitelisting bypasses.")
    parser.add_argument(
        '-h', '-?', '--h', '-help', '--help', action="store_true",
        help=argparse.SUPPRESS)

    greatsctframework = parser.add_argument_group('GreatSCT Options')
    greatsctframework.add_argument(
        '--update', action='store_true', help='Update the GreatSCT framework.')
    greatsctframework.add_argument(
        '--version', action="store_true", help='Displays version and quits.')
    greatsctframework.add_argument(
        '--list-tools', action="store_true", default=False,
        help='List GreatSCT\'s tools')
    greatsctframework.add_argument(
        '-t', '--tool', metavar='Bypass', default=False,
        help='Specify GreatSCT tool to use (Bypass)')

    callback_args = parser.add_argument_group('Callback Settings')
    callback_args.add_argument(
        "--ip", "--domain", metavar="IP", default=None,
        help="IP Address to connect back to")
    callback_args.add_argument(
        '--port', metavar="Port", default=443, type=int,
        help="Port number to connect to.")
    
    payload_args = parser.add_argument_group('[*] Payload Settings')
    payload_args.add_argument(
        '--list-payloads', default=False, action='store_true',
        help='Lists all available payloads for that tool')
    payload_args.add_argument(
        '--generate-awl', action="store_true", default=False, 
        help="Generate all bypasses in the framework"
    )

    greatsctbypass = parser.add_argument_group('Great Scott Options')
    greatsctbypass.add_argument(
        '-c', metavar='OPTION1=value OPTION2=value', nargs='*',
        default=None, help='Custom payload module options.')
    greatsctbypass.add_argument(
        '-o', metavar="OUTPUT NAME", default="payload",
        help='Output file base name for source and compiled binaries.')
    greatsctbypass.add_argument(
        '-p', metavar="PAYLOAD", nargs='?', const="list",
        help='Payload to generate. Lists payloads if none specified.')
    greatsctbypass.add_argument(
        '--clean', action='store_true',
        help='Clean out payload folders.')
    greatsctbypass.add_argument(
        '--msfoptions', metavar="OPTION=value", nargs='*',
        help='Options for the specified metasploit payload.')
    greatsctbypass.add_argument(
        '--msfvenom', metavar="windows/meterpreter/reverse_tcp", nargs='?',
        default='windows/meterpreter/reverse_tcp', help='Metasploit shellcode to generate.')

    args = parser.parse_args()

    try:
        the_conductor = orchestra.Conductor(args)
    except NameError:
        print("ERROR: You forgot to run the setup script!")
        sys.exit()

    if args.h:
        parser.print_help()
        sys.exit()

    if args.version:
        messages.title_screen()
        sys.exit()

    if args.update:
        the_conductor.great_sct()
        sys.exit()

    if args.list_tools:
        the_conductor.list_tools()
        sys.exit()

    if args.clean:
        helpers.clean_payloads()
        sys.exit()

    if not args.tool:
        the_conductor.main_menu()
        sys.exit()

    # This should hit if trying to use the CLI
    else:
        the_conductor.command_line_use()
