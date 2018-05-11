# Roadmap
This is the GreatSCT 1.0 development roadmap.

## Payloads

### MSBuild
- [x] msbuild/meterpreter/rev_https - Chris
- [x] msbuild/meterpreter/rev_http - Chris
- [x] msbuild/meterpreter/rev_tcp - Chris
- [x] msbuild/shellcode_inject/virtual.py - Chris
- [x] msbuild/shellcode_inject/base64.py - Chris
- [x] msbuild/powershell/script.py - Chris

### InstallUtil
- [x] installutil/meterpreter/rev_https - Chris
- [x] installutil/meterpreter/rev_http - Chris
- [x] installutil/meterpreter/rev_tcp - Chris
- [x] installutil/shellcode_inject/virtual.py
- [x] installutil/shellcode_inject/base64.py - Chris
- [x] installutil/powershell/script.py - Chris

### Mshta
- [x] mshta/shellcode_inject/base64.py - Chris

### Regasm
- [x] regasm/meterpreter/rev_https - Chris
- [x] regasm/meterpreter/rev_http - Chris
- [x] regasm/meterpreter/rev_tcp - Chris
- [x] regasm/shellcode_inject/virtual.py - Chris
- [x] regasm/shellcode_inject/base64.py - Chris
- [x] regasm/powershell/script.py - Chris

### Regsvcs
- [x] regsvcs/meterpreter/rev_https - Chris
- [x] regsvcs/meterpreter/rev_http - Chris
- [x] regsvcs/meterpreter/rev_tcp - Chris
- [x] regsvcs/shellcode_inject/virtual.py - Chris
- [x] regsvcs/shellcode_inject/base64.py - Chris
- [x] regsvcs/powershell/script.py - Chris

### Regsvr32
- [x] regsvr32/shellcode_inject/base64_migrate.py

## Features

- [x] Basic random variable renaming obfuscation - Chris
- [x] Sandbox detection - Chris
- [ ] GenerateAll
- Invoke-Obfuscation python ports
    + [x] ASCII encoding - Chris
    + [x] Binary encoding - Chiggins

## TODO
- [x] Fix CLI generation
- [ ] Modify setup script to support all the Linux distributions - Not enough time for 1.0, aim for next minor revision
- [ ] Make C# imports more dynamic - Not enough time for 1.0, aim for next minor revision
- [ ] Add Process based sandbox evasion for all payloads - Not enough time for 1.0, aim for next minor revision
