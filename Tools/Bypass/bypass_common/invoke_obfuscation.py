"""
Python port of Invoke-Obfuscation

ASCII Encoding
Binary Encoding

Based on code from:

    https://github.com/danielbohannon/Invoke-Obfuscation/blob/master/Out-EncodedAsciiCommand.ps1
    https://github.com/danielbohannon/Invoke-Obfuscation/blob/master/Out-EncodedBinaryCommand.ps1

ASCII Encoding written by @ConsciousHacker
Binary Encoding written by @ch1gg1ns

"""

from string import ascii_lowercase
from random import choice, choices, sample, randrange, sample

def asciiEncode(scriptString):
    # Add letters a-z with random case to $RandomDelimiters.
    alphabet = ''.join(choice([i.upper(), i]) for i in ascii_lowercase)

    # Create list of random dxelimiters called randomDelimiters.
    # Avoid using . * ' " [ ] ( ) etc. as delimiters as these will cause problems in the -Split command syntax.
    randomDelimiters = ['_','-',',','{','}','~','!','@','%','&','<','>',';',':']

    for i in alphabet:
        randomDelimiters.append(i)

    # Only use a subset of current delimiters to randomize what you see in every iteration of this script's output.
    randomDelimiters = choices(randomDelimiters, k=int(len(randomDelimiters)/4))

    # Convert $ScriptString to delimited ASCII values in [Char] array separated by random delimiter from defined list $RandomDelimiters.
    delimitedEncodedArray = ''
    for char in scriptString:
        delimitedEncodedArray += str(ord(char)) + choice(randomDelimiters)

    # Remove trailing delimiter from $DelimitedEncodedArray.
    delimitedEncodedArray = delimitedEncodedArray[:-1]
    # Create printable version of $RandomDelimiters in random order to be used by final command.
    test = sample(randomDelimiters, len(randomDelimiters))
    randomDelimitersToPrint = ''.join(i for i in test)

    # Generate random case versions for necessary operations.
    forEachObject = choice(['ForEach','ForEach-Object','%'])
    strJoin = ''.join(choice([i.upper(), i.lower()]) for i in '[String]::Join')
    strStr = ''.join(choice([i.upper(), i.lower()]) for i in '[String]')
    join = ''.join(choice([i.upper(), i.lower()]) for i in '-Join')
    charStr = ''.join(choice([i.upper(), i.lower()]) for i in 'Char')
    integer = ''.join(choice([i.upper(), i.lower()]) for i in 'Int')
    forEachObject = ''.join(choice([i.upper(), i.lower()]) for i in forEachObject)

    # Create printable version of $RandomDelimiters in random order to be used by final command specifically for -Split syntax.
    randomDelimitersToPrintForDashSplit = ''

    for delim in randomDelimiters:
        # Random case 'split' string.
        split = ''.join(choice([i.upper(), i.lower()]) for i in 'Split')

        randomDelimitersToPrintForDashSplit += '-' + split + choice(['', ' ']) + '\'' + delim + '\'' + choice(['', ' '])

    randomDelimitersToPrintForDashSplit = randomDelimitersToPrintForDashSplit.strip('\t\n\r')
    # Randomly select between various conversion syntax options.
    randomConversionSyntax = []
    randomConversionSyntax.append('[' + charStr + ']' + choice(['', ' ']) + '[' + integer + ']' + choice(['', ' ']) + '$_')
    randomConversionSyntax.append('[' + integer + ']' + choice(['', ' ']) + '$_' + choice(['', ' ']) + choice(['-as', '-As', '-aS', '-AS']) + choice(['', ' ']) + '[' + charStr + ']')
    randomConversionSyntax = choice(randomConversionSyntax)

    # Create array syntax for encoded scriptString as alternative to .Split/-Split syntax.
    encodedArray = ''
    for char in scriptString:
        encodedArray += str(ord(char)) + choice(['', ' ']) + ',' + choice(['', ' '])

    # Remove trailing comma from encodedArray
    encodedArray = '(' + choice(['', ' ']) + encodedArray.rstrip().rstrip(',') + ')'

    # Generate random syntax to create/set OFS variable ($OFS is the Output Field Separator automatic variable).
    # Using Set-Item and Set-Variable/SV/SET syntax. Not using New-Item in case OFS variable already exists.
    # If the OFS variable did exists then we could use even more syntax: $varname, Set-Variable/SV, Set-Item/SET, Get-Variable/GV/Variable, Get-ChildItem/GCI/ChildItem/Dir/Ls
    # For more info: https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.core/about/about_automatic_variables
    setOfsVarSyntax = []
    setOfsVarSyntax.append('Set-Item' + choice([' '*1, ' '*2]) + "'Variable:OFS'" + choice([' '*1, ' '*2]) + "''")
    setOfsVarSyntax.append(choice(['Set-Variable', 'SV', 'SET']) + choice([' '*1, ' '*2]) + "'OFS'" + choice([' '*1, ' '*2]) + "''")
    setOfsVar = choice(setOfsVarSyntax)

    setOfsVarBackSyntax = []
    setOfsVarBackSyntax.append('Set-Item' + choice([' '*1, ' '*2]) + "'Variable:OFS'" + choice([' '*1, ' '*2]) + "' '")
    setOfsVarBackSyntax.append('Set-Item' + choice([' '*1, ' '*2]) + "'Variable:OFS'" + choice([' '*1, ' '*2]) + "' '")
    setOfsVarBack = choice(setOfsVarBackSyntax)

    # Randomize case of $SetOfsVar and $SetOfsVarBack.
    setOfsVar = ''.join(choice([i.upper(), i.lower()]) for i in setOfsVar)
    setOfsVarBack = ''.join(choice([i.upper(), i.lower()]) for i in setOfsVarBack)

    # Generate the code that will decrypt and execute the payload and randomly select one.
    baseScriptArray = []
    baseScriptArray.append('[' + charStr + '[]' + ']' + choice(['', ' ']) + encodedArray)
    baseScriptArray.append('(' + choice(['', ' ']) + "'" + delimitedEncodedArray + "'." + split + "(" + choice(['', ' ']) + "'" + randomDelimitersToPrint + "'" + choice(['', ' ']) + ')' + choice(['', ' ']) + '|' + choice(['', ' ']) + forEachObject + choice(['', ' ']) + '{' + choice(['', ' ']) + '(' + choice(['', ' ']) + randomConversionSyntax + ')' + choice(['', ' ']) + '}' + choice(['', ' ']) + ')')
    baseScriptArray.append('(' + choice(['', ' ']) + "'" + delimitedEncodedArray + "'" + choice(['', ' ']) + randomDelimitersToPrintForDashSplit + choice(['', ' ']) + '|' + choice(['', ' ']) + forEachObject + choice(['', ' ']) + '{' + choice(['', ' ']) + '(' + choice(['', ' ']) + randomConversionSyntax + ')' + choice(['', ' ']) + '}' + choice(['', ' ']) + ')')
    baseScriptArray.append('(' + choice(['', ' ']) + encodedArray + choice(['', ' ']) + '|' + choice(['', ' ']) + forEachObject + choice(['', ' ']) + '{' + choice(['', ' ']) + '(' + choice(['', ' ']) + randomConversionSyntax + ')' + choice(['', ' ']) + '}' + choice(['', ' ']) + ')')
    # Generate random JOIN syntax for all above options
    newScriptArray = []
    newScriptArray.append(choice(baseScriptArray) + choice(['', ' ']) + join + choice(['', ' ']) + "''")
    newScriptArray.append(join + choice(['', ' ']) + choice(baseScriptArray))
    newScriptArray.append(strJoin + '(' + choice(['', ' ']) + "''" + choice(['', ' ']) + ',' + choice(['', ' ']) + choice(baseScriptArray) + choice(['', ' ']) + ')')
    newScriptArray.append('"' + choice(['', ' ']) + '$(' + choice(['', ' ']) + setOfsVar + choice(['', ' ']) + ')' + choice(['', ' ']) + '"' + choice(['', ' ']) + '+' + choice(['', ' ']) + strStr + choice(baseScriptArray) + choice(['', ' ']) + '+' + '"' + choice(['', ' ']) + '$(' + choice(['', ' ']) + setOfsVarBack + choice(['', ' ']) + ')' + choice(['', ' ']) + '"')

    # Randomly select one of the above commands.
    newScript = choice(newScriptArray)

    # Generate random invoke operation syntax.
    # Below code block is a copy from Out-ObfuscatedStringCommand.ps1. It is copied into this encoding function so that this will remain a standalone script without dependencies.
    invokeExpressionSyntax  = []
    invokeExpressionSyntax.append(choice(['IEX', 'Invoke-Expression']))
    # Added below slightly-randomized obfuscated ways to form the string 'iex' and then invoke it with . or &.
    # Though far from fully built out, these are included to highlight how IEX/Invoke-Expression is a great indicator but not a silver bullet.
    # These methods draw on common environment variable values and PowerShell Automatic Variable values/methods/members/properties/etc.
    invocationOperator = choice(['.','&']) + choice(['', ' '])
    invokeExpressionSyntax.append(invocationOperator + "( $ShellId[1]+$ShellId[13]+'x')")
    invokeExpressionSyntax.append(invocationOperator + "( $PSHome[" + choice(['4', '21']) + "]+$PSHOME[" + choice(['30', '34']) + "]+'x')")
    invokeExpressionSyntax.append(invocationOperator + "( $env:Public[13]+$env:Public[5]+'x')")
    invokeExpressionSyntax.append(invocationOperator + "( $env:ComSpec[4," + choice(['15', '24', '26']) + ",25]-Join'')")
    invokeExpressionSyntax.append(invocationOperator + "((" + choice(['Get-Variable','GV','Variable']) + " '*mdr*').Name[3,11,2]-Join'')")
    invokeExpressionSyntax.append(invocationOperator + "( " + choice(['$VerbosePreference.ToString()','([String]$VerbosePreference)']) + "[1,3]+'x'-Join'')")

    # Randomly choose from above invoke operation syntaxes.
    invokeExpression = choice(invokeExpressionSyntax)

     # Randomize the case of selected invoke operation.
    invokeExpression = ''.join(choice([i.upper(), i.lower()]) for i in invokeExpression)

    # Choose random Invoke-Expression/IEX syntax and ordering: IEX ($ScriptString) or ($ScriptString | IEX)
    invokeOptions = []
    invokeOptions.append(choice(['', ' ']) + invokeExpression + choice(['', ' ']) + '(' + choice(['', ' ']) + newScript + choice(['', ' ']) + ')' + choice(['', ' ']))
    invokeOptions.append(choice(['', ' ']) + newScript + choice(['', ' ']) + '|' + choice(['', ' ']) + invokeExpression)

    newScript = choice(invokeOptions)

    return newScript

def binaryEncode(scriptString):
    # Encoding base values: 16=Hex, 8=Octal, 2=Binary
    encodingBase = 2

    # Add letters a-z with random case to $RandomDelimiters.
    alphabet = ''.join(choice([i.upper(), i]) for i in ascii_lowercase)

    # Create list of random dxelimiters called randomDelimiters.
    # Avoid using . * ' " [ ] ( ) etc. as delimiters as these will cause problems in the -Split command syntax.
    randomDelimiters = ['_','-',',','{','}','~','!','@','%','&','<','>',';',':']

    for i in alphabet:
        randomDelimiters.append(i)

    # Only use a subset of current delimiters to randomize what you see in every iteration of this script's output.
    randomDelimiters = choices(randomDelimiters, k=int(len(randomDelimiters)/4))
    #  ([Char[]]$ScriptString) | ForEach-Object {$DelimitedEncodedArray += ([Convert]::ToString(([Int][Char]$_),$EncodingBase) + (Get-Random -Input $RandomDelimiters))}
    for char in scriptString:
        delimitedEncodedArray = choice(randomDelimiters)

    # Convert $ScriptString to delimited binary values in [Char] array separated by random delimiter from defined list $RandomDelimiters.
    delimitedEncodedArray = ''
    for char in scriptString:
        delimitedEncodedArray += bin(ord(char))[2:] + choice(randomDelimiters)

    # Remove trailing delimiter from $DelimitedEncodedArray.
    delimitedEncodedArray = delimitedEncodedArray[:-1]
    # Create printable version of $RandomDelimiters in random order to be used by final command.
    test = sample(randomDelimiters, len(randomDelimiters))
    randomDelimitersToPrint = ''.join(i for i in test)

    # Generate random case versions for necessary operations.
    forEachObject = choice(['ForEach','ForEach-Object','%'])
    strJoin = ''.join(choice([i.upper(), i.lower()]) for i in '[String]::Join')
    strStr = ''.join(choice([i.upper(), i.lower()]) for i in '[String]')
    join = ''.join(choice([i.upper(), i.lower()]) for i in '-Join')
    charStr = ''.join(choice([i.upper(), i.lower()]) for i in 'Char')
    integer = ''.join(choice([i.upper(), i.lower()]) for i in 'Int')
    forEachObject = ''.join(choice([i.upper(), i.lower()]) for i in forEachObject)
    ToInt16 = ''.join(choice([i.upper(), i.lower()]) for i in '[Convert]::ToInt16(')

    # Create printable version of $RandomDelimiters in random order to be used by final command specifically for -Split syntax.
    randomDelimitersToPrintForDashSplit = ''

    for delim in randomDelimiters:
        # Random case 'split' string.
        split = ''.join(choice([i.upper(), i.lower()]) for i in 'Split')

        randomDelimitersToPrintForDashSplit += '-' + split + choice(['', ' ']) + '\'' + delim + '\'' + choice(['', ' '])

    randomDelimitersToPrintForDashSplit = randomDelimitersToPrintForDashSplit.strip('\t\n\r')
    # Randomly select between various conversion syntax options.
    #$RandomStringSyntax = ([Char[]](Get-Random -Input @('[String]$_','$_.ToString()')) | 
    # ForEach-Object {
    #   $Char = $_.ToString().ToLower(); 
    #   If(Get-Random -Input @(0..1)) {
    #       $Char = $Char.ToUpper()
    #   } 
    #   $Char
    # }) -Join ''
    randomStringSyntax = ''
    thisStringType = choice(['[String]$_', '$_.ToString()'])
    for i in thisStringType:
        randomStringSyntax += choice([i.upper(), i.lower()])
    randomConversionSyntax = []
    randomConversionSyntax.append('[' + charStr + ']' + choice(['', ' ']) + '(' + choice(['', ' ']) + ToInt16 + choice(['', ' ']) + '(' + choice(['', ' ']) + randomStringSyntax + choice(['', ' ']) + ')' + choice(['', ' ']) + ',' + str(encodingBase) + choice(['', ' ']) + ')' + choice(['',' ']) + ')')
    randomConversionSyntax.append(ToInt16 + choice(['', ' ']) + '(' + choice(['', ' ']) + randomStringSyntax + choice(['', ' ']) + ')' + choice(['', ' ']) + ',' + choice(['', ' ']) + str(encodingBase) + choice(['', ' ']) + ')' + choice(['', ' ']) + choice(['-as', '-aS', '-As', '-AS']) + choice(['', ' ']) + '[' + charStr + ']')
    randomConversionSyntax = choice(randomConversionSyntax)

    encodedArray = ''
    for char in scriptString:
        quote = ''
        if (len(bin(ord(char))[2:].strip('0123456789')) > 0):
            quote = '\''

        encodedArray += quote + bin(ord(char))[2:] + quote + choice(['', ' ']) + ',' + choice(['', ' '])

    # Remove trailing comma from encodedArray
    encodedArray = '(' + choice(['', ' ']) + encodedArray.rstrip().rstrip(',') + ')'

    # Generate random syntax to create/set OFS variable ($OFS is the Output Field Separator automatic variable).
    # Using Set-Item and Set-Variable/SV/SET syntax. Not using New-Item in case OFS variable already exists.
    # If the OFS variable did exists then we could use even more syntax: $varname, Set-Variable/SV, Set-Item/SET, Get-Variable/GV/Variable, Get-ChildItem/GCI/ChildItem/Dir/Ls
    # For more info: https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.core/about/about_automatic_variables
    setOfsVarSyntax = []
    setOfsVarSyntax.append('Set-Item' + choice([' '*1, ' '*2]) + "'Variable:OFS'" + choice([' '*1, ' '*2]) + "''")
    setOfsVarSyntax.append(choice(['Set-Variable', 'SV', 'SET']) + choice([' '*1, ' '*2]) + "'OFS'" + choice([' '*1, ' '*2]) + "''")
    setOfsVar = choice(setOfsVarSyntax)

    setOfsVarBackSyntax = []
    setOfsVarBackSyntax.append('Set-Item' + choice([' '*1, ' '*2]) + "'Variable:OFS'" + choice([' '*1, ' '*2]) + "' '")
    setOfsVarBackSyntax.append('Set-Item' + choice([' '*1, ' '*2]) + "'Variable:OFS'" + choice([' '*1, ' '*2]) + "' '")
    setOfsVarBack = choice(setOfsVarBackSyntax)

    # Randomize case of $SetOfsVar and $SetOfsVarBack.
    setOfsVar = ''.join(choice([i.upper(), i.lower()]) for i in setOfsVar)
    setOfsVarBack = ''.join(choice([i.upper(), i.lower()]) for i in setOfsVarBack)

    # Generate the code that will decrypt and execute the payload and randomly select one.
    baseScriptArray = []
    baseScriptArray.append('(' + choice(['', ' ']) + "'" + delimitedEncodedArray + "'." + split + "(" + choice(['', ' ']) + "'" + randomDelimitersToPrint + "'" + choice(['', ' ']) + ')' + choice(['', ' ']) + '|' + choice(['', ' ']) + forEachObject + choice(['', ' ']) + '{' + choice(['', ' ']) + '(' + choice(['', ' ']) + randomConversionSyntax + ')' + choice(['', ' ']) + '}' + choice(['', ' ']) + ')')
    baseScriptArray.append('(' + choice(['', ' ']) + "'" + delimitedEncodedArray + "'" + choice(['', ' ']) + randomDelimitersToPrintForDashSplit + choice(['', ' ']) + '|' + choice(['', ' ']) + forEachObject + choice(['', ' ']) + '{' + choice(['', ' ']) + '(' + choice(['', ' ']) + randomConversionSyntax + ')' + choice(['', ' ']) + '}' + choice(['', ' ']) + ')')
    baseScriptArray.append('(' + choice(['', ' ']) + encodedArray + choice(['', ' ']) + '|' + choice(['', ' ']) + forEachObject + choice(['', ' ']) + '{' + choice(['', ' ']) + '(' + choice(['', ' ']) + randomConversionSyntax + ')' + choice(['', ' ']) + '}' + choice(['', ' ']) + ')')
    # Generate random JOIN syntax for all above options
    newScriptArray = []
    newScriptArray.append(choice(baseScriptArray) + choice(['', ' ']) + join + choice(['', ' ']) + "''")
    newScriptArray.append(join + choice(['', ' ']) + choice(baseScriptArray))
    newScriptArray.append(strJoin + '(' + choice(['', ' ']) + "''" + choice(['', ' ']) + ',' + choice(['', ' ']) + choice(baseScriptArray) + choice(['', ' ']) + ')')
    newScriptArray.append('"' + choice(['', ' ']) + '$(' + choice(['', ' ']) + setOfsVar + choice(['', ' ']) + ')' + choice(['', ' ']) + '"' + choice(['', ' ']) + '+' + choice(['', ' ']) + strStr + choice(baseScriptArray) + choice(['', ' ']) + '+' + '"' + choice(['', ' ']) + '$(' + choice(['', ' ']) + setOfsVarBack + choice(['', ' ']) + ')' + choice(['', ' ']) + '"')

    # Randomly select one of the above commands.
    newScript = choice(newScriptArray)

    # Generate random invoke operation syntax.
    # Below code block is a copy from Out-ObfuscatedStringCommand.ps1. It is copied into this encoding function so that this will remain a standalone script without dependencies.
    invokeExpressionSyntax  = []
    invokeExpressionSyntax.append(choice(['IEX', 'Invoke-Expression']))
    # Added below slightly-randomized obfuscated ways to form the string 'iex' and then invoke it with . or &.
    # Though far from fully built out, these are included to highlight how IEX/Invoke-Expression is a great indicator but not a silver bullet.
    # These methods draw on common environment variable values and PowerShell Automatic Variable values/methods/members/properties/etc.
    invocationOperator = choice(['.','&']) + choice(['', ' '])
    invokeExpressionSyntax.append(invocationOperator + "( $ShellId[1]+$ShellId[13]+'x')")
    invokeExpressionSyntax.append(invocationOperator + "( $PSHome[" + choice(['4', '21']) + "]+$PSHOME[" + choice(['30', '34']) + "]+'x')")
    invokeExpressionSyntax.append(invocationOperator + "( $env:Public[13]+$env:Public[5]+'x')")
    invokeExpressionSyntax.append(invocationOperator + "( $env:ComSpec[4," + choice(['15', '24', '26']) + ",25]-Join'')")
    invokeExpressionSyntax.append(invocationOperator + "((" + choice(['Get-Variable','GV','Variable']) + " '*mdr*').Name[3,11,2]-Join'')")
    invokeExpressionSyntax.append(invocationOperator + "( " + choice(['$VerbosePreference.ToString()','([String]$VerbosePreference)']) + "[1,3]+'x'-Join'')")

    # Randomly choose from above invoke operation syntaxes.
    invokeExpression = choice(invokeExpressionSyntax)

     # Randomize the case of selected invoke operation.
    invokeExpression = ''.join(choice([i.upper(), i.lower()]) for i in invokeExpression)

    # Choose random Invoke-Expression/IEX syntax and ordering: IEX ($ScriptString) or ($ScriptString | IEX)
    invokeOptions = []
    invokeOptions.append(choice(['', ' ']) + invokeExpression + choice(['', ' ']) + '(' + choice(['', ' ']) + newScript + choice(['', ' ']) + ')' + choice(['', ' ']))
    invokeOptions.append(choice(['', ' ']) + newScript + choice(['', ' ']) + '|' + choice(['', ' ']) + invokeExpression)

    newScript = choice(invokeOptions)

    return newScript
