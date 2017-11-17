# GreatSCT
### An Application Whitelisting Bypass Tool

```python3 gr8sct.py```

The first screen you'll see is this menu.

![](https://raw.githubusercontent.com/GreatSCT/GreatSCT/Images/gsImages/gsMenu.PNG)

Select the payload you wish to generate by name or its number, `help` for help, and `menu` at any time to get back here.

For single payload generation you will find the follwing with with values pointing to your C&C to fill out.

![](https://raw.githubusercontent.com/GreatSCT/GreatSCT/Images/gsImages/gsSet.PNG)

These can be set using `set variable value` syntax

Or by entering `variable name/#` itself, which gives more hints about the expected value

`help` gives more info as well

![](https://raw.githubusercontent.com/GreatSCT/GreatSCT/Images/gsImages/gsHelp.PNG)  

Once the correct values have been set `generate` to build your payload.

![](https://raw.githubusercontent.com/GreatSCT/GreatSCT/Images/gsImages/gsGenerated.PNG)

The payload (shellcode.xml in this case) appears in the root directory.  
The devs should fix this so you can specify an output folder, but they are lazy.

![](https://raw.githubusercontent.com/GreatSCT/GreatSCT/Images/gsImages/gsOutput.PNG)
___

For network testing purposes use `generateAll` from the inital menu

![](https://raw.githubusercontent.com/GreatSCT/GreatSCT/Images/gsImages/gsGenAllSet.PNG)

The bottom values are those which are common to multiple payloads.
This lets you easily set your C&C values for all the payloads.

When it's all set `generate` and you'll find your payloads in ./GenerateAll/

![](https://raw.githubusercontent.com/GreatSCT/GreatSCT/Images/gsImages/genAllGenerate.PNG)

Apache and metasploit will automatically start when the GenerateAll function finishes.

![](https://raw.githubusercontent.com/GreatSCT/GreatSCT/Images/gsImages/genAllDone.PNG)

A script to automatically execute each payload is located in ./GenerateAll/gr8sct.bat.

![](https://raw.githubusercontent.com/GreatSCT/GreatSCT/Images/gsImages/genAllFolder.PNG)

Download generateall.zip from the HostedDomain, execute gr8sct.bat, and open ./GenerateAll/analyst.csv when the batch script finishes to see which bypasses worked.
