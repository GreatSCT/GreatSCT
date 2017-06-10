# GreatSCT
### An Application Whitlisintg Bypass Tool

```python3 gr8sct.py```

The first screen you'll see is this menu.

![](https://github.com/GreatSCT/GreatSCT/blob/7c7a7d6e2595e9ca4f9e6c71a5305acfe836cdb6/gsImages/gsMenu.PNG)

Select the payload you wish to generate by name or its number, `help` for help, and `menu` at any time to get back here.

For single payload generation you will find the follwing with with values pointing to your C&C to fill out.

![](https://raw.githubusercontent.com/GreatSCT/GreatSCT/7c7a7d6e2595e9ca4f9e6c71a5305acfe836cdb6/gsImages/gsSet.PNG)

These can be set using `set variable value` syntax

Or by entering `variable name/#` itself, which gives more hints about the expected value

`help` gives more info as well

![](https://raw.githubusercontent.com/GreatSCT/GreatSCT/7c7a7d6e2595e9ca4f9e6c71a5305acfe836cdb6/gsImages/gsHelp.PNG)  
  
>\n because I hate markdown

Once the correct values have been set `generate` to build your payload.

![](https://raw.githubusercontent.com/GreatSCT/GreatSCT/7c7a7d6e2595e9ca4f9e6c71a5305acfe836cdb6/gsImages/gsGenerated.PNG)

The payload (shellcode.xml in this case) appears in the root directory.  
The devs should fix this so you can specify an output folder, but they are lazy.

![](https://raw.githubusercontent.com/GreatSCT/GreatSCT/7c7a7d6e2595e9ca4f9e6c71a5305acfe836cdb6/gsImages/gsOutput.PNG)
___

For network testing purposes use `generateAll` from the inital menu

![](https://raw.githubusercontent.com/GreatSCT/GreatSCT/7c7a7d6e2595e9ca4f9e6c71a5305acfe836cdb6/gsImages/gsGenAllSet.PNG)

The bottom values are those which are common to multiple payloads.
This lets you easily set your C&C values for all the payloads.

When it's all set `generate` and you'll find your payloads in ./GenerateAll/

![](https://raw.githubusercontent.com/GreatSCT/GreatSCT/7c7a7d6e2595e9ca4f9e6c71a5305acfe836cdb6/gsImages/gsGenAllGenerate.PNG)

A script to automatically execute each payload is pending.
For now drop the folder onto the representative box, execute payloads one by one, and note which are blocked, which generate alerts, and which make it through undisturbed.

___

>Always remember, if you see penises, you're doing something right.  
>Don't be a dumbass
