laura/source-g15-fix

a patcher to fix the Logitech GamePanel SDK integration in Source games (for 32-bit source games only!)

pre-patched installation guide:
1. find the folder for the game you want
2. copy the contents of that folder to your game directory
3. profit!

if you don't see a game yet pre-patched, follow these instructions:
1. patch the binary:
  1.1. if your version of Source exports CommandLine_Tier0 in tier0.dll, run py patcher.py --fix-pe g15.dll 
  1.2. if your version of Source exports CommandLine in tier0.dll, run py patcher.py g15.dll
2. copy g15_patched.dll (as g15.dll) and LgLcdApi_x86.dll to the bin folder of your game
3. copy the g15_default.res to as <game>/resource/g15.res
  3.1. unless you're running CS:Source, you must edit the res file to match the props used for your game.
       to do this, run g15_dumpplayer to get a list of props available to use

Q&A:
- Why are you patching out the registry lookup in favour of a flat folder one
-> It was causing issues on my system for some reason

- Why did you do this?
-> Idk bored

- Will you or can I submit this patch to Valve?
-> go for it but they probably don't care, it's a fix for an obscure integration
   for a piece of hardware that the vendor hasn't supported in well over 10 years
   and who's software stopped being receiving updates in 2020. the GamePanel SDK 
   and by extension the G15/G15v2/G510 and G19 do NOT work with G-Hub and never will.

- meow?
-> wruff
    