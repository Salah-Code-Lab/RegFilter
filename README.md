# RegFilter

RegFilter is a kernel mode registry protection driver for Windows.
It sits between the OS and the registry and blocks anything that 
shouldn't be touching critical keys.

## What it protects
Any key you need to Block or Forbid from being written at all 
make sure to write it with the exact same structure and Flags
The flag for PROTECT_FLAG_SID for HKCU is a must


## How it works

Four stage pipeline on every registry operation:

Stage 1 is a DJB2 hash table lookup. O(1). Exact match keys 
get hashed on load and checked instantly. Match means block.

Stage 2 is a linear recursive scan for wildcard entries. 
These can't be hashed since the incoming path is longer than 
the stored prefix. Only runs if stage 1 misses.

Stage 3 is caller context. ChkInt() checks if the caller is 
PPL or Light PPL protected, or if it's services.exe parented 
by wininit.exe. Trusted callers get through. Everyone else 
goes through ControlHiveAccess which blocks userland writes 
to the services hive entirely.

Stage 4 is HKCU filtering. Resolves the caller SID from the 
thread impersonation token first to catch ImpersonateLoggedOnUser 
attempts, falls back to primary token. Builds the full 
REGISTRY\USER\<SID>\... path and checks it against the 
HKCU protection table.

## Accountability

I know this may be a bit obvious and I even forgot to write it, but an important and crucial thing to mention is Accountability. 
What I mean by this is that:

# RegFilter will absolutely fail if you are allowing the following:

1- Allow on this Device bypasses for detected threats (Persistent Bootkits, WMI Persistent Threats, Rootkits)
2- Allowing vulnerable drivers on your machine (BYOVD attacks, if the attacker was targeting RegFilter)
3- Allowing malicious drivers to load on your machine (if the attacker was targeting RegFilter)
 + other means 

But this driver isn't meant to counter other threats at the same level of rights (Ring 0, the Kernel). It is made to be resistant, which raises the cost for the attacker, but it is ultimately, at the end of the day, still bypassable. 

## BUT

# If the attacker reaches Kernel Context execution (e.g., loading a driver into the kernel successfully)
OR
# Has the ability to abuse current vulnerable drivers installed on the device (e.g., Anti-Cheats, known vulnerable services, etc.)

Then RegFilter may already had failed and the one at fault here was the User for allowing them in the first place
RegFilter isn't designed to counter these specifically, but to resist. This was an intentional design to not only show the user that he or she must be careful, but also to preserve system stability and avoid being invasive. Just once again, a reminder:

# IF SIGNED!!!

RegFilter is made for OS hardening and persistence prevention and should be used for protection. (AFTER it was auditted accordingly to the Use cases the Users own Needs)

# If not signed

It is then used for educational purposes and NOT mass deployment.

RegFilter is not a complete protection solution (do not be mistaken; it is not complete on its own).
RegFilter is not for:
Countering APTs 
Countering Zero Days
Countering the user's own choices
etc. etc.


## Compatibility

Tested on Windows 11 25H2.

May be able to Support (23H2, 24H2).

If the user is going to Run a Older Version of Windows (e.g Win10) then it is best to 
Use the Win10 source Code branch 
since This version can cause issues that can be 
Failure to Start on load:
E.g The Current Procedure Couldn't Be Found.

## Building Instructions

Requirements:
VS2022 
Latest WDK (preferably)
Spectre Build Mitigations

## How To Run
After Building the Driver which needs 
VS2022 and the WDK Installed
test on Any OS that ranges from Win10 to Win11 any build May be Compatible 
To actually Run the Driver In Windows Ensure 
That test signing is on:
bcdedit /set testsigning on





## Additional Info: 
On a 6 Core VM with Hyper-V on host Off<br>
with Virtualization of CPU Counters 
RegFilter can achieve a max of 80k Reg Operations per second<br>
the silicon in that test is the Bottle Neck not the driver
tests show the limit of RegFilter which had been tested on a Core i9 14900HX machine with 32 Logical Processors<br>
<code>140k</code> Reg Ops per second, without utilizing the full Capabilities of the CPU which indicates The driver this time is the bottleneck<br>
the driver won't be Optimized further.<br>
since it is already fast gaining a maximum response time of Mere microseconds.<br>
These tests were conducted with the Win11 Version and not the Win10 Version<br>
oh, i almost forgot the build had been slightly edited and the flags 
/Oy (Omit Frame Pointers), /O2 (Maxamize Speed), /Ot (favor speed)<br>
from these testings the driver is roughly ~5x times to ~10x times faster in response than Other EDR solutions<br>
but EDR solutions does have some other solutions that are complete and not just compound unlike RegFilter which is specialized in CM's subsystem only<br>
This was tested on a Custom Executable that writes constantly with a total of 128 threads 64 for HKLM 64 for HKCU 
the tool will not be published for obvious reasons (Abuse, DoS, Other Malicious Usage)

<mark>To Conduct this test here is how you can set the Environment</mark>
1. First this was a Debloated VM with Microwin results may differ with ones that aren't debloated<br>
2. Hyper-V must be disabled on Host because it was a Limiter for VMWare, the results will be different if Hyper-V is enabled on Host.<br>
3. The VM Specs Were:<br>
<code>CPU</code>: Optional Depending on your Choice, My Testings used 6 cores as my main machine and the other was borrowed and set accordingly<br>
<code>RAM</code>: 8GB can be less though<br>
<code>Virtualized CPU Counters</code>: True (needs Hyper-V on host OFF)<br>

<mark>If you need any assistance please Contact me on session Don't hesitate in asking me any questions about the driver(s)<br>
if you find any issues with the driver please give me a heads up and place an issue on the repo Thanks</mark>
<code>056bf8ea1a057b4f351d8b651944252cd4d88416ce6c11761f0c406f228a302301</code>

## Author

Sal.

