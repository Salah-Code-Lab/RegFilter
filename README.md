
## QoL fixes: (Published)
* ChkInt had been Enhanced to a better version
* Fixed The Recursive Protections and it works again
* Replaced recursive O(n) scan with dual-hash O(1) wildcard matching
* Less False Positives on the Services key now 
* Addressed a Fix for Initialize Protections not looping correctly 

These Updates had been Published

Testing Results: Driver in the test Handled 127 Million Operations the test was stopped Due to the Time of my Patience 

* Performance sustained improvement is around ~60% More than before 



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

Stage 2 is a secondary hash lookup for wildcard entries. Wildcard entries are hashed by key path only (no value name), allowing O(1) matching for any value under this key.

Stage 3 is caller context. ControlHiveAccessEx() which calls ChkInt2() checks if the caller is 
PPL or Light PPL protected, or if it's services.exe parented 
by wininit.exe. Trusted callers get through. Everyone else 
goes through ControlHiveAccess which blocks userland writes 
to the services hive entirely.

I Would recommend removing it for daily drivers


Stage 3-4 is HKCU filtering. Resolves the caller SID from the 
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





## Additional Info (With QoL Fixes): 
On a 6 Core VM with Hyper-V on host Off<br>
with Virtualization of CPU Counters 
RegFilter can achieve a max of <code>140k</code> Reg Operations per second<br>
in that scenario the silicon in that test is the Bottle Neck not the driver
the driver won't be Optimized further.<br>
since it is already fast gaining a maximum response time of Mere microseconds (around 7.1 Microseconds on a I5 10th Gen though is not constantly consistent, it is user side not kernel side so it isn't accurate it includes CM acquiring locks time, returning to userland so userland API dominate while we want to focus on the driver Return time and not the whole Chain of execution but perhaps the driver responds in about 5 microseconds but i am unsure additional testing is needed).<br>
These tests were conducted with the Win11 Version and not the Win10 Version<br>
oh, i almost forgot the build is the Default with the Updated QoL

Now when the driver was tested i ran well more than 217 Million Operations they include Write And Deletions<br>
Stability Shouldn't be an issue considering that Normally the OS does Maybe Hundreds of thousands in a day<br>
so to out buffer the 217 Million you'd need Months unless if there was something that would act abnormally and i didn't account for it<br>
as i said before i am not Megamind or Superman to account for every single possible Edge case in the World<br>
Over ~60% increase in Response time than the old version of the driver<br>


This was tested on a custom executable that writes constantly with 128 threads (64 for HKLM, 64 for HKCU). The tool will not be published for obvious reasons (abuse, DoS, other malicious usage).

<mark>To Conduct this test here is how you can set the Environment</mark>
1. First this was a Debloated VM with Microwin results may differ with ones that aren't debloated<br>
2. Hyper-V must be disabled on Host because it was a Limiter for VMWare, the results will be different if Hyper-V is enabled on Host.<br>
3. The VM Specs Were:<br>
<code>CPU</code>: Optional Depending on your Choice, My Tests used 6 cores  but the CPU Specs of mine are:(2.5GHz, 12 vCPUs, 6 Cores, 12 Threads Intel Core I5, 10th gen 10500H)<br>
<code>RAM</code>: 8GB can be less though<br>
<code>Virtualized CPU Counters</code>: True can be false as well i didn't notice that much of a difference across both(needs Hyper-V on host OFF)<br>

about the 140k Max ops per second just Note
Results can differ from It will so take it as you will 
you may achieve it or you may achieve 120k or 110k or even 100k 
to me that happened multiple times 140k is just the best i had personally seen
a Video of Demonstration and Explanation had been recorded for 
* Protected Paths,
* demonstration of actual speed response, 
* Mirrored paths and Protecting them,
* And the test was Ran until my CPU began to Thermal Throttle when it reached 95 Celsius the Test reached about 55Million Operations done anyway more than enough Proof 
The Video will be edited and Published on my [YT Channel](https://www.youtube.com/@Salah-Code-Lab)<br>
there is no Schedule only when it is ready it will be published because i don't promise anything


> some parts had been removed because i felt they were marketing i hate that i don't love that attitude so take it if you will RegFilter responds in the Single Digits in Microseconds

<mark>If you need any assistance please Contact me on session Don't hesitate in asking me any questions about the driver(s)<br>
if you find any issues with the driver please give me a heads up and place an issue on the repo Thanks</mark>
<code>056bf8ea1a057b4f351d8b651944252cd4d88416ce6c11761f0c406f228a302301</code>

## Author

Sal.

