----------------------------
Script Name: Get Domain Admins (GDA)
Author: Scott Sutherland (nullbind) <scott.sutherland@netspi.com>
Date: 12/5/2011

----------------------------
Shout Outz!
----------------------------
Thank you Mark Beard (pacmandu) <pacmandu@gmail.com> and humble-desser for
taking the time to mod this script so that it can use 
multipart domain names.  Also, thank you for testing it out on the 
following compatable flavors of Windows: 
- Windows XP
- Windows 7
- Win2003 server 
- Win2008 server

Finally, I would also like to thank Joe Richards of joeware.net.  He has 
created a fantastic ADS toolset.  Without him this script 
wouldn't exist.

----------------------------
Script Summary
----------------------------
The primary goal of this script is to locate systems 
running processes with a Domain Admin account so that penetesters
can conduct cleaner privilege escalation in Active Directory domains.  
This way pentesters dont have to spray shells all over the place with
metasploit+psexec+meterpreter and scrape for admin tokens. :)

Fewer sprayed shells = Less risk of service disruptions = Happy client/boss
				   and
			Higher likelyhood of 
			escalating to Domain Admin
			quickly

----------------------------
How it Works
----------------------------
1. Gather a list of Domain Controllers from the ADS "Domain Controllers" OU 
   using LDAP and a trusted connection. - (adfind.exe)
   
2. Gather a list of Domain Admins from the ADS "Domain Admins" group using 
   LDAP and a trusted connection. - (adfind.exe)
   
3. Gather a list of all of the active sessions being tracked on 
   each of the domain controllers using netsessionenum API. - (netsess.exe)
   
   The following information will be returned:
   - IP address
   - Username 
   - Session start time
   - Session idle time
   
4. Cross reference the Domain Admin list with the active session list to determine which IP addresses
   have processes being run as a Domain Admin.
   
5. Take the natural next steps. (metasploit+psexec+meterpreter)

Note: In environments where there are very few domain admins, and they are using seperate accounts
      you may have to run it a few times until you catch them in an active sesions, but in larger
      environments you can almost always catch a service account doing in daily tasks.
      My hope is that Mubix and Jabra will create some fun Metasploit modules that take advantage of 
      this approach using Railgun and Jabra's current escalation module, but I still need to followup
      with them....to be continued...

      
              

----------------------------
Instructions - Installation 
----------------------------

1. Download the freeware tools below to the same directory as the GDA.bat.

Source - http://www.joeware.net/freetools/
- NetSess.exe 
- adfind.exe 
- findpdc.exe

Source - http://sourceforge.net/projects/unxutils/
- grep.exe 
- gawk.exe  
- uniq.exe

2. Run desired command.

------------------------------------------------------------------
Instructions - Identify Systems with active Domain Admin sessions - Target Default Domain
------------------------------------------------------------------
1. Open a Windows command console and navigate to the GDA directory. 

2. Type gda -a to locate domain admin sessions for the current user's domain. 

3. Collect the list of domain controllers, domain admins, and systems with domain admin sessions from datargets.txt.

------------------------------------------------------------------
Instructions - Identify Systems with active Domain Admin sessions - Target NON Default Domain
------------------------------------------------------------------
1. Open a Windows command console and navigate to the GDA directory. 

2. Type gda -c subdomain.domain.com to locate domain admin sessions for a domain other than the one the current
   usre belongs to.

3. Collect the list of domain controllers, domain admins, and systems with domain admin sessions from datargets.txt.

Note: Right now this usually only works when looking up info from domains with trust relationships to the default domain.

------------------------------------------------------------------
Instructions - Enumerate domain users for the current domain
------------------------------------------------------------------
1. Open a Windows command console and navigate to the GDA directory. 

2. Type gda -l to enumerate users for the current domain using ldap and a trusted connection for the current user.

3. Collect the list domain users from user_ldap.txt.

