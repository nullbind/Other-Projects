----------------------------
Script Name: GDA
Author: Scott Sutherland (nullbind) <scott.sutherland@nullbind.com>
Date: 12/1/2011

----------------------------
Description
----------------------------
This script can be used to enumerate users that exist in the current machine's domain and locate systems running processes with a domain admin account by querying domain controllers.  I know its craptacular, but it works.  One note though, make sure to modify the script manually when enumerating accounts and sessions for domains with three part names.  For example: subdomain.domain.com.

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

------------------------------------------------------------------
Instructions - Identify Systems with active Domain Admin sessions
------------------------------------------------------------------
1. Open a Windows command console and navigate to the GDA directory. 

2. Type gda -a to location domain admin session for the current user's domain. 

3. Collect the list of domain controllers, domain admins, and systems with domain admin sessions from datargets.txt.


------------------------------------------------------------------
Instructions - Enumerate domain users for the current domain
------------------------------------------------------------------
1. Open a Windows command console and navigate to the GDA directory. 

2. Type gda -l to enumerate users for the current domain using ldap and a trusted connection for the current user.

3. Collect the list domain users from user_ldap.txt.

