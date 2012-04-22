#################################################################
# GET DOMIAIN USERS (GDU) - Overview
#################################################################
 Script Name: Get Domain Users (GDU)
 Author: Scott Sutherland(nullbind)<scott.sutherland@netspi.com>
 Version: 1.1

 Description:
 This script is intended to automate Windows domain user 
 enumeration using multiple methods, and initiate a 
 dictionary attack against the accounts with respect to the 
 acccount lockout policy.

 Technical Summary:
 1) Determine domain from IPCONFIG (option provided to override)
 2) Identify domain controllers via DNS server queries
 3) Enumerate users via RCP endpoints with Dumpsec
 4) Enumerate users via RCP endpoints with Enum
 5) Enumerate users via RCP SID Brute forcing with the Metasploit
    smb_lookupsid module
 6) Enumerate users via SNMP default strings with the Metasploit
    snmp_enumusers module
 7) Enumerate password policy with Dumpsec
 8) Conduct dictionary attack using top 20 rockyou password list 
    against enumerated users with Metasploit smb_login module 
    with respect to the password policy
		
 Authentication Methods:
 Users can authenticate with one of three options during attack.
 1) Null SMB Login
 2) Trusted connection
 3) Username and password

 Notes:
 1) If no lockout policy exists, the dictionary attack will be 
    aborted so it can be manually confirmed.
 2)If the lockout policy cannot be determined the dicitonary
    attack will be aborted.

#################################################################
# GET DOMIAIN USERS (GDU) - Installation
#################################################################
 
 1) Download GDU.bat
 
 2) Download the freeware tools below
 
		Joeware Tools
		http://www.joeware.net/freetools/
		Download the tools below:
		- NetSess.exe 
		- adfind.exe 		

		UnxUtils
		Source - http://sourceforge.net/projects/unxutils/
		I recommend downloading the endtire toolset, but
		at a minimum you'll need the files below:
		- grep.exe 
		- gawk.exe  
		- uniq.exe
		- tail.exe
		- head.exe
		- sort.exe
		- tr.exe
		
		Dumpssec
		http://www.systemtools.com/somarsoft/?somarsoft.com
		
		Metasploit
		http://www.metasploit.com
		
		Enum
		http://www.google.com

 3) Add the new freeware program directories to the executable PATH.
 
 4) Modify the dumpsec, enum, and metasploit paths in GDU.bat.
 
 5) Modify/add passwords to script.
 
 6) Execute script.

################################################################
# GET DOMIAIN USERS (GDU) - Usage
################################################################

   Syntax: gdu [options]

   Options:

    -n Authenticate with a null SMB login
    -t Authenticate with a trusted connection (current user)
    -a Authenticate with a supplied credentials
    -u User name to authenticate with
    -p Password to authenticate with
    -g Domain group name for finding active member sessions
    -c custom domain

   Examples (basic):
 
    gdu -n 							
    gdu -t
    gdu -a -u "domain\user" -p password
    gdu -g "group name" -u "domain\user" -p password 

   Examples (custom domain):

    gdu -n -c domain.com							
    gdu -t -c domain.com
    gdu -a -u "domain\user" -p password -c domain.com
    gdu -g "group name" -u "domain\user" -p password -c domain.com

################################################################
# GET DOMIAIN USERS (GDU) - Todo
################################################################
  
 1) Add fast/comprehensive modes - fast=stop user enumeration on first success.
 2) Add custom dictionary option.
 3) Add check for required executables before running.
 4) Add some more error checking.
 5) Write the script in a real programming lanugage . - Maybe ruby...  :)
  



