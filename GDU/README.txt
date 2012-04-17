#################################################################
# Author and Stuff
#################################################################
# Script Name: Get Domain Users (GDU)
# Author: Scott Sutherland(nullbind)<scott.sutherland@netspi.com>
#
# Description:
# This script is intended to automate Windows domain user 
# enumeration using multiple methods, and initiate a 
# dictionary attack against the accounts with respect to the 
# acccount lockout policy.
#
# Technical Summary:
# 1) Determine domain from IPCONFIG (option provided to override)
# 2) Identify domain controllers via DNS server queries
# 3) Enumerate users via RCP endpoints with Dumpsec
# 4) Enumerate users via RCP endpoints with Enum
# 5) Enumerate users via RCP SID Brute forcing with the Metasploit
#    smb_lookupsid module
# 6) Enumerate users via SNMP default strings with the Metasploit
#    snmp_enumusers module
# 7) Enumerate password policy with Dumpsec
# 8) Conduct dictionary attack using top 20 rockyou password list 
#    against enumerated users with Metasploit smb_login module 
#    with respect to the password policy
#		
# Authentication Methods:
# Users can authenticate with one of three options during attack.
# 1) Null SMB Login
# 2) Trusted connection
# 3) Username and password
#
# Notes:
# 1) If no lockout policy exists, the dictionary attack will be 
#    aborted so it can be manually confirmed
# 2)If the lockout policy cannot be determined the dicitonary
#    attack will be aborted
#################################################################