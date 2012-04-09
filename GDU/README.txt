
 Script Name: Get Domain Users (GDU)
 Author: Scott Sutherland (nullbind) <scott.sutherland@netspi.com>

 Description:
 This script is intended to automated the following tasks:
 1) Determine domain from IPCONFIG
 2) Identify domain controllers via DNS
 3) Enumerate users via RCP endpoints with Dumpsec
 4) Enumerate users via RCP endpoints with Enum -U
 5) Enumerate users via RCP endpoints with Enum -N
 6) Enumerate users via RCP SID Brute force with Metasploit
 7) Enumerate users via SNMP default strings with Metasploit
 8) Conduct short dictionary attack against users with Metasploit

 Users can authenticate with one of three options during attack:
 1) Null SMB Login
 2) Trusted connection
 3) Username and password
