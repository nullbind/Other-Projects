@echo off
cls

REM #######################################################
REM Author and Stuff
REM #######################################################
REM Script Name: Get Domain Admins (GDA)
REM Author: Scott Sutherland (nullbind) <scott.sutherland@netspi.com>
REM Publish Date: 12/4/2011

REM #######################################################
REM Shout Outz!
REM #######################################################
REM Thank you Mark Beard (pacmandu) <pacmandu@gmail.com> and humble-desser
REM for your updating the script to accept five part domain names.

REM #######################################################
REM Script Summary
REM #######################################################
REM The primary goal of this script is to locate systems 
REM running processes with a Domain Admin account so that penetesters
REM can conduct cleaner privilege escalation in Active Directory domains.  
REM This way pentesters dont have to spray shells all over the place with
REM metasploit+psexec+meterpreter and scrape for admin tokens. :)

REM #######################################################
REM Check  Variables 
REM #######################################################
REM - Target Domain
IF EXIST target del target
echo %userdnsdomain% | gawk -F "." "{print $0}" > target
SET /p target_domain= < target
DEL target


REM - Checking total number of words in a given domain name and save on totalvar 
IF EXIST num_words del num_words
echo %userdnsdomain% | gawk  -F "." "{ total = total + NF }; END { print total+0 }" > num_words
SET /p totalvar= < num_words
DEL num_words

REM - Define all variables to be used later (e.g: var1=hacking, var2=lab, var3=local)
IF EXIST domainname del domainname
FOR /L %%G IN (1,1,%totalvar%) DO (echo %userdnsdomain% | gawk -F "." "{print $%%G}" > %%G
SET /p var%%G= < %%G
gawk "BEGIN { while (a++<1) s=s \"dc=%%var%%G%%\"; print s }" >> domainname
DEL %%G )

REM - Parsing the domain variables to be insert into domain_parameters (e.g: dc=%var1%,dc=%var2%,dc=%var3%)
IF EXIST domainname_var del domainname_var
gawk "NR==1{x=$0;next}NF{x=x\",\"$0}END{print x}" domainname > domainname_var
DEL domainname

REM - Fix parsing issues
IF EXIST domainname_var2 del domainname_var2
SET /p temp_var= < domainname_var
@echo %temp_var% | sed "s/'//" > domainname_var2
SET /p domain_parameter= < domainname_var2
DEL domainname_var 
DEL domainname_var2
 

if [%1] equ [] goto :SYNTAX
if [%1] equ [-h] goto :SYNTAX
if [%1] equ [-c] goto :CUSTOM
if [%1] equ [-a] goto :CURRENT
if [%1] equ [-l] goto :DUMPUSERSLDAP


goto :end
REM #######################################################

:SYNTAX
echo ------------------------------------------------------------
echo            GET DOMAIN ADMIN (GDA)
echo ------------------------------------------------------------
echo This script can be used to enumerate users that exist in 
echo the current machines domain and locate systems running 
echo processes as a domain admin
echo ------------------------------------------------------------
echo Syntax: 
echo -l Dump list of users from current domain using LDAP
echo -c Get list of DA sessions - custom domain
echo -a Get list of DA sessions - local machine's domain
echo ------------------------------------------------------------
REM #######################################################
REM Check for require binaries
REM #######################################################
IF NOT EXIST NetSess.exe GOTO missingfiles
IF NOT EXIST grep.exe GOTO missingfiles
IF NOT EXIST gawk.exe GOTO missingfiles
IF NOT EXIST adfind.exe GOTO missingfiles
IF NOT EXIST uniq.exe GOTO missingfiles
IF NOT EXIST findpdc.exe GOTO missingfiles
goto end

:missingfiles
echo                  ERROR
echo ----------------------------------------
echo The following required files 
echo are missing:	
echo - NetSess.exe 
echo - grep.exe 
echo - gawk.exe  
echo - adfind.exe 
echo - uniq.exe
echo - findpdc.exe
goto :end

:DUMPUSERSLDAP
IF EXIST users_ldap.txt del users_ldap.txt
@adfind -b %domain_parameter% -f "objectcategory=user" -gc | grep -i "sAMAccountName:" | gawk -F ":" "{print $2}" | gawk -F " " "{print $1}"| sort > users_ldap.txt
users_ldap.txt
goto :END

:CUSTOM
IF EXIST datargets.txt del datargets.txt
REM ####################################################### 
REM GET LIST OF DOMAIN CONTROLLERS WITH ADFIND
REM ####################################################### 
@adfind -b -sc dcdmp %domain_parameter% -gc | grep -i ">name:" | gawk -F " " "{print $2}" | sort | uniq >> dcs.txt 2>&1
echo -----------------------------------------------
echo Getting list of Domain Controllers...
echo -----------------------------------------------

REM ####################################################### 
REM GET LIST OF DOMAIN ADMINS WITH ADFIND
REM ####################################################### 
echo -----------------------------------------------
echo Getting list of Domain Admins...
echo -----------------------------------------------
@adfind -b %domain_parameter% -f name="Domain Admins" -gc > myadmins1.txt
grep -i "member:" myadmins1.txt > myadmins2.txt
sed -e s/^>member:" "CN=/'/g myadmins2.txt > myadmins3.txt
sed -e s/,/',/g myadmins3.txt > myadmins4.txt
cat myadmins4.txt | gawk -F "," "{print $1}" > myadmins5.txt
sed s/'//g myadmins5.txt > dcadmintmp.txt
del myadmins*.txt

REM PARSE LIST OF DOMAIN ADMINS
FOR /f "tokens=1 delims=" %%a IN ('cat dcadmintmp.txt') do @adfind -b %domain_parameter% -f name="%%a" | grep -i "sAMAccountName" | sed -e s/^>sAMAccountName:" "//g >> dcadmins.txt
del dcadmintmp.txt

REM ####################################################### 
REM SCAN FOR ACTIVE DOMAIN ADMIN SESSIONS (NETSESS)
REM ####################################################### 
echo -----------------------------------------------
echo Getting list of Active Domain Admin Sessions...
echo -----------------------------------------------
for /f %%a in ('type dcs.txt') do NetSess.exe %%a >> mysessions.txt 

REM Identify domain admin sessions
for /f %%a in ('type dcadmins.txt') do grep -i %%a mysessions.txt >> mysessions2.txt

echo =============================>>datargets.txt
echo TARGET DOMAIN                >>datargets.txt
echo ----------------------------->>datargets.txt
echo %userdnsdomain%              >>datargets.txt
echo _                            >>datargets.txt
goto :report


:CURRENT
IF EXIST datargets.txt del datargets.txt
REM ####################################################### 
REM GET LIST OF DOMAIN CONTROLLERS WITH ADFIND
REM ####################################################### 
findpdc %userdomain% 1 >> pdc1.txt
gawk -F "\\" "{print $3}" pdc1.txt > pdc.txt
SET /P PDC= < pdc.txt
del pdc1.txt
del pdc.txt
@adfind -b -sc dcdmp %domain_parameter% -f name=%PDC% -gc | grep -i ">name:" | gawk -F " " "{print $2}" | sort | uniq >> dcs.txt 2>&1
echo -----------------------------------------------
echo Getting list of Domain Controllers...
echo -----------------------------------------------

REM ####################################################### 
REM GET LIST OF DOMAIN ADMINS WITH ADFIND
REM ####################################################### 
echo -----------------------------------------------
echo Getting list of Domain Admins...
echo -----------------------------------------------
@adfind -b %domain_parameter% -f name="Domain Admins" -gc > myadmins1.txt
grep -i "member:" myadmins1.txt > myadmins2.txt
sed -e s/^>member:" "CN=/'/g myadmins2.txt > myadmins3.txt
sed -e s/,/',/g myadmins3.txt > myadmins4.txt
cat myadmins4.txt | gawk -F "," "{print $1}" > myadmins5.txt
sed s/'//g myadmins5.txt > dcadmintmp.txt
REM del myadmins*.txt

REM PARSE LIST OF DOMAIN ADMINS
FOR /f "tokens=1 delims=" %%a IN ('cat dcadmintmp.txt') do @adfind -b %domain_parameter% -f name="%%a" | grep -i "sAMAccountName" | sed -e s/^>sAMAccountName:" "//g >>dcadmins.txt
del dcadmintmp.txt

REM ####################################################### 
REM SCAN FOR ACTIVE DOMAIN ADMIN SESSIONS (NETSESS)
REM ####################################################### 
echo -----------------------------------------------
echo Getting list of Active Domain Admin Sessions...
echo -----------------------------------------------
for /f %%a in ('type dcs.txt') do NetSess.exe %%a >> mysessions.txt 

REM Identify domain admin sessions
for /f %%a in ('type dcadmins.txt') do grep -i %%a mysessions.txt >> mysessions2.txt

echo =============================>>datargets.txt
echo TARGET DOMAIN                >>datargets.txt
echo ----------------------------->>datargets.txt
echo %userdnsdomain%              >>datargets.txt
echo _                            >>datargets.txt

:report
REM ####################################################### 
REM PRINT REPORT
REM #######################################################
echo .
echo .
echo =============================>>datargets.txt
echo Domain Controllers           >>datargets.txt
echo ----------------------------->>datargets.txt
echo =============================
echo Domain Controllers
echo -----------------------------
uniq dcs.txt | sort >> datargets.txt
uniq dcs.txt | sort


echo =============================
echo Domain Admins
echo -----------------------------
echo _                            >>datargets.txt
echo =============================>>datargets.txt
echo Domain Admins	   			  >>datargets.txt
echo ----------------------------->>datargets.txt
uniq dcadmins.txt                 >>datargets.txt
uniq dcadmins.txt
del dcadmins.txt

echo _                            >>datargets.txt   
echo =============================>>datargets.txt
echo Active Domain Admin Sessions >>datargets.txt
echo =============================>>datargets.txt
echo =============================
echo Active Domain Admin Sessions 
echo -----------------------------
uniq mysessions2.txt | sort >> datargets.txt
uniq mysessions2.txt

datargets.txt

DEL myadmin*.txt

echo .
echo .
echo Results have been exported to datargets.txt
del mysessions2.txt
del mysessions.txt
del dcs.txt


:end