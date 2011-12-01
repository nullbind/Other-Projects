@echo off
cls

REM #######################################################
REM Check  Variables 
REM #######################################################
echo %userdnsdomain% | gawk -F "." "{print $1}">1
echo %userdnsdomain% | gawk -F "." "{print $2}">2
SET /p var1= < 1
SET /p var2= < 2
DEL 1
DEL 2

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
echo -c Get list of DA sessions - custom domain (gda -c acme com)
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
@adfind -b dc=%var1%,dc=%var2% -f "objectcategory=user" -gc | grep -i "sAMAccountName:" | gawk -F ":" "{print $2}" | gawk -F " " "{print $1}"| sort > users_ldap.txt
users_ldap.txt
goto :END

:CUSTOM
IF EXIST datargets.txt del datargets.txt
REM ####################################################### 
REM GET LIST OF DOMAIN CONTROLLERS WITH ADFIND
REM ####################################################### 
@adfind -b -sc dcdmp dc=%2,dc=%3 -gc | grep -i ">name:" | gawk -F " " "{print $2}" | sort | uniq >> dcs.txt 2>&1
echo -----------------------------------------------
echo Getting list of Domain Controllers...
echo -----------------------------------------------

REM ####################################################### 
REM GET LIST OF DOMAIN ADMINS WITH ADFIND
REM ####################################################### 
echo -----------------------------------------------
echo Getting list of Domain Admins...
echo -----------------------------------------------
@adfind -b dc=%2,dc=%3 -f name="Domain Admins" -gc > myadmins1.txt
grep -i "member:" myadmins1.txt > myadmins2.txt
sed -e s/^>member:" "CN=/'/g myadmins2.txt > myadmins3.txt
sed -e s/,/',/g myadmins3.txt > myadmins4.txt
cat myadmins4.txt | gawk -F "," "{print $1}" > myadmins5.txt
sed s/'//g myadmins5.txt > dcadmintmp.txt
del myadmins*.txt

REM PARSE LIST OF DOMAIN ADMINS
FOR /f "tokens=1 delims=" %%a IN ('cat dcadmintmp.txt') do @adfind -b dc=%2,dc=%3 -f name="%%a" | grep -i "sAMAccountName" | sed -e s/^>sAMAccountName:" "//g >> dcadmins.txt
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
echo %2.%3                        >>datargets.txt
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
@adfind -b -sc dcdmp dc=%var1%,dc=%var2% -f name=%PDC% -gc | grep -i ">name:" | gawk -F " " "{print $2}" | sort | uniq >> dcs.txt 2>&1
echo -----------------------------------------------
echo Getting list of Domain Controllers...
echo -----------------------------------------------

REM ####################################################### 
REM GET LIST OF DOMAIN ADMINS WITH ADFIND
REM ####################################################### 
echo -----------------------------------------------
echo Getting list of Domain Admins...
echo -----------------------------------------------
@adfind -b dc=%var1%,dc=%var2% -f name="Domain Admins" -gc > myadmins1.txt
grep -i "member:" myadmins1.txt > myadmins2.txt
sed -e s/^>member:" "CN=/'/g myadmins2.txt > myadmins3.txt
sed -e s/,/',/g myadmins3.txt > myadmins4.txt
cat myadmins4.txt | gawk -F "," "{print $1}" > myadmins5.txt
sed s/'//g myadmins5.txt > dcadmintmp.txt
REM del myadmins*.txt

REM PARSE LIST OF DOMAIN ADMINS
FOR /f "tokens=1 delims=" %%a IN ('cat dcadmintmp.txt') do @adfind -b dc=%var1%,dc=%var2% -f name="%%a" | grep -i "sAMAccountName" | sed -e s/^>sAMAccountName:" "//g >>dcadmins.txt
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