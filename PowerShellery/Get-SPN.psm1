<# 
	.SYNOPSIS
    Displays Service Principal Names (SPN) for domain accounts based on SPN, domain account, 
    or domain group for the current domain via LDAP queries.

	.DESCRIPTION
    Displays Service Principal Names (SPN) for domain accounts based on SPN, domain account, 
    or domain group for the current domain via LDAP queries.  This information can be used to 
    identify systems running specific services, and in some cases locate systems that specific 
    domain accounts are running on.  For example, it could be used to locate systems where a 
    specific domain account was used to run SQL Server.  It can also be used to identify systems 
    where Domain Admins or other domain group members may be logged in.  Which can be valuable 
    when escalating privileges during penetration tests.
	
	.LINK
     http://www.netspi.com
     http://msdn.microsoft.com/en-us/library/windows/desktop/ms677949(v=vs.85).aspx
	 http://technet.microsoft.com/en-us/library/cc731241.aspx

	.NOTES
    Scott Sutherland 2013, NetSPI
#>


##########################################
# Search for SPN by SPN
##########################################
function Get-SpnBySpn{
	<# 
	 .SYNOPSIS
	  Search for Service Principals by the Service Principal Name (SPN).
	  A list of Service Principal Names can be found at:
	 
	  http://technet.microsoft.com/en-us/library/cc731241.aspx.
	  
	 .DESCRIPTION
     Displays Service Principal Names (SPN) for domain accounts based on SPN for the current domain
	 via LDAP queries.  This information can be used to identify systems running specific services, 
	 and in some cases locate systems that specific domain accounts are running on.  For example, 
	 it could be used to locate systems where a specific domain account was used to run SQL Server.  
	 It can also be used to identify systems where Domain Admins or other domain group members may 
	 be logged in.  Which can be valuable when escalating privileges during penetration tests.

	 .EXAMPLE	 
	  PS C:\> Get-SpnBySpn -search "MSSQLSvc"
	  ----------------------
	  Account: SQLSERVER1-PROD$
	  SPN Count: 2
	  Service Principal Names:d
	  MSSQLSvc/SQLSERVER1-PROD.netspi.local:55030
	  MSSQLSvc/SQLSERVER1-PROD.netspi.local:PROD
	  ----------------------
	  Account: SQLSERVER2-DEV$
	  SPN Count: 2
	  Service Principal Names:
	  MSSQLSvc/SQLSERVER2-DEV.netspi.local:1433
	  MSSQLSvc/SQLSERVER2-DEV.netspi.local:DEV
	  ----------------------
		   
	 .EXAMPLE		  
	  PS C:\> Get-SpnBySpn -search "MSSQL*"
	  ----------------------
	  Account: SQLSERVER1-PROD$
	  SPN Count: 2
	  Service Principal Names:d
	  MSSQLSvc/SQLSERVER1-PROD.netspi.local:55030
	  MSSQLSvc/SQLSERVER1-PROD.netspi.local:PROD
	  ----------------------
	  Account: SQLSERVER2-DEV$
	  SPN Count: 2
	  Service Principal Names:
	  MSSQLSvc/SQLSERVER2-DEV.netspi.local:1433
	  MSSQLSvc/SQLSERVER2-DEV.netspi.local:DEV
	  ----------------------
	#>

	[CmdletBinding()]
	param(
		 [Parameter(Mandatory=$true)]
		 [String]$Search
	)

	#Get current domain
    $current_domain = $env:USERDNSDOMAIN
    $domain_list = ""
    $current_domain.split(".")| foreach { $domain_list = $domain_list + ",DC=$_" }

    #Get all accounts with spns (based on service principal name)
    $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
    $objSearcher.Filter = "(ServicePrincipalName=$Search)"
    "name","samaccountname","ServicePrincipalName" | Foreach-Object {$null = $objSearcher.PropertiesToLoad.Add($_) }
    
	# Check if there are any matches for the search
	$records = $objSearcher.FindAll()
	$record_count = $records.count
	if ($record_count -gt 0){
		
		# Dispaly account and service principal information
		Write-Host " "  
		Write-Host "----------------------"
		$objSearcher.FindAll() | foreach {
		
			$MyName = $_.properties['name']
			$MyAccount = $_.properties['samaccountname']
			$MySPN = $_.properties['ServicePrincipalName'] 
			$MySPNCount = $MySPN.Count

			Write-Output "Name: $MyName"
			Write-Output "Account: $MyAccount"
			Write-Output "SPN Count: $MySPNCount"
				if ($MySPNCount -gt 0)
				{
					Write-Output "Service Principal Names:"
					$MySPN
				}
			Write-Host "----------------------"
		}
	}
	
	# Display records found
	Write-Host " " 
	Write-Host "Found $record_count accounts that matched your search."
	Write-Host " " 
}


##########################################
# Search for SPN by domain account    
##########################################
function Get-SpnByUser{
	<# 
	 .SYNOPSIS
	  Search for Service Principals by the domain account (samaccountname).
	  
	 .DESCRIPTION
     Displays Service Principal Names (SPN) for domain accounts for the current domain via LDAP 
	 queries.  This information can be used to identify systems running specific services, and 
	 in some cases locate systems that specific domain accounts are running on.  For example, 
	 it could be used to locate systems where a specific domain account was used to run SQL 
	 Server.  It can also be used to identify systems where Domain Admins or other domain group 
	 members may be logged in.  Which can be valuable when escalating privileges during penetration 
	 tests.

	.EXAMPLE   
	PS C:\> Get-SpnByUser -search "SVC_SQL"
	----------------------
	Name: SQL Service Account	
	Account: SVC_SQL
	SPN Count: 4
	Service Principal Names:
	MSSQLSvc/SQLSERVER1-PROD.netspi.local:55030
	MSSQLSvc/SQLSERVER1-PROD.netspi.local:PROD
	MSSQLSvc/SQLSERVER2-DEV.netspi.local:1433
	MSSQLSvc/SQLSERVER2-DEV.netspi.local:DEV
	
	.EXAMPLE   
	PS C:\> Get-SpnByUser -search "*SQL"
	----------------------
	Name: SQL Service Account	
	Account: SVC_SQL
	SPN Count: 4
	Service Principal Names:
	MSSQLSvc/SQLSERVER1-PROD.netspi.local:55030
	MSSQLSvc/SQLSERVER1-PROD.netspi.local:PROD
	MSSQLSvc/SQLSERVER2-DEV.netspi.local:1433
	MSSQLSvc/SQLSERVER2-DEV.netspi.local:DE
	#>
	
	[CmdletBinding()]
	param(
		 [Parameter(Mandatory=$true)]
		 [String]$Search
	)
	
	#Get current domain
    $current_domain = $env:USERDNSDOMAIN
    $domain_list = ""
    $current_domain.split(".")| foreach { $domain_list = $domain_list + ",DC=$_" }

    #Get all SPNs for all accounts (based on account filter)
    $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
    $objSearcher.Filter = "(samaccountname=$Search)"
    "name","samaccountname","ServicePrincipalName" | Foreach-Object {$null = $objSearcher.PropertiesToLoad.Add($_) }
	
	# Check if there are any matches for the search
	$records = $objSearcher.FindAll()
	$record_count = $records.count
	if ($record_count -gt 0){
		
		# Dispaly account and service principal information
		Write-Host " "  
		Write-Host "----------------------"
		$objSearcher.FindAll() | foreach {
		
			$MyName = $_.properties['name']
			$MyAccount = $_.properties['samaccountname']
			$MySPN = $_.properties['ServicePrincipalName'] 
			$MySPNCount = $MySPN.Count

			Write-Output "Name: $MyName"
			Write-Output "Account: $MyAccount"
			Write-Output "SPN Count: $MySPNCount"
				if ($MySPNCount -gt 0)
				{
					Write-Output "Service Principal Names:"
					$MySPN
				}
			Write-Host "----------------------"
		}
	}
	
	# Display records found
	Write-Host " " 
	Write-Host "Found $record_count accounts that matched your search."
	Write-Host " " 
}


##########################################
# Search for SPN by domain group 
##########################################
function Get-SpnByGroup{
	<# 
	 .SYNOPSIS
	  Search for Service Principals by the domain group.
	  
	 .DESCRIPTION
     Displays Service Principal Names (SPN) for domain accounts for the current domain via LDAP 
	 queries.  This information can be used to identify systems running specific services, and 
	 in some cases locate systems that specific domain accounts are running on.  For example, 
	 it could be used to locate systems where a specific domain account was used to run SQL 
	 Server.  It can also be used to identify systems where Domain Admins or other domain group 
	 members may be logged in.  Which can be valuable when escalating privileges during penetration 
	 tests.

	.EXAMPLE   
	PS C:\> Get-SpnByGroup -search "Domain Admins"
	----------------------
	Name: Super Admin 1		
	Account: Admin1
	SPN Count: 0
	----------------------
	Name: Super Admin 2		
	Account: admin2
	SPN Count: 0
	----------------------
	Name: Super Admin 3	
	Account: admin3
	SPN Count: 0
	----------------------
	Name: SQL Service Account
	Account: SVC_SQL
	SPN Count: 4
	Service Principal Names:
	MSSQLSvc/SQLSERVER1-PROD.netspi.local:55030
	MSSQLSvc/SQLSERVER1-PROD.netspi.local:PROD
	MSSQLSvc/SQLSERVER2-DEV.netspi.local:1433
	MSSQLSvc/SQLSERVER2-DEV.netspi.local:DEV
	----------------------
	#>
	
	[CmdletBinding()]
	param(
		 [Parameter(Mandatory=$true)]
		 [String]$Search
	)
	
	#Get current domain
    $current_domain = $env:USERDNSDOMAIN
    $domain_list = ""
    $current_domain.split(".")| foreach { $domain_list = $domain_list + ",DC=$_" }

    #Get all SPNs for domain admin accounts (based on group name)
    $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
    $objSearcher.Filter = "(memberOf=CN=$Search,CN=Users$domain_list)"
    "name","samaccountname","ServicePrincipalName" | Foreach-Object {$null = $objSearcher.PropertiesToLoad.Add($_) }
	
 	# Check if there are any matches for the search
	$records = $objSearcher.FindAll()
	$record_count = $records.count
	if ($record_count -gt 0){
		
		# Dispaly account and service principal information
		Write-Host " "  
		Write-Host "----------------------"
		$objSearcher.FindAll() | foreach {
		
			$MyName = $_.properties['name']
			$MyAccount = $_.properties['samaccountname']
			$MySPN = $_.properties['ServicePrincipalName'] 
			$MySPNCount = $MySPN.Count

			Write-Output "Name: $MyName"
			Write-Output "Account: $MyAccount"
			Write-Output "SPN Count: $MySPNCount"
				if ($MySPNCount -gt 0)
				{
					Write-Output "Service Principal Names:"
					$MySPN
				}
			Write-Host "----------------------"
		}
	}
	
	# Display records found
	Write-Host " " 
	Write-Host "Found $record_count accounts that matched your search."
	Write-Host " " 
}