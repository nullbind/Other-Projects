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
# Account Query for SPN Information
##########################################
function Get-Spn{
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
	
	.EXAMPLE	 
	PS C:\> Get-Spn -type spn -search "MSSQLSvc"
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
	  
	.EXAMPLE   
	PS C:\> Get-Spn -type user -search "SVC_SQL"
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
	PS C:\> Get-Spn -type group -search "Domain Admins"
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
	
	.LINK
     http://www.netspi.com
     http://msdn.microsoft.com/en-us/library/windows/desktop/ms677949(v=vs.85).aspx
	 http://technet.microsoft.com/en-us/library/cc731241.aspx

	.NOTES
    Scott Sutherland 2013, NetSPI
	#>	
	
	[CmdletBinding()]
	Param(
	  [Parameter(Mandatory=$True,Position=1)]
	   [string]$Type,
		
	   [Parameter(Mandatory=$True)]
	   [string]$Search
	)	
	
	# Format domain for LDAP
    $current_domain = $env:USERDNSDOMAIN
    $domain_list = ""
    $current_domain.split(".")| foreach { $domain_list = $domain_list + ",DC=$_" }
	
	# Create query options
	$QueryGroup = "(&(objectCategory=user)(memberOf=CN=$Search,CN=Users$domain_list))"	
	$QueryUser = "(samaccountname=$Search)"
	$QuerySpn = "(ServicePrincipalName=$Search)"
	
	# Check query type
	if(($Type -eq "group") -or ($Type -eq "user") -or ($Type -eq "spn")){
		
		# Define query based on type
		switch ($Type) 
		{ 
			"group" {$MyFilter = $QueryGroup} 
			"user" {$MyFilter = $QueryUser} 
			"spn" {$MyFilter = $QuerySpn} 
			default {"Invalid query type."}
		}
		
		# Setup LDAP query filters
		$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
		$objSearcher.Filter = $MyFilter
		"name","samaccountname","ServicePrincipalName" | Foreach-Object {$null = $objSearcher.PropertiesToLoad.Add($_) }
		
		# Check if there are any matches for the search
		$records = $objSearcher.FindAll()
		$record_count = $records.count
		if ($record_count -gt 0){
			
			# Display account and service principal information
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
			
			# Display records found
			Write-Host " " 
			Write-Host "Found $record_count accounts that matched your search."
			Write-Host " " 
			
			#---------------------------------------------------------------------------------
			
			# Display account associated server information in uniqued list
			Write-Host " "  
			Write-Host "----------------------"
			$objSearcher.FindAll() | foreach {
				
				$MyName = $_.properties['name']
				[string]$MyAccount = $_.properties['samaccountname']
				
				$MySPN = $_.properties['ServicePrincipalName'] 
				$Uniqued += @{$MyAccount=@()}
							
				$MySPNCount = $MySPN.Count

				if ($MySPNCount -gt 0)
				{					
					$MySPN | foreach {
						
						$TempSpn =  $_.split("/")[1].split(":")[0]						
																		
						Write-Output "$MyAccount : $TempSpn"
						$Uniqued[$MyAccount] += $TempSpn
					}
				}			
			}
			
			Write-Host "Unique list of crap"
			$Uniqued 
			
			# Display records found
			Write-Host " " 
			Write-Host "Found $record_count accounts that matched your search."
			Write-Host " " 
			
		}else{
		
			# Display fail
			Write-Host " " 
			Write-Host "No records were found that match your search."
			Write-Host ""
		}
	}else{

		# Fail buckets
		Write-Host " "
		Write-Host "Invalid query type"
		Write-Host " "
	}    
}
