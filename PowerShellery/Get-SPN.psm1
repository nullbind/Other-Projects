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
	PS C:\> Get-Spn -type service -search "MSSQLSvc"
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
     http://technet.microsoft.com/en-us/library/cc978021.aspx

	.NOTES
    Scott Sutherland 2013, NetSPI
    The LDAP function skeleton was taken from Carlos Perez's "Get-AuditDSDisabledUserAcount" function.
	#>	
	
	[CmdletBinding()]
	Param(
	  [Parameter(Mandatory=$True)]
	   [string]$Type,
		
	   [Parameter(Mandatory=$True)]
	   [string]$Search,

       [Parameter(Mandatory=$False)]
	   [string]$List
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
	if(($Type -eq "group") -or ($Type -eq "user") -or ($Type -eq "service")){
		
		# Define query based on type
		switch ($Type) 
		{ 
			"group" {$MyFilter = $QueryGroup} 
			"user" {$MyFilter = $QueryUser} 
			"service" {$MyFilter = $QuerySpn} 
			default {"Invalid query type."}
		}
		
		# Setup LDAP query filters
		$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
		$objSearcher.Filter = $MyFilter
		"name","description","samaccountname","ServicePrincipalName" | Foreach-Object {$null = $objSearcher.PropertiesToLoad.Add($_) }		        

		# Check if there are any matches for the search
		$records = $objSearcher.FindAll()
		$record_count = $records.count
		if ($record_count -gt 0){
			
            if($list){                      

                # Dispaly minimal information
	            # Display account associated server information in uniqued list			
                # get-process | select @{name = 'test';expression = {$_.ProcessName}}
	            $objSearcher.FindAll() | foreach {
				
		            $MyName = $_.properties['name']
		            [string]$MyAccount = $_.properties['samaccountname']
				
		            $MySPN = $_.properties['ServicePrincipalName'] 
		            $Uniqued += @{$MyAccount=@()}
		            $MySPNCount = $MySPN.Count

                    # Check if any SPN exist
		            if ($MySPNCount -gt 0)
		            {					
		                $MySPN | foreach {
						
			            $TempSpn =  $_.split("/")[1].split(":")[0]																														
			            $Uniqued[$MyAccount] += $TempSpn                           

			            }
		            }			
	            }			                  

               Write-Host " "  
               Write-Host "----------------------------------------------------"
               Write-Host "List of servers where accounts are registered to run"
               Write-Host "----------------------------------------------------"

               # Setup hash array to store accounts and server information
               $UserProps = [ordered]@{}
               
               # Create data table to house data
               $dataTable = New-Object System.Data.DataTable 

               # Create and name column in table
               $dataTable.Columns.Add("Account") | Out-Null
               $dataTable.Columns.Add("Server") | Out-Null

               # Uniq the servers for each account
               $Uniqued.keys.clone()| Foreach {
                    $Uniqued[$_]=  $Uniqued[$_] | select -Unique
               }
            
               # If a spn exist for an account then print the info   
               $account_count = 0    

               $Uniqued.keys | Foreach {

                    $account = $_ ; 

                    # Only display accounts if they have a spn
                    if ($Uniqued[$_].Count -gt 0) {
                        
                        $account_count = $account_count+1

                        # Display account and associated spn
                        $Uniqued[$_] | %{ $account +" : " +$_;}
                        $dataTable.Rows.Add($account, $_) | Out-Null  
                    } 
                }     
                # Format array as object and display records
                #[pscustomobject]$UserProps  

                $Uniqued[$_]

                $dataTable | Sort-Object Account,Server| Format-Table -AutoSize 
                     

                # Display records found
                Write-Host "----------------------------------------------------"
			    Write-Host "Found $account_count accounts with SPNs that matched your search."
			    Write-Host " "  
	        }else { 

			    # Display account and service principal information
			    Write-Host " "  
			    Write-Host "----------------------"

               # Create data table to house data
               $dataTable = New-Object System.Data.DataTable 

               # Create and name column in table
               $dataTable.Columns.Add("Account") | Out-Null
               $dataTable.Columns.Add("Server") | Out-Null
                               
			    $objSearcher.FindAll() | foreach {
			
				    $MyName = $_.properties['name']
				    [string]$MyAccount = $_.properties['samaccountname']
				    $MySPN = $_.properties['ServicePrincipalName'] 
                    $MyDescription = $_.properties['description']                   
				    $MySPNCount = $MySPN.Count

				    Write-Output "Name: $MyName"
				    Write-Output "Account: $MyAccount"
				    Write-Output "Description: $MyDescription"
				    Write-Output "SPN Count: $MySPNCount"
				    if ($MySPNCount -gt 0)
				    {
					    Write-Output "Service Principal Names:"
					    $MySPN
                        foreach ($item in $mySPN){
                            $x =  $MySPN.split("/")[1].split(":")[0]	                            
                            $dataTable.Rows.Add($MyAccount, $x) | Out-Null  
                        }
				    }
				    Write-Host "----------------------"
			    }
			
                 $dataTable | Sort-Object Account,Server| Format-Table -AutoSize 

			    # Display records found
			    Write-Host " " 
			    Write-Host "Found $record_count accounts that matched your search."
			    Write-Host " "     
            }
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

#get-spn -type service -search "*sql*" 


