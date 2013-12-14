
##########################################
# ServicePrincipalName Query Function
##########################################
function Get-SPN
{

	<#
	.SYNOPSIS
	Displays Service Principal Names (SPN) for domain accounts based on SPN service name, 
	domain account, or domain group via LDAP queries.

	.DESCRIPTION
	Displays Service Principal Names (SPN) for domain accounts based on SPN service name, 
	domain account, or domain group via LDAP queries. This information can be used to 
	identify systems running specific services and the domain accounts running them.  
	For example, this script could be used to locate domain systems where SQL Server has been 
	installed.  It can also be used to help find systems where members of the Domain Admins 
	group might be logged in if the accounts where used to run services on the domain 
	(which is very common).  So this should be handy for both system administrators and 
	penetration testers.
	
	.EXAMPLE	 
	Get-SPN -type service -search "MSSQLSvc*"
	Get-SPN -type service -search "*sql*"
	Get-SPN -type service -search "*www*"
	Get-SPN -type service -search "*vnc*"

	.EXAMPLE	 
	Get-SPN -type user -search "svc-sql" 
	Get-SPN -type user -search "ServerAdmin"
	Get-SPN -type user -search "myDA"

	.EXAMPLE	 
	Get-SPN -type group -search "Domain Admins" 	 
	Get-SPN -type group -search "Domain Admins" -list yes	 
	Get-SPN -type group -search "Domain Admins" -list yes | Select Server
	Get-SPN -type group -search "Domain Admins" -DomainController 192.168.1.109 -Credential demo\user2 
	
	.LINK
	http://www.netspi.com
	http://msdn.microsoft.com/en-us/library/windows/desktop/ms677949(v=vs.85).aspx
	http://technet.microsoft.com/en-us/library/cc731241.aspx
	http://technet.microsoft.com/en-us/library/cc978021.aspx
	
	.NOTES
	Author: Scott Sutherland 2013, NetSPI
	This script require Powershell v3
	The LDAP function skeleton was taken from Carlos Perez's "Get-AuditDSDisabledUserAcount" function found in PoshSec-Mod.	
	#>	
	
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Credentials to use when connecting to a Domain Controller.")]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [Parameter(Mandatory=$false,
        HelpMessage="Domain controller for Domain and Site that you want to query against.")]
        [string]$DomainController,

        [Parameter(Mandatory=$false,
        HelpMessage="Maximum number of Objects to pull from AD, limit is 1,000 .")]
        [int]$Limit = 1000,

        [Parameter(Mandatory=$false,
        HelpMessage="scope of a search as either a base, one-level, or subtree search, default is subtree.")]
        [ValidateSet("Subtree","OneLevel","Base")]
        [string]$SearchScope = "Subtree",

        [Parameter(Mandatory=$false,
        HelpMessage="Distinguished Name Path to limit search to.")]
        [string]$SearchDN,

        [Parameter(Mandatory=$True,
        HelpMessage="Search by domain user, domain group, or SPN service name to search for.")]
	    [string]$Type,

		[Parameter(Mandatory=$True,
        HelpMessage="Define search for user, group, or SPN service name. Wildcards are accepted")]
	    [string]$Search,

        [Parameter(Mandatory=$false,
        HelpMessage="View minimal information that includes the accounts,affected systems,and registered services.  Nice for getting quick list of DAs.")]
	    [string]$List
    )

    Begin
    {
        if ($DomainController -and $Credential.GetNetworkCredential().Password)
        {
            $objDomain = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)", $Credential.UserName,$Credential.GetNetworkCredential().Password
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        }
        else
        {
            $objDomain = [ADSI]""  
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        }
    }

    Process
    {

        # Format the current domain for LDAP - SPS
        $current_domain = $env:USERDNSDOMAIN
        $domain_list = ""
        $current_domain.split(".")| foreach { $domain_list = $domain_list + ",DC=$_" }
	
	    # Create query options - SPS
	    $QueryGroup = "(&(objectCategory=user)(memberOf=CN=$Search,CN=Users$domain_list))"	
	    $QueryUser = "(samaccountname=$Search)"
	    $QueryService = "(ServicePrincipalName=$Search)"
        
        # Check SPN query type - SPS
	    if(($Type -eq "group") -or ($Type -eq "user") -or ($Type -eq "service")){
		
		    # Define query based on type
		    switch ($Type) 
		    { 
			    "group" {$MyFilter = $QueryGroup} 
			    "user" {$MyFilter = $QueryUser} 
			    "service" {$MyFilter = $QueryService} 
			    default {"Invalid query type."}
		    }
        }
		
        $ObjSearcher.PageSize = $Limit
        $ObjSearcher.Filter = $Myfilter
        $ObjSearcher.SearchScope = $SearchScope

        if ($SearchDN)
        {
            $objSearcher.SearchDN = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($SearchDN)")
        }

        # Get record count
        $records = $objSearcher.FindAll()
		$record_count = $records.count

        # Display search results if results exist
        if ($record_count -gt 0){
                
            # Create data table to house data
            $dataTable = New-Object System.Data.DataTable 

            # Create and name column in table
            $dataTable.Columns.Add("Account") | Out-Null
            $dataTable.Columns.Add("Server") | Out-Null
            $dataTable.Columns.Add("Service") | Out-Null            

            # Display records                
            $ObjSearcher.FindAll() | ForEach-Object {

                # Fill hash array with results                    
                $UserProps = [ordered]@{}                    
                $UserProps.Add('Name', "$($_.properties.name)")
                $UserProps.Add('SAMAccount', "$($_.properties.samaccountname)")
                $UserProps.Add('Description', "$($_.properties.description)")
                $UserProps.Add('UserPrincipal', "$($_.properties.userprincipalname)")
                $UserProps.Add('DN', "$($_.properties.distinguishedname)")
                $UserProps.Add('Created', [dateTime]"$($_.properties.whencreated)")
                $UserProps.Add('LastModified', [dateTime]"$($_.properties.whenchanged)")
                $UserProps.Add('PasswordLastSet', [dateTime]::FromFileTime("$($_.properties.pwdlastset)"))                    
                $UserProps.Add('AccountExpires',( &{$exval = "$($_.properties.accountexpires)"
                If (($exval -eq 0) -or ($exval -gt [DateTime]::MaxValue.Ticks))
                {
                    $AcctExpires = "<Never>"
                }Else{
                    $Date = [DateTime]$exval
                    $AcctExpires = $Date.AddYears(1600).ToLocalTime()
                }

               $AcctExpires
            
                    }))
                    $UserProps.Add('LastLogon', [dateTime]::FromFileTime("$($_.properties.lastlogon)"))
                    $UserProps.Add('GroupMembership', "$($_.properties.memberof)")
                    $UserProps.Add('SPN Count', "$($_.properties['ServicePrincipalName'].count)") 
                    #$UserProps.Add('ServicePrincipalName', "$($_.properties['ServicePrincipalName'])")                  

                    # Only display line for detailed view
                    If (!$list){

                        # Format array as object and display records
                        [pscustomobject]$UserProps 
                    }

                    $SPN_Count = $_.properties['ServicePrincipalName'].count

                    if ($SPN_Count -gt 0)
				    {
                        
                        # Only display line for detailed view
                        If (!$list){
					        Write-Output "ServicePrincipalNames (SPN):"
					        $_.properties['ServicePrincipalName']
                        }
                        
                        # Add records to data table
                        foreach ($item in $_.properties['ServicePrincipalName'])
                        {
                            $x =  $_.properties['ServicePrincipalName'].split("/")[1].split(":")[0]	
                            $y =  $_.properties['ServicePrincipalName'].split("/")[0]                                                                                   
                            $dataTable.Rows.Add($($_.properties.samaccountname), $x, $y) | Out-Null  
                        }

				    }            
                    
                    
                    # Only display line for detailed view
                    If (!$list){
                        Write-Host "-------------------------------------------------------------"
                    }

                } 

                    # Only display lines for detailed view
                    If (!$list){

                        # Display number of accounts found
			            Write-Host "Found $record_count accounts that matched your search."   
                        Write-Host "-------------------------------------------------------------"                                    

                        # Dispaly list view of results
                        $dataTable | Sort-Object Account,Server,Service | Format-Table -AutoSize

                        # Display number of service instances
                        $instance_count = $dataTable.rows.count
			            Write-Host "-------------------------------------------------------------"
                        Write-Host "Found $instance_count service instances that matched your search."
                        Write-Host "-------------------------------------------------------------"
                    }else{
                        
                        # Dispaly list view of results
                        $dataTable | Sort-Object Account,Server,Service 
                    }

        }else{
            
            # Display fail
			Write-Host " " 
			Write-Host "No records were found that match your search."
			Write-Host ""
        }

        
    }
}


# Commands tested that work
#Get-SPN  -type group -search "Domain Admins" -DomainController 192.168.1.109 -Credential demo\user2
#Get-SPN -type service -search "*www*"
#Get-SPN -type service -search "*sql*"
#Get-SPN -type user -search "sqladmin"
#Get-SPN -type group -search "Domain Admins"
#Get-SPN -type group -search "Domain Admins" -list yes
#Get-SPN -type group -search "Domain Admins" -list yes | Select server

# known / pending Issues
# - Group search uses users defaultdnsdomain instead of specific
# - need to debug authenticating to specified dc from another domain
# - need to dedpulicate the dta table before displaying info...seems to be a bug somewhere