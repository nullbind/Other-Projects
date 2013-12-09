function Get-SPN2
{
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
        HelpMessage="Set type user, group, or spn to search by.")]
	    [string]$Type,

		[Parameter(Mandatory=$True,
        HelpMessage="Define search for user, group, or spn.")]
	    [string]$Search,

        [Parameter(Mandatory=$false,
        HelpMessage="View minimal information that includes the account and affected systems.  Nice for getting quick list of DAs.")]
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
	    $QuerySpn = "(ServicePrincipalName=$Search)"
        
        # Check SPN query type - SPS
	    if(($Type -eq "group") -or ($Type -eq "user") -or ($Type -eq "spn")){
		
		    # Define query based on type
		    switch ($Type) 
		    { 
			    "group" {$MyFilter = $QueryGroup} 
			    "user" {$MyFilter = $QueryUser} 
			    "spn" {$MyFilter = $QuerySpn} 
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
			
            # Check if list view was set
            if($list){     
                
                # Display records in list view     


            }else{

                # Display records in verbose view  
                # Note: use nullbind code and convert to object when all is done....pending              
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
                        }
                        Else
                        {
                            $Date = [DateTime]$exval
                            $AcctExpires = $Date.AddYears(1600).ToLocalTime()
                        }
                        $AcctExpires
            
                    }))
                    $UserProps.Add('LastLogon', [dateTime]::FromFileTime("$($_.properties.lastlogon)"))
                    $UserProps.Add('GroupMembership', "$($_.properties.memberof)")
                    $UserProps.Add('SPN Count', "$($_.properties['ServicePrincipalName'].count)") 
                    #$UserProps.Add('ServicePrincipalName', "$($_.properties['ServicePrincipalName'])")                  

                    
                    # Format array as object and display records
                    [pscustomobject]$UserProps 

                    $SPN_Count = $_.properties['ServicePrincipalName'].count

                    if ($SPN_Count -gt 0)
				    {
					    Write-Output "ServicePrincipalNames (SPN):"
					    $_.properties['ServicePrincipalName']
				    }            
                    
                    Write-Host "------------------------------------------------"
                }

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

        
    }
}

Get-SPN2 -type group -search "Domain Admin"