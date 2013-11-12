<#
	.SYNOPSIS
    Displays the clear text passwords for custom application pool idenities.
	
	.NOTES
	Must be run as administrator.
#>

# Command to dump IIS application pool configurations from applicationHost.config
$MyPools = c:\windows\system32\inetsrv\appcmd.exe list apppool
$MyPoolsConfigs = c:\windows\system32\inetsrv\appcmd.exe list apppool /text:* 

# Display status summary to user
$MyPoolCount = $MyPools.count
Write-Host " "
Write-Host "Found $MyPoolCount IIS application pools"
Write-Host "Dumping IIS application pool credentials in clear text..."
Write-Host " "

$MyPoolsConfigs | foreach {

	# Display application pool name
	if($_ -like "*APPPOOL.NAME*")  
	{	
		Write-Host "------------------------------------"
		write-host $_
	}
	
	# Display username for application pool
	if($_ -like "*username*")  
	{
		write-host $_
	}
	
	# Display password for application pool
	if($_ -like "*password*")  
	{
		write-host $_
	}
} 
Write-Host "------------------------------------"
Write-Host " "

<#
Below are things I would like to build out in the future.

# Import module
import-module WebAdministration 
		
# Recover application pool credentials
Get-WMIObject -Namespace root\WebAdministration -Class ApplicationPool | Foreach { $I = $_.Name + " - " + $_.ProcessModel.UserName + " - " + $_.ProcessModel.Password; $I }

# OS commands option look like the following
c:\windows\system32\inetsrv\appcmd.exe list apppool /text:*
c:\windows\system32\inetsrv\appcmd.exe list apppool /text:processModel.username
c:\windows\system32\inetsrv\appcmd.exe list apppool /text:processModel.password

# Get the app pool name for each IIS worker process
Get-WmiObject –class win32_process -filter 'name="w3wp.exe"' | Select-Object –Property Name, ProcessId, @{n='AppPool';e={$_.GetOwner().user}} 

#>