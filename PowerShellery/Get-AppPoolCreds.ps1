<#
	.SYNOPSIS
    Displays the clear text passwords for custom application pool idenities.
	
	.NOTES
	Must be run as administrator.
	Requires Powershell version 3 or above.
#>

#List available modules
$modules = get-module -listavailable | select name | foreach {
	
	#Check if the WebAdministration is available
	if( $_.name -eq "WebAdministration")
	{
		# Import module
		import-module WebAdministration 
		
		# Recover application pool credentials
		Get-WMIObject -Namespace root\WebAdministration -Class ApplicationPool | Foreach { $I = $_.Name + " - " + $_.ProcessModel.UserName + " - " + $_.ProcessModel.Password; $I }
	}
}


# get the app pool name for each iis worker process
#Get-WmiObject –class win32_process -filter 'name="w3wp.exe"' | Select-Object –Property Name, ProcessId, @{n='AppPool';e={$_.GetOwner().user}} 
