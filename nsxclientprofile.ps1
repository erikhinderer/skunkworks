# VMware TAM NSX Client Profile
#Program:        nsxclientprofile.ps1
#Description:    Export VMware NSX-v DFW
#Version:        1.0
#Date:           09/20/2018
#Website:        http://www.virtuallyread.com
#Author:         Erik Hinderer
#Compatibility   NSX-v 6.4.x

# Adds the base cmdlets
Add-PSSnapin VMware.VimAutomation.Core
$config = Get-PowerCLIConfiguration 
if($config.DefaultVIServerMode -eq "Single"){
    Set-PowerCLIConfiguration -DefaultVIServerMode Multiple
}

# Set client vCenter environment variables
$vclist = @(Read-Host "Please enter the FQDN or IP address of vCenter Server")
"Please enter your vCenter credentials"
$creds = get-credential "root"
connect-viserver -server $vclist -credential $creds -WarningAction 0

# Set client NSX environment variables
$nsxclientname = Read-Host "Please enter the name of the client company"
$nsxmanager = Read-Host "Please enter the FQDN or IP address of NSX Manager"
$nsxadmin = Read-Host "Please enter the NSX Manager admin account"
$nsxadminpassresponse = Read-Host "Please enter the NSX Manager admin password" -AsSecureString
$nsxadminpass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($nsxadminpassresponse))

function Get-NSXController {

[CmdletBinding()] 
	param(
		[Parameter(Mandatory=$true,Position=0)]
		[String]$NSXManager,
		[Parameter(Mandatory=$false,Position=1)]
		[String]$Username = "admin",
		[Parameter(Mandatory=$false)]
		[String]$Password
  	)

	Process {

	# Ignore TLS/SSL errors	

	[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

	# Create authorization string and store in $head
	$auth = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Username + ":" + $Password))
	$head = @{"Authorization"="Basic $auth"}

	# Connect to NSX Manager via API
	$Request = "https://$NSXManager/api/2.0/vdn/controller"
	$r = Invoke-WebRequest -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop
	if ($r.StatusCode -eq "200") {Write-Host -BackgroundColor:Black -ForegroundColor:Green Status: Connected to $NSXManager successfully.}
	[xml]$rxml = $r.Content
	
	# Return the NSX Controllers
	$global:nreport = @()
	foreach ($controller in $rxml.controllers.controller)
		{
		$n = @{} | select Name,IP,Status,Version,VMName,Host,Datastore
		$n.Name = $controller.id
		$n.IP = $controller.ipAddress
		$n.Status = $controller.status
		$n.Version = $controller.version
		$n.VMName = $controller.virtualMachineInfo.name
		$n.Host = $controller.hostInfo.name
		$n.Datastore = $controller.datastoreInfo.name
		$global:nreport += $n
		}
	$global:nreport | ft -AutoSize

	} # End of process
} # End of function

# Setting global variables for VMHost NIC driver and firmware function
$output = @()

# Output the available clusters to choose from
$InputCluster = Get-Cluster

# Gather available VMHosts
$vmhosts = Get-Cluster $InputCluster -ErrorAction Stop | Get-VMHost | where {$_.ConnectionState -eq 'Maintenance' -or $_.State -eq 'Connected'} | sort Name

# Loop through each VMHost gathering information
foreach ($vmh in $vmhosts) {
# Null variables which will be reused in the loop
$esxcli = $niclist = $null

# Connect to the vmhost via esxcli and then pull its NICs
$esxcli = $vmh | Get-EsxCli
$niclist = $esxcli.network.nic.list()

# Loop through each NIC gathering information
foreach ($nic in $niclist) {
# Null variables which will be reused in the loop
$tempvar = $driverinfo = $null

# Gather NIC information from the DriverInfo selection
$driverinfo = $esxcli.network.nic.get($nic.Name).DriverInfo

# Feed NIC information into a variable to be displayed later
$tempvar = "" | select VMHost,Nic,Driver,DV,FV
$tempvar.VMHost = ($vmh.Name).Split('.')[0]
$tempvar.Nic = $nic.Name
$tempvar.Driver = $driverinfo.Driver
$tempvar.DV = $driverinfo.Version
$tempvar.FV = $driverinfo.FirmwareVersion

# Add the above variable to variable that's to be the final result
$output += $tempvar
}

}

# Creating report output file
$output_file = @(

echo "NSX Client Profile - $nsxclientname"`r`n

# Return the NSX Manager
echo "[NSX Manager Details]"
Connect-NsxServer -Server $nsxmanager -VIUserName $nsxadmin -VIPassword $nsxadminpass | Format-Table Server,Version,BuildNumber,VIConnection

# Return the NSX Clusters
echo "[NSX Cluster Details]"
Get-Cluster | Format-Table Name,HAEnabled,HAFailoverLevel,DrsEnabled,DrsAutomationLevel
Get-Cluster | Get-NsxClusterStatus | Format-Table -AutoSize featureId,featureVersion,status,enabled,installed,updateAvailable,messsage,allowConfiguration

# Return the NSX Controllers
echo "[NSX Controller Details]"
Get-NSXController -NSXManager $nsxmanager -Username $nsxadmin -Password $nsxadminpass

# Return the NSX Logical Switches
echo "[NSX Logical Switch Details]"
Get-NsxTransportZone | Get-NsxLogicalSwitch | Format-Table name,objectTypeName,objectId,tenantId,controlPlaneMode,vdnScopeId,vdsContextWithBacking,vdnId,guestVlanAllowed,macLearningEnabled

# Return the NSX Logical Routers
echo "[NSX Logical Router Details]"
Get-NsxLogicalRouter | Format-Table Name,type,version,status,fqdn,datacenterName,id,vseLogLevel
Get-NsxLogicalRouter | Get-NsxLogicalRouterInterface | Format-Table name,logicalRouterId,label,type,isConnected,connectedToName,connectedToId,IsSharedNetwork
Get-NsxLogicalRouter | Get-NsxLogicalRouterRouting | Format-Table logicalrouterId,ospf,staticRouting,enabled,version

# Return the NSX Edge Gateways
echo "[NSX Edge Gateway Details]"
Get-NsxEdges -NSXManager $nsxmanager -Username $nsxadmin -Password $nsxadminpass
Get-NSXEdgeFeatures -NSXManager $nsxmanager -Username $nsxadmin -Password $nsxadminpass
echo "[NSX Host NIC Driver and Firmware Details]"
$output | Format-Table @{Expression={$_.VMHost};Label="vSphere Host";width=250},@{Expression={$_.NIC};Label="Network Interface Card (NIC)";width=250},@{Expression={$_.Driver};Label="Driver";width=2500},@{Expression={$_.DV};Label="Driver Version";width=2500}, `
@{Expression={$_.FV};Label="Firmware Version";width=250}

### Return the NSX Security Policies
echo "[NSX Security Policies]"
Get-NsxSecurityPolicy | Sort-Object Name | Format-Table Name,objectId

### Return the NSX Security Groups
echo "[NSX Security Groups]"
Get-NsxSecurityGroup | Sort-Object Name | Format-Table Name,objectId,revision,isUniversal,universalRevision,inheritanceAllowed 

### Return the NSX Security Services
echo "[NSX Security Services]"
Get-NSXService | Sort-Object Name | Format-Table Name,objectId,revision,isUniversal,universalRevision,inheritanceAllowed 
Get-VM | Get-NsxCliDfwRule | Format-Table

)
$output_file | ConvertTo-HTML -head $nsxclientname -body "<H2>NSX Client Profile</H2>" | Set-AlternatingRows -CSSEvenClass even -CSSOddClass odd | Out-file C:\nsxclientprofile-$nsxclientname.html
