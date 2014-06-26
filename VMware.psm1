Function Connect-VI()
{
    <#
        .SYNOPSIS
            Connects to one more more vCenter sessions

        .DESCRIPTION
            Connects to vCenter sessions from provided hosts.

        .EXAMPLE
            PS C:\> Connect-VI vc1.school.edu

        .EXAMPLE
            PS C:\> Connect-VI @('vc1.school.edu','vc2.school.edu')
    #>
    Param (
        [Parameter(ValueFromPipeline=$true)]$vchosts,
        [Parameter(Mandatory=$False)][switch]$disconnectExisting = [switch]::$false
    )
	Write-Debug "Connecting to VIServers";
	#  Clear out any existing session
	if (($defaultVIServer -ne $null -or $defaultVIServers.length -gt 0) -and $disconnectExisting.IsPresent)
	{
		Write-Debug "Existing connections found ($defaultVIServers), disconnecting";
		Disconnect-VIServer * -Confirm:$false -ErrorAction SilentlyContinue
	}
		
    # Set some configuration defaults
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false
    Set-PowerCLIConfiguration -DefaultVIServerMode Multiple -Confirm:$false

	# Connect to the appropriate vCenter Servers
	Connect-VIServer $vchosts -ErrorAction:Stop | Out-Null
    Write-Debug "Connected to VIServer $defaultVIServers";
}

Function Get-ViSession 
{
    <#
        .SYNOPSIS
            Lists vCenter Sessions.

        .DESCRIPTION
            Lists all connected vCenter Sessions.

        .EXAMPLE
            PS C:\> Get-VISession

        .EXAMPLE
            PS C:\> Get-VISession | Where { $_.IdleMinutes -gt 5 }
    #>
    $SessionMgr = Get-View $DefaultViserver.ExtensionData.Client.ServiceContent.SessionManager
    $AllSessions = @()
    $SessionMgr.SessionList | Foreach {   
        $Session = New-Object -TypeName PSObject -Property @{
            Key = $_.Key
            UserName = $_.UserName
            FullName = $_.FullName
            LoginTime = ($_.LoginTime).ToLocalTime()
            LastActiveTime = ($_.LastActiveTime).ToLocalTime()
           
        }
            If ($_.Key -eq $SessionMgr.CurrentSession.Key) {
                $Session | Add-Member -MemberType NoteProperty -Name Status -Value "Current Session"
            } Else {
                $Session | Add-Member -MemberType NoteProperty -Name Status -Value "Idle"
            }
            $Session | Add-Member -MemberType NoteProperty -Name IdleMinutes -Value ([Math]::Round(((Get-Date) – ($_.LastActiveTime).ToLocalTime()).TotalMinutes))
    $AllSessions += $Session
    }
    $AllSessions
}

Function Disconnect-ViSession 
{
    <#
        .SYNOPSIS
            Disconnects a connected vCenter Session.

        .DESCRIPTION
            Disconnects a open connected vCenter Session.

        .PARAMETER  SessionList
            A session or a list of sessions to disconnect.

        .EXAMPLE
            PS C:\> Get-VISession | Where { $_.IdleMinutes -gt 5 } | Disconnect-ViSession

        .EXAMPLE
            PS C:\> Get-VISession | Where { $_.Username -eq "User19" } | Disconnect-ViSession
    #>
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$true)]
        $SessionList
    )
    Process 
    {
        $SessionMgr = Get-View $DefaultViserver.ExtensionData.Client.ServiceContent.SessionManager
        $SessionList | Foreach {
            Write "Disconnecting Session for $($_.Username) which has been active since $($_.LoginTime)"
            $SessionMgr.TerminateSession($_.Key)
        }
    }
}


Function Set-SIOC()
{
    Param(
        [Parameter(Mandatory=$True)]$dataStores,
        [Parameter(Mandatory=$False)][switch]$enabled=[switch]$False
    )
    $siocSpec = New-Object VMware.Vim.StorageIORMConfigSpec
    if($enabled.IsPresent)
    {
        $siocspec.Enabled = $True
    }
    else
    {
        $siocspec.Enabled = $False
    }

    $dataStores | ForEach-Object -Begin {$viewStorageRM = Get-View -Id "StorageResourceManager-StorageResourceManager"} {
        $viewStorageRM.ConfigureDatastoreIORM_Task($_.ExtensionData.MoRef, $siocSpec)
    }
}

function Get-vLicense{
<#
.SYNOPSIS
Function to show all licenses  in vCenter
  
.DESCRIPTION
Use this function to get all licenses in vcenter
  
.PARAMETER  xyz 
  
.NOTES
Author: Niklas Akerlund / RTS
Date: 2012-03-28
#>
    param (
        [Parameter(ValueFromPipeline=$True, HelpMessage="Enter the license key or object")]$LicenseKey = $null,
        [Switch]$showUnused,
        [Switch]$showEval
        )
    $servInst = Get-View ServiceInstance
    $licenceMgr = Get-View $servInst.Content.licenseManager
    if ($showUnused -and $showEval){
        $licenses = $licenceMgr.Licenses | where {$_.EditionKey -eq "eval" -or $_.Used -eq 0}
    }elseif($showUnused){
        $licenses = $licenceMgr.Licenses | where {$_.EditionKey -ne "eval" -and $_.Used -eq 0}
    }elseif($showEval){
        $licenses = $licenceMgr.Licenses | where {$_.EditionKey -eq "eval"}
    }elseif ($LicenseKey -ne $null) {
        if (($LicenseKey.GetType()).Name -eq "String"){
            $licenses = $licenceMgr.Licenses | where {$_.LicenseKey -eq $LicenseKey}
        }else {
            $licenses = $licenceMgr.Licenses | where {$_.LicenseKey -eq $LicenseKey.LicenseKey}
        }
    }
    else {
        $licenses = $licenceMgr.Licenses | where {$_.EditionKey -ne "eval"}
    }
     
    $licenses
}
 
function Add-vLicense
{
<#
.SYNOPSIS
Add New Licenses to the vCenter license manager
  
.DESCRIPTION
Use this function to add licenses  and assing to either the vcenter or the hosts
  
.PARAMETER  xyz 
    
.NOTES
Author: Niklas Akerlund / RTS
Date: 2012-03-28
#>
param (
    $VMHost ,
    [Parameter(ValueFromPipeline=$True)]$License = $null,
    [string]$LicenseKey = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
    [switch]$AddKey
    )
    $LicenseMgr = Get-View -Id 'LicenseManager-LicenseManager'
    $LicenseAssignMgr = Get-View -Id 'LicenseAssignmentManager-LicenseAssignmentManager'
    if($License)
    {
        $LicenseKey = $License.LicenseKey
        $LicenseType = $LicenseMgr.DecodeLicense($LicenseKey)
    }
    else
    {
        $LicenseType = $LicenseMgr.DecodeLicense($LicenseKey)
    }
     
    if ($LicenseType) 
    {
        if ($AddKey)
        {
            $LicenseMgr.AddLicense($LicenseKey, $null)
        }
        else
        {
            if ($LicenseType.EditionKey -eq "vc")
            {
                
#$servInst = Get-View ServiceInstance
                $Uuid = (Get-View ServiceInstance).Content.About.InstanceUuid
                $licenseAssignMgr.UpdateAssignedLicense($Uuid, $LicenseKey,$null)
            }
            else
            {
                $key = Get-vLicense -LicenseKey $LicenseKey
                if($key  -and ($key.Total-$key.Used) -lt (get-vmhost $VMHost | get-view).Hardware.CpuInfo.NumCpuPackages)
                {
                    Write-Host "Not Enough licenses left"
                } else
                {
                    $Uuid = (Get-VMhost $VMHost | Get-View).MoRef.Value
                    $licenseAssignMgr.UpdateAssignedLicense($Uuid, $LicenseKey,$null)
                }
            }  
        }
    }  
}
 
 
function Remove-vLicense
{
<#
.SYNOPSIS
Function to remove a licenses that is not in use in vCenter
  
.DESCRIPTION
Use this function to remove a license
  
.PARAMETER  xyz 
  
.NOTES
Author: Niklas Akerlund / RTS
Date: 2012-03-28
#>
param (
    [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$True, HelpMessage="Enter the key or keyobject to remove")]$License
    )
    $LicObj = Get-vLicense $License 
    if($LicObj.Used -eq 0)
    {
        $LicenseMgr = Get-View -Id 'LicenseManager-LicenseManager'
        $LicenseMgr.RemoveLicense($LicObj.LicenseKey)
    }
    else
    {
        Write-Host " The license is assigned and cannot be removed"
    }
}

Function Recurse-Children($folder, $hash)
{
    foreach($child in $folder.ChildEntity)
    {
        if($child.Type -eq "Folder")
        {
            # Get the child view
            $thisChildView = Get-View $child
        
            # Append the root path and add it to the hash
            $childRoot = $folderHash[$thisChildView.Parent.Value]
            $newRoot = "$childRoot/$($thisChildView.Name)"
            $newRoot
            $folderHash.Add($thisChildView.MoRef.Value,$newRoot)
            Recurse-Children($thisChildView,$hash)
        }
    }
}

Function Get-VMFolderStruct
{
    # We want a hashtable of folderId and fullPath
    # Set-Variable -Name folderHash -value @{} -Option AllScope
    $folderHash = @{}

    # Start with the 'vm' root
    $vmRoots = get-view -ViewType Folder -Filter @{"name" = "^vm$"}

    # Get all the datacenters
    $dcs = Get-View -ViewType Datacenter
    foreach($dc in $dcs)
    {
        $rootVmFolderView = Get-View -ViewType Folder -Filter @{"Parent" = "$($dc.MoRef.Value)"; "Name"="^vm$"}
        $path = "/$($dc.name)/$($rootVmFolderView.name)"
        $folderHash.Add($rootVmFolderView.MoRef.Value,$path)
        # for each subfolder in the VM root, call a recursive while loop to get the children
        Recurse-Children -folder $rootVmFolderView -hash $folderHash
    }
    # Put the folder hashtable out on the pipeline
    $folderHash
}

Export-ModuleMember -Function Connect-VI
Export-ModuleMember -Function Get-ViSession
Export-ModuleMember -Function Disconnect-ViSession
Export-ModuleMember -Function Set-SIOC
Export-ModuleMember -Function Remove-vLicense
Export-ModuleMember -Function Add-vLicense
Export-ModuleMember -Function Get-vLicense
Export-ModuleMember -Function Get-VMFolderStruct