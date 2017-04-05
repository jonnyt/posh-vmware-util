Function Connect-VI() {
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
        [Parameter(ValueFromPipeline = $true)]$vchosts,
        [Parameter(Mandatory = $False)][switch]$disconnectExisting = [switch]::$false,
        [Parameter(Mandatory = $False)]$credential
    )
    Write-Debug "Connecting to VIServers";
    #  Clear out any existing session
    if (($defaultVIServer -ne $null -or $defaultVIServers.length -gt 0) -and $disconnectExisting.IsPresent) {
        Write-Debug "Existing connections found ($defaultVIServers), disconnecting";
        Disconnect-VIServer * -Confirm:$false -ErrorAction SilentlyContinue
    }
		
    # Set some configuration defaults
    Try {
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -ErrorAction SilentlyContinue
        Set-PowerCLIConfiguration -DefaultVIServerMode Multiple -Confirm:$false -ErrorAction SilentlyContinue
    }
    Catch {
    }

    # Connect to the appropriate vCenter Servers
    if ($credential -eq $null) {
        Connect-VIServer $vchosts -ErrorAction:Stop | Out-Null
    }
    else {
        Connect-VIServer $vchosts -Credential $credential -ErrorAction:Stop | Out-Null
    }
    Write-Debug "Connected to VIServer $defaultVIServers";
}

Function Get-ViSession {
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
        }
        Else {
            $Session | Add-Member -MemberType NoteProperty -Name Status -Value "Idle"
        }
        $Session | Add-Member -MemberType NoteProperty -Name IdleMinutes -Value ([Math]::Round(((Get-Date) – ($_.LastActiveTime).ToLocalTime()).TotalMinutes))
        $AllSessions += $Session
    }
    $AllSessions
}

Function Disconnect-ViSession {
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
        [Parameter(ValueFromPipeline = $true)]
        $SessionList
    )
    Process {
        $SessionMgr = Get-View $DefaultViserver.ExtensionData.Client.ServiceContent.SessionManager
        $SessionList | Foreach {
            Write "Disconnecting Session for $($_.Username) which has been active since $($_.LoginTime)"
            $SessionMgr.TerminateSession($_.Key)
        }
    }
}

Function Set-SIOC() {
    Param(
        [Parameter(Mandatory = $True)]$dataStores,
        [Parameter(Mandatory = $False)][switch]$enabled = [switch]$False
    )
    $siocSpec = New-Object VMware.Vim.StorageIORMConfigSpec
    if ($enabled.IsPresent) {
        $siocspec.Enabled = $True
    }
    else {
        $siocspec.Enabled = $False
    }

    $dataStores | ForEach-Object -Begin {$viewStorageRM = Get-View -Id "StorageResourceManager-StorageResourceManager"} {
        $viewStorageRM.ConfigureDatastoreIORM_Task($_.ExtensionData.MoRef, $siocSpec)
    }
}

Function Get-vLicense {
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
        [Parameter(ValueFromPipeline = $True, HelpMessage = "Enter the license key or object")]$LicenseKey = $null,
        [Switch]$showUnused,
        [Switch]$showEval
    )
    $servInst = Get-View ServiceInstance
    $licenceMgr = Get-View $servInst.Content.licenseManager
    if ($showUnused -and $showEval) {
        $licenses = $licenceMgr.Licenses | where {$_.EditionKey -eq "eval" -or $_.Used -eq 0}
    }
    elseif ($showUnused) {
        $licenses = $licenceMgr.Licenses | where {$_.EditionKey -ne "eval" -and $_.Used -eq 0}
    }
    elseif ($showEval) {
        $licenses = $licenceMgr.Licenses | where {$_.EditionKey -eq "eval"}
    }
    elseif ($LicenseKey -ne $null) {
        if (($LicenseKey.GetType()).Name -eq "String") {
            $licenses = $licenceMgr.Licenses | where {$_.LicenseKey -eq $LicenseKey}
        }
        else {
            $licenses = $licenceMgr.Licenses | where {$_.LicenseKey -eq $LicenseKey.LicenseKey}
        }
    }
    else {
        $licenses = $licenceMgr.Licenses | where {$_.EditionKey -ne "eval"}
    }
     
    $licenses
}
 
Function Add-vLicense {
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
        [Parameter(ValueFromPipeline = $True)]$License = $null,
        [string]$LicenseKey = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
        [switch]$AddKey
    )
    $LicenseMgr = Get-View -Id 'LicenseManager-LicenseManager'
    $LicenseAssignMgr = Get-View -Id 'LicenseAssignmentManager-LicenseAssignmentManager'
    if ($License) {
        $LicenseKey = $License.LicenseKey
        $LicenseType = $LicenseMgr.DecodeLicense($LicenseKey)
    }
    else {
        $LicenseType = $LicenseMgr.DecodeLicense($LicenseKey)
    }
     
    if ($LicenseType) {
        if ($AddKey) {
            $LicenseMgr.AddLicense($LicenseKey, $null)
        }
        else {
            if ($LicenseType.EditionKey -eq "vc") {
                #$servInst = Get-View ServiceInstance
                $Uuid = (Get-View ServiceInstance).Content.About.InstanceUuid
                $licenseAssignMgr.UpdateAssignedLicense($Uuid, $LicenseKey, $null)
            }
            else {
                $key = Get-vLicense -LicenseKey $LicenseKey
                if ($key -and ($key.Total - $key.Used) -lt (get-vmhost $VMHost | get-view).Hardware.CpuInfo.NumCpuPackages) {
                    Write-Host "Not Enough licenses left"
                }
                else {
                    $Uuid = (Get-VMhost $VMHost | Get-View).MoRef.Value
                    $licenseAssignMgr.UpdateAssignedLicense($Uuid, $LicenseKey, $null)
                }
            }  
        }
    }  
}
 
Function Remove-vLicense {
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
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $True, HelpMessage = "Enter the key or keyobject to remove")]$License
    )
    $LicObj = Get-vLicense $License 
    if ($LicObj.Used -eq 0) {
        $LicenseMgr = Get-View -Id 'LicenseManager-LicenseManager'
        $LicenseMgr.RemoveLicense($LicObj.LicenseKey)
    }
    else {
        Write-Host " The license is assigned and cannot be removed"
    }
}

Function Recurse-Children($folder, $folderHash, $vCenterServer) {
    foreach ($child in $folder.ChildEntity) {
        if ($child.Type -eq "Folder") {
            # Get the child view
            $thisChildView = Get-View $child -Server $vCenterServer | Select-Object -First 1
        
            # Append the root path and add it to the hash
            $childRoot = $folderHash[$thisChildView.Parent.ToString()]
            if ($childRoot -eq $null) {
                $newRoot = "/$($thisChildView.Name)"
            }
            else {
                $newRoot = "$childRoot/$($thisChildView.Name)"
            }

            Write-Debug ("Adding $($thisChildView.MoRef.ToString()),$newRoot for server $vCenterServer")
            
            $folderHash.Add($thisChildView.MoRef.ToString(), $newRoot)
            Recurse-Children -folder $thisChildView -folderHash $folderHash -vCenterServer $vCenterServer
        }
    }
}

Function Get-VMFolderStruct {
    Param(
        [Parameter(ValueFromPipeline = $true)]$vCenterServer,
        [Parameter(ValueFromPipeline = $false)]$Datacenter
    )

    # We want a hashtable of folderId and fullPath
    # Set-Variable -Name folderHash -value @{} -Option AllScope
    $thisFolderHash = @{}

    # Start with the 'vm' root
    $vmRoots = get-view -ViewType Folder -Filter @{"name" = "^vm$"} -Server $vCenterServer

    # Get all the datacenters
    if ($PSBoundParameters['Datacenter'] -eq $null) {
        $dcs = Get-View -ViewType Datacenter -Server $vCenterServer
    }
    else {
        $dcs = Get-View -ViewType Datacenter -Server $vCenterServer -Filter @{"Name" = "$Datacenter"}
    }
    
    foreach ($dc in $dcs) {
        $rootVmFolderView = Get-View -ViewType Folder -Filter @{"Parent" = "$($dc.MoRef.Value)"; "Name" = "^vm$"} -Server $vCenterServer
        #$path = "/$($dc.name)/$($rootVmFolderView.name)"
        #$folderHash.Add($rootVmFolderView.MoRef.ToString(),$path)
        # for each subfolder in the VM root, call a recursive while loop to get the children
        Recurse-Children -folder $rootVmFolderView -folderHash $thisFolderHash -vCenterServer $vCenterServer
    }
    # Put the folder hashtable out on the pipeline
    $thisFolderHash
}

Function Get-FolderStruct {
    Param(
        [Parameter(ValueFromPipeline = $true)]$vCenterServer,
        [Parameter(ValueFromPipeline = $false)]$Datacenter,
        [Parameter(ValueFromPipeline = $false)][ValidateSet('vm', 'host', 'datastore', 'network')][String]$RootType
    )

    # We want a hashtable of folderId and fullPath
    # Set-Variable -Name folderHash -value @{} -Option AllScope
    $thisFolderHash = @{}

    # Start with the 'vm' root
    $vmRoots = get-view -ViewType Folder -Filter @{"name" = "^$RootType$"} -Server $vCenterServer

    # Get all the datacenters
    if ($PSBoundParameters['Datacenter'] -eq $null) {
        $dcs = Get-View -ViewType Datacenter -Server $vCenterServer
    }
    else {
        $dcs = Get-View -ViewType Datacenter -Server $vCenterServer -Filter @{"Name" = "$Datacenter"}
    }
    
    foreach ($dc in $dcs) {
        $rootVmFolderView = Get-View -ViewType Folder -Filter @{"Parent" = "$($dc.MoRef.Value)"; "Name" = "^$RootType$"} -Server $vCenterServer
        #$path = "/$($dc.name)/$($rootVmFolderView.name)"
        #$folderHash.Add($rootVmFolderView.MoRef.ToString(),$path)
        # for each subfolder in the VM root, call a recursive while loop to get the children
        Recurse-Children -folder $rootVmFolderView -folderHash $thisFolderHash -vCenterServer $vCenterServer
    }
    # Put the folder hashtable out on the pipeline
    $thisFolderHash
}

Function Detach-DatastoreFromHost {
    [cmdletbinding(SupportsShouldProcess = $True)]
    Param
    (
        [Parameter(ValueFromPipeline = $true)]$Datastore,
        $vmHost

    )
    Process {
        $hostview = Get-View $VMHost.Key
        $StorageSys = Get-View $HostView.ConfigManager.StorageSystem
        $devices = $StorageSys.StorageDeviceInfo.ScsiLun
        Foreach ($device in $devices) {
            if ($device.canonicalName -eq $hostviewDSDiskName) {
                $LunUUID = $Device.Uuid
                Write-Host "Detaching LUN $($Device.CanonicalName) from host $($hostview.Name)..."
                $StorageSys.DetachScsiLun($LunUUID);
            }
        }
    }
}

Function Detach-Datastore {
    <#
.SYNOPSIS
Detach a datastore LUN device.  If no host supplied will detach from all connected hosts.
  
.DESCRIPTION
Detach a datastore LUN device.  If no host supplied will detach from all connected hosts.
  
.PARAMETER  Datastore
.PARAMETER  VMHost
  
.NOTES
Author: Jonathon Taylor
#>
    [CmdletBinding()]
    Param
    (
        [Parameter(ValueFromPipeline = $true)]$Datastore,
        $vmHost
    )
    Process {
        if (-not $Datastore) {
            Write-Host "No Datastore defined as input"
            Exit
        }
        Foreach ($ds in $Datastore) {
            $hostviewDSDiskName = $ds.ExtensionData.Info.vmfs.extent[0].Diskname
            if ($ds.ExtensionData.Host) {
                if ($vmHost) {
                    Foreach ($thisVMHost in $vmHost) {
                        $vmHostRef = $ds.ExtensionData.Host | Where-Object {$_.Key.Value -eq $thisVMHost.ExtensionData.MoRef.value}
                        Detach-DatastoreFromHost -Datastore $ds -vmHost $vmHostRef
                    }
                }
                else {
                    $attachedHosts = $ds.ExtensionData.Host
                    Foreach ($vmHostRef in $attachedHosts) {
                        Detach-DatastoreFromHost -Datastore $ds -vmHost $vmHostRef
                    }

                }
            }        
        }
    }
}

Function Unmount-DatastoreFromHost {
    [CmdletBinding()]
    Param 
    (
        [Parameter(ValueFromPipeline = $true)]
        $Datastore,
        $VMHost
    )
    Process {
        $hostview = Get-View $VMHost.Key
        $StorageSys = Get-View $HostView.ConfigManager.StorageSystem
        Write-Host "Unmounting VMFS Datastore $($Datastore.Name) from host $($hostview.Name)..."
        $StorageSys.UnmountVmfsVolume($Datastore.ExtensionData.Info.vmfs.uuid);
    }
}

Function Unmount-Datastore {
    <#
.SYNOPSIS
Unmounts a datastore.  If no host supplied will unmount from all connected hosts.
  
.DESCRIPTION
Unmounts a datastore.  If no host supplied will unmount from all connected hosts.
  
.PARAMETER  Datastore
.PARAMETER  VMHost
  
.NOTES
Author: Jonathon Taylor
#>
    [CmdletBinding()]
    Param 
    (
        [Parameter(ValueFromPipeline = $true)]
        $Datastore,
        $VMHost
    )
    Process {
        if (-not $Datastore) {
            Write-Host "No Datastore defined as input"
            Exit
        }
        Foreach ($ds in $Datastore) {
            $hostviewDSDiskName = $ds.ExtensionData.Info.vmfs.extent[0].Diskname
            if ($ds.ExtensionData.Host) {
                if ($VMHost) {
                    Foreach ($thisVMHost in $VMHost) {
                        $vmHostRef = $ds.ExtensionData.Host | Where-Object {$_.Key.Value -eq $thisVMHost.ExtensionData.MoRef.value}
                        Unmount-DatastoreFromHost -Datastore $ds -vmHost $vmHostRef
                    }
                }
                else {
                    $attachedHosts = $ds.ExtensionData.Host
                    Foreach ($vmHostRef in $attachedHosts) {
                        Unmount-DatastoreFromHost -Datastore $ds -vmHost $vmHostRef
                    }
                }
            }
        }
    }
}

Function Get-DatastoreMountInfo {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline = $true)]
        $Datastore
    )
    Process {
        $AllInfo = @()
        if (-not $Datastore) {
            $Datastore = Get-Datastore
        }
        Foreach ($ds in $Datastore) {  
            if ($ds.ExtensionData.info.Vmfs) {
                $hostviewDSDiskName = $ds.ExtensionData.Info.vmfs.extent[0].diskname
                if ($ds.ExtensionData.Host) {
                    $attachedHosts = $ds.ExtensionData.Host
                    Foreach ($VMHost in $attachedHosts) {
                        $hostview = Get-View $VMHost.Key
                        $hostviewDSState = $VMHost.MountInfo.Mounted
                        $StorageSys = Get-View $HostView.ConfigManager.StorageSystem
                        $devices = $StorageSys.StorageDeviceInfo.ScsiLun
                        Foreach ($device in $devices) {
                            $Info = "" | Select Datastore, VMHost, Lun, Mounted, State
                            if ($device.canonicalName -eq $hostviewDSDiskName) {
                                $hostviewDSAttachState = ""
                                if ($device.operationalState[0] -eq "ok") {
                                    $hostviewDSAttachState = "Attached"							
                                }
                                elseif ($device.operationalState[0] -eq "off") {
                                    $hostviewDSAttachState = "Detached"							
                                }
                                else {
                                    $hostviewDSAttachState = $device.operationalstate[0]
                                }
                                $Info.Datastore = $ds.Name
                                $Info.Lun = $hostviewDSDiskName
                                $Info.VMHost = $hostview.Name
                                $Info.Mounted = $HostViewDSState
                                $Info.State = $hostviewDSAttachState
                                $AllInfo += $Info
                            }
                        }
						
                    }
                }
            }
        }
        $AllInfo
    }
}

Function Mount-Datastore {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline = $true)]
        $Datastore
    )
    Process {
        if (-not $Datastore) {
            Write-Host "No Datastore defined as input"
            Exit
        }
        Foreach ($ds in $Datastore) {
            $hostviewDSDiskName = $ds.ExtensionData.Info.vmfs.extent[0].Diskname
            if ($ds.ExtensionData.Host) {
                $attachedHosts = $ds.ExtensionData.Host
                Foreach ($VMHost in $attachedHosts) {
                    $hostview = Get-View $VMHost.Key
                    $StorageSys = Get-View $HostView.ConfigManager.StorageSystem
                    Write-Host "Mounting VMFS Datastore $($DS.Name) on host $($hostview.Name)..."
                    $StorageSys.MountVmfsVolume($DS.ExtensionData.Info.vmfs.uuid);
                }
            }
        }
    }
}

Function Attach-Datastore {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline = $true)]
        $Datastore
    )
    Process {
        if (-not $Datastore) {
            Write-Host "No Datastore defined as input"
            Exit
        }
        Foreach ($ds in $Datastore) {
            $hostviewDSDiskName = $ds.ExtensionData.Info.vmfs.extent[0].Diskname
            if ($ds.ExtensionData.Host) {
                $attachedHosts = $ds.ExtensionData.Host
                Foreach ($VMHost in $attachedHosts) {
                    $hostview = Get-View $VMHost.Key
                    $StorageSys = Get-View $HostView.ConfigManager.StorageSystem
                    $devices = $StorageSys.StorageDeviceInfo.ScsiLun
                    Foreach ($device in $devices) {
                        if ($device.canonicalName -eq $hostviewDSDiskName) {
                            $LunUUID = $Device.Uuid
                            Write-Host "Attaching LUN $($Device.CanonicalName) to host $($hostview.Name)..."
                            $StorageSys.AttachScsiLun($LunUUID);
                        }
                    }
                }
            }
        }
    }
}

Function Get-DatastoreFromExtent {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline = $true)]
        $ExtentRegEx
    )
    Process {
        $viewMatches = @()
        $dsViews = Get-View -ViewType DataStore
        foreach ($dsView in $dsViews) {
            $extents = $dsView.Info.Vmfs.Extent
            foreach ($extent in $extents) {
                if ($extent.DiskName -match $ExtentRegEx) {
                    $viewMatches += , $dsView
                }
            }
        }
        $viewMatches
    }
}

Function Get-HostSatpPSPDefault {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline = $true)]$vmHost,
        [Parameter(Mandatory = $true)][ValidateSet("VMW_SATP_DEFAULT_AA", "VMW_SATP_DEFAULT_AP", "VMW_SATP_ALUA")][string]$satp
    )
    Process {
        $esxcli = Get-EsxCli -VMHost (Get-VMHost -id $vmHost.MoRef)
        $currentPolicy = $esxcli.storage.nmp.satp.list() | Where-Object {$_.Name -eq $satp}
        $currentPolicy.DefaultPSP
    }
}

Function Set-HostSatpPSPDefault {
    [cmdletbinding(SupportsShouldProcess = $True)]
    Param (
        [Parameter(ValueFromPipeline = $true)]$vmHost,
        [Parameter(Mandatory = $true)][ValidateSet("VMW_PSP_MRU", "VMW_PSP_FIXED", "VMW_PSP_RR")][string]$defaultPSP,
        [Parameter(Mandatory = $true)][ValidateSet("VMW_SATP_DEFAULT_AA", "VMW_SATP_DEFAULT_AP", "VMW_SATP_ALUA")][string]$satp
    )
    Process {
        $esxcli = Get-EsxCli -VMHost (Get-VMHost -id $vmHost.MoRef)
        if (!$WhatIfPreference) {
            $esxcli.storage.nmp.satp.set($false, $defaultPSP, $satp)
        }
        else {
            Write-Host "What if:  Performing the operation `"`$esxcli.storage.nmp.satp.set(`$false,$defaultPSP,$satp) on $($vmHost.Name)`"" 
        }
    }
}

Function Set-LunPSP {
    [CmdletBinding(SupportsShouldProcess = $True)]
    Param (
        [Parameter(ValueFromPipeline = $true)]$vmHost,
        [Parameter(Mandatory = $true)][ValidateSet("VMW_PSP_MRU", "VMW_PSP_FIXED", "VMW_PSP_RR")][string]$psp,
        [Parameter(Mandatory = $true)][string]$lunCN
    )
    Process {
        $esxcli = Get-EsxCli -VMHost (Get-VMHost -id $vmHost.MoRef)
        if (!$WhatIfPreference) {
            $esxcli.storage.nmp.device.set($false, $lunCN, $psp)
        }
        else {
            Write-Host "What if:  Performing the operation `"`$esxcli.storage.nmp.device.set(`$false,$lunCN,$psp) on $($vmHost.Name)`"" 
        }
    }
}

Function Set-HAAdmissionControlPolicy {
    <#
.SYNOPSIS
Set the HA admission control policy and related parameters.

#>
    [CmdletBinding(DefaultParameterSetName = "PercentageBased", SupportsShouldProcess = $True)]
    param(
        [Parameter(ParameterSetName = "PercentageBased", Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [Parameter(ParameterSetName = "SlotsBased", Position = 0, Mandatory = $true, ValueFromPipeline = $true)][VMware.VimAutomation.ViCore.Impl.V1.Inventory.ComputeResourceImpl]$cluster,
        [Parameter(ParameterSetName = "PercentageBased", Mandatory = $false)][int]$percentCPU = 25,
        [Parameter(ParameterSetName = "PercentageBased", Mandatory = $false)][int]$percentMem = 25,
        [Parameter(ParameterSetName = "SlotsBased", Mandatory = $false)][int]$hostFailuresToTolerate = 1
    )

    $cluSpec = New-Object VMware.Vim.ClusterConfigSpecEx
    $cluSpec.DasConfig = New-Object VMware.Vim.ClusterDasConfigInfo
    $cluSpec.DasConfig.AdmissionControlPolicy = New-Object VMware.Vim.ClusterFailoverResourcesAdmissionControlPolicy
    $cluSpec.Dasconfig.AdmissionControlEnabled = $true
    
    switch ($PSCmdlet.ParameterSetName) {
        "PercentageBased" {
            $cluSpec.DasConfig.AdmissionControlPolicy.CpuFailoverResourcesPercent = $percentCPU
            $cluSpec.DasConfig.AdmissionControlPolicy.MemoryFailoverResourcesPercent = $percentMem
        }
        "SlotsBased" {
            Throw Exception "Not Implemented"
        }
    }

    $clusterView = Get-View $cluster
    if (!$WhatIfPreference) {
        $clusterView.ReconfigureComputeResource($cluSpec, $true)
    }
    else {
        Write-Host "What if:  Performing the operation `"`ReconfigureComputeResource($cluSpec,$true) on $($cluster.Name)`"" 
    }
}

Function Get-SerialPort { 
    Param ( 
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelinebyPropertyName = $True)] 
        $VM 
    ) 
    Process { 
        Foreach ($VMachine in $VM) { 
            Foreach ($Device in $VMachine.ExtensionData.Config.Hardware.Device) { 
                If ($Device.gettype().Name -eq "VirtualSerialPort") { 
                    $Details = New-Object PsObject 
                    $Details | Add-Member Noteproperty VM -Value $VMachine 
                    $Details | Add-Member Noteproperty Name -Value $Device.DeviceInfo.Label 
                    If ($Device.Backing.FileName) { $Details | Add-Member Noteproperty Filename -Value $Device.Backing.FileName } 
                    If ($Device.Backing.Datastore) { $Details | Add-Member Noteproperty Datastore -Value $Device.Backing.Datastore } 
                    If ($Device.Backing.DeviceName) { $Details | Add-Member Noteproperty DeviceName -Value $Device.Backing.DeviceName } 
                    $Details | Add-Member Noteproperty Connected -Value $Device.Connectable.Connected 
                    $Details | Add-Member Noteproperty StartConnected -Value $Device.Connectable.StartConnected 
                    $Details 
                } 
            } 
        } 
    } 
}

Function Remove-SerialPort { 
    Param ( 
        [Parameter(Mandatory = $True, ValueFromPipelinebyPropertyName = $True)] 
        $VM, 
        [Parameter(Mandatory = $True, ValueFromPipelinebyPropertyName = $True)] 
        $Name 
    ) 
    Process { 
        $VMSpec = New-Object VMware.Vim.VirtualMachineConfigSpec 
        $VMSpec.deviceChange = New-Object VMware.Vim.VirtualDeviceConfigSpec 
        $VMSpec.deviceChange[0] = New-Object VMware.Vim.VirtualDeviceConfigSpec 
        $VMSpec.deviceChange[0].operation = "remove" 
        $Device = $VM.ExtensionData.Config.Hardware.Device | Foreach-Object { 
            $_ | Where-Object {$_.gettype().Name -eq "VirtualSerialPort"} | Where-Object { $_.DeviceInfo.Label -eq $Name } 
        } 
        $VMSpec.deviceChange[0].device = $Device 
        $VM.ExtensionData.ReconfigVM_Task($VMSpec) 
    } 
}

Function Get-USBPort { 
    Param ( 
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelinebyPropertyName = $True)] 
        $VM 
    ) 
    Process { 
        Foreach ($VMachine in $VM) { 
            Foreach ($Device in $VMachine.ExtensionData.Config.Hardware.Device) { 
                If ($Device.gettype().Name -eq "VirtualUSB") { 
                    $Details = New-Object PsObject 
                    $Details | Add-Member Noteproperty VM -Value $VMachine 
                    $Details | Add-Member Noteproperty Name -Value $Device.DeviceInfo.Label 
                    If ($Device.Backing.FileName) { $Details | Add-Member Noteproperty Filename -Value $Device.Backing.FileName } 
                    If ($Device.Backing.Datastore) { $Details | Add-Member Noteproperty Datastore -Value $Device.Backing.Datastore } 
                    If ($Device.Backing.DeviceName) { $Details | Add-Member Noteproperty DeviceName -Value $Device.Backing.DeviceName } 
                    $Details | Add-Member Noteproperty Connected -Value $Device.Connectable.Connected 
                    $Details | Add-Member Noteproperty StartConnected -Value $Device.Connectable.StartConnected 
                    $Details 
                } 
            } 
        } 
    } 
}

Function Remove-ParallelPort { 
    Param ( 
        [Parameter(Mandatory = $True, ValueFromPipelinebyPropertyName = $True)] 
        $VM, 
        [Parameter(Mandatory = $True, ValueFromPipelinebyPropertyName = $True)] 
        $Name 
    ) 
    Process { 
        $VMSpec = New-Object VMware.Vim.VirtualMachineConfigSpec 
        $VMSpec.deviceChange = New-Object VMware.Vim.VirtualDeviceConfigSpec 
        $VMSpec.deviceChange[0] = New-Object VMware.Vim.VirtualDeviceConfigSpec 
        $VMSpec.deviceChange[0].operation = "remove" 
        $Device = $VM.ExtensionData.Config.Hardware.Device | Foreach-Object { 
            $_ | Where-Object {$_.gettype().Name -eq "VirtualParallelPort"} | Where-Object { $_.DeviceInfo.Label -eq $Name } 
        } 
        $VMSpec.deviceChange[0].device = $Device 
        $VM.ExtensionData.ReconfigVM_Task($VMSpec) 
    } 
}

Function Get-ParallelPort { 
    Param ( 
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelinebyPropertyName = $True)] 
        $VM 
    ) 
    Process { 
        Foreach ($VMachine in $VM) { 
            Foreach ($Device in $VMachine.ExtensionData.Config.Hardware.Device) { 
                If ($Device.gettype().Name -eq "VirtualParallelPort") { 
                    $Details = New-Object PsObject 
                    $Details | Add-Member Noteproperty VM -Value $VMachine 
                    $Details | Add-Member Noteproperty Name -Value $Device.DeviceInfo.Label 
                    If ($Device.Backing.FileName) { $Details | Add-Member Noteproperty Filename -Value $Device.Backing.FileName } 
                    If ($Device.Backing.Datastore) { $Details | Add-Member Noteproperty Datastore -Value $Device.Backing.Datastore } 
                    If ($Device.Backing.DeviceName) { $Details | Add-Member Noteproperty DeviceName -Value $Device.Backing.DeviceName } 
                    $Details | Add-Member Noteproperty Connected -Value $Device.Connectable.Connected 
                    $Details | Add-Member Noteproperty StartConnected -Value $Device.Connectable.StartConnected 
                    $Details 
                } 
            } 
        } 
    } 
}

Function Remove-ParallelPort { 
    Param ( 
        [Parameter(Mandatory = $True, ValueFromPipelinebyPropertyName = $True)] 
        $VM, 
        [Parameter(Mandatory = $True, ValueFromPipelinebyPropertyName = $True)] 
        $Name 
    ) 
    Process { 
        $VMSpec = New-Object VMware.Vim.VirtualMachineConfigSpec 
        $VMSpec.deviceChange = New-Object VMware.Vim.VirtualDeviceConfigSpec 
        $VMSpec.deviceChange[0] = New-Object VMware.Vim.VirtualDeviceConfigSpec 
        $VMSpec.deviceChange[0].operation = "remove" 
        $Device = $VM.ExtensionData.Config.Hardware.Device | Foreach { 
            $_ | Where {$_.gettype().Name -eq "VirtualParallelPort"} | Where { $_.DeviceInfo.Label -eq $Name } 
        } 
        $VMSpec.deviceChange[0].device = $Device 
        $VM.ExtensionData.ReconfigVM_Task($VMSpec) 
    } 
}

Function Test-VMKPing {
    Param(
        [Parameter (Mandatory = $true)]$vmHost,
        [Parameter (Mandatory = $true)]$sshKeyPath,
        [Parameter (Mandatory = $true)]$pingAddress,
        [Parameter (Mandatory = $false)]$count = 3
    )

    $ErrorActionPreference = 'stop'
    $InformationPreference = 'continue'
    $WarningPreference = 'continue'

    $userName = "root"
    $sshKeyCred = New-Object -TypeName System.Management.Automation.PSCredential -argumentList $userName, (New-Object System.Security.SecureString)

    Import-Module posh-ssh

    foreach ($thisVMHost in $vmHost) {
        Write-Verbose "Attempting to test $($thisVMHost.Name)"
    
        # Enable ssh
        $thisVMHost | Get-VMHostService | ? {$_.label -eq 'SSH'} | Start-VMHostService | Out-Null

        # Get a session
        $sshSession = New-SshSession -ComputerName $($thisVMHost.Name) -KeyFile $sshKeyPath -Credential $sshKeyCred
        $res = Invoke-SSHCommand -SSHSession $sshSession -Command "vmkping -c $count $pingAddress"

        # Stop SSH
        $thisVMHost | Get-VMHostService | ? {$_.label -eq 'SSH'} | Stop-VMHostService -Confirm:$false | Out-Null

        $res.Output

    }
}

Export-ModuleMember -Function *