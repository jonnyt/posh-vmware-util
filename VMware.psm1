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

Export-ModuleMember -Function Connect-VI
Export-ModuleMember -Function Get-ViSession
Export-ModuleMember -Function Disconnect-ViSession
Export-ModuleMember -Function Set-SIOC