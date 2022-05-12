function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $True)]
        [System.String]
        $Identity,

        [Parameter()]
        [System.String]
        $DisplayName,

        [Parameter()]
        [System.String]
        $Description,

        [Parameter()]
        [System.Boolean]
        $EncryptDevice=$false,

        [Parameter()]
        [System.Boolean]
        $AllowStandardUserEncryption=$false,

        [Parameter()]
        [System.Boolean]
        $EnableStorageCardEncryptionOnMobile=$false,

        [Parameter()]
        [System.Boolean]
        $DisableWarningForOtherDiskEncryption=$false,

        [Parameter()]
        [System.String]
        [ValidateSet("notConfigured","disabled","enabledForAzureAd","enabledForAzureAdAndHybrid")]
        $RecoveryPasswordRotation="notConfigured",

        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $FixedDrivePolicy,

        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $RemovableDrivePolicy,

        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $SystemDrivePolicy,

        [Parameter(Mandatory = $True)]
        [System.String]
        [ValidateSet('Absent', 'Present')]
        $Ensure,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter()]
        [System.String]
        $ApplicationId,

        [Parameter()]
        [System.String]
        $TenantId,

        [Parameter()]
        [System.String]
        $ApplicationSecret,

        [Parameter()]
        [System.String]
        $CertificateThumbprint
    )

    Write-Verbose -Message "Checking for the Intune Endpoint Protection Bitlocker Policy {$DisplayName}"

    $connectionMode = New-M365DSCConnection -Workload 'MicrosoftGraph' `
                            -InboundParameters $PSBoundParameters `
                            -ProfileName 'beta' `
                            -ErrorAction Stop
    $context=Get-MgContext
    if($null -eq $context)
    {
        New-M365DSCConnection -Workload 'MicrosoftGraph' `
            -InboundParameters $PSBoundParameters -ErrorAction Stop
    }
    Select-MgProfile -Name 'beta'
    #Ensure the proper dependencies are installed in the current environment.
    Confirm-M365DSCDependencies

    #region Telemetry
    $ResourceName = $MyInvocation.MyCommand.ModuleName -replace "MSFT_", ""
    $CommandName  = $MyInvocation.MyCommand
    $data = Format-M365DSCTelemetryParameters -ResourceName $ResourceName `
        -CommandName $CommandName `
        -Parameters $PSBoundParameters
    Add-M365DSCTelemetryEvent -Data $data
    #endregion

    $nullResult = $PSBoundParameters
    $nullResult.Ensure = 'Absent'

    try
    {
        #Retrieve policy general settings
        $policy = Get-MgDeviceManagementIntent -DeviceManagementIntentId $Identity `
                        -ErrorAction Stop
    }
    catch
    {
        if ($null -eq $policy)
        {
            Write-Verbose -Message "No Endpoint Protection Bitlocker Policy {$Identity} was found"
            return $nullResult
        }
    }

    try
    {
        Write-Verbose -Message "Found Endpoint Protection Bitlocker Policy {$($policy.DisplayName)}"
        #Retrieve policy specific settings
        [array]$settings = Get-MgDeviceManagementIntentSetting -DeviceManagementIntentId $Identity `
                    -ErrorAction Stop

        $settingEncryptDevice= ($settings|Where-Object `
            -FilterScript {$_.DefinitionId -like "*EncryptDevice"}).ValueJson|ConvertFrom-Json

        $settingAllowStandardUserEncryption= ($settings|Where-Object `
            -FilterScript {$_.DefinitionId -like "*AllowStandardUserEncryption"}).ValueJson|ConvertFrom-Json

        $settingEnableStorageCardEncryptionOnMobile= ($settings|Where-Object `
            -FilterScript {$_.DefinitionId -like "*EnableStorageCardEncryptionOnMobile"}).ValueJson|ConvertFrom-Json

        $settingDisableWarningForOtherDiskEncryption= ($settings|Where-Object `
            -FilterScript {$_.DefinitionId -like "*DisableWarningForOtherDiskEncryption"}).ValueJson|ConvertFrom-Json

        $settingRecoveryPasswordRotation=($settings|Where-Object `
            -FilterScript {$_.DefinitionId -like "*RecoveryPasswordRotation"}).ValueJson|ConvertFrom-Json

        $settingFixedDrivePolicy=($settings|Where-Object `
            -FilterScript {$_.DefinitionId -like "*FixedDrivePolicy"}).ValueJson|ConvertFrom-Json

        $settingRemovableDrivePolicy=($settings|Where-Object `
            -FilterScript {$_.DefinitionId -like "*RemovableDrivePolicy"}).ValueJson|ConvertFrom-Json

        $settingSystemDrivePolicy=($settings|Where-Object `
            -FilterScript {$_.DefinitionId -like "*SystemDrivePolicy"}).ValueJson|ConvertFrom-Json

        return @{
            Identity                                                = $Identity
            Description                                             = $policy.Description
            DisplayName                                             = $policy.DisplayName
            EncryptDevice                                           = $settingEncryptDevice
            AllowStandardUserEncryption                             = $settingAllowStandardUserEncryption
            EnableStorageCardEncryptionOnMobile                     = $settingEnableStorageCardEncryptionOnMobile
            DisableWarningForOtherDiskEncryption                    = $settingDisableWarningForOtherDiskEncryption
            RecoveryPasswordRotation                                = $settingRecoveryPasswordRotation
            FixedDrivePolicy                                        = $settingFixedDrivePolicy
            RemovableDrivePolicy                                    = $settingRemovableDrivePolicy
            SystemDrivePolicy                                       = $settingSystemDrivePolicy
            Ensure                                                  = "Present"
            Credential                                              = $Credential
            ApplicationId                                           = $ApplicationId
            TenantId                                                = $TenantId
            ApplicationSecret                                       = $ApplicationSecret
            CertificateThumbprint                                   = $CertificateThumbprint
        }

    }
    catch
    {
        try
        {
            Write-Verbose -Message $_
            $tenantIdValue = ""
            $tenantIdValue = $Credential.UserName.Split('@')[1]
            Add-M365DSCEvent -Message $_ -EntryType 'Error' `
                -EventID 1 -Source $($MyInvocation.MyCommand.Source) `
                -TenantId $tenantIdValue
        }
        catch
        {
            Write-Verbose -Message $_
        }
        return $nullResult
    }
}

function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $True)]
        [System.String]
        $Identity,

        [Parameter()]
        [System.String]
        $DisplayName,

        [Parameter()]
        [System.String]
        $Description,

        [Parameter()]
        [System.Boolean]
        $EncryptDevice=$false,

        [Parameter()]
        [System.Boolean]
        $AllowStandardUserEncryption=$false,

        [Parameter()]
        [System.Boolean]
        $EnableStorageCardEncryptionOnMobile=$false,

        [Parameter()]
        [System.Boolean]
        $DisableWarningForOtherDiskEncryption=$false,

        [Parameter()]
        [System.String]
        [ValidateSet("notConfigured","disabled","enabledForAzureAd","enabledForAzureAdAndHybrid")]
        $RecoveryPasswordRotation="notConfigured",

        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $FixedDrivePolicy,

        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $RemovableDrivePolicy,

        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $SystemDrivePolicy,

        [Parameter(Mandatory = $True)]
        [System.String]
        [ValidateSet('Absent', 'Present')]
        $Ensure,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter()]
        [System.String]
        $ApplicationId,

        [Parameter()]
        [System.String]
        $TenantId,

        [Parameter()]
        [System.String]
        $ApplicationSecret,

        [Parameter()]
        [System.String]
        $CertificateThumbprint
    )

    $ConnectionMode = New-M365DSCConnection -Workload 'MicrosoftGraph' `
        -InboundParameters $PSBoundParameters `
        -ProfileName 'beta'

    Select-MgProfile -Name 'beta'
    #Ensure the proper dependencies are installed in the current environment.
    Confirm-M365DSCDependencies

    #region Telemetry
    $ResourceName = $MyInvocation.MyCommand.ModuleName -replace "MSFT_", ""
    $CommandName  = $MyInvocation.MyCommand
    $data = Format-M365DSCTelemetryParameters -ResourceName $ResourceName `
        -CommandName $CommandName `
        -Parameters $PSBoundParameters
    Add-M365DSCTelemetryEvent -Data $data
    #endregion

    $currentPolicy = Get-TargetResource @PSBoundParameters
    $PSBoundParameters.Remove("Ensure") | Out-Null
    $PSBoundParameters.Remove("Credential") | Out-Null
    $PSBoundParameters.Remove("ApplicationId") | Out-Null
    $PSBoundParameters.Remove("TenantId") | Out-Null
    $PSBoundParameters.Remove("ApplicationSecret") | Out-Null
    $PSBoundParameters.Remove("CertificateThumbprint") | Out-Null

    $policyTemplateID='d1174162-1dd2-4976-affc-6667049ab0ae'
    if ($Ensure -eq 'Present' -and $currentPolicy.Ensure -eq 'Absent')
    {
        Write-Verbose -Message "Creating new Endpoint Protection Bitlocker Policy {$DisplayName}"
        $PSBoundParameters.Remove('Identity') | Out-Null
        $PSBoundParameters.Remove('Description') | Out-Null
        $PSBoundParameters.Remove('DisplayName') | Out-Null

        $PSBoundParameters.FixedDrivePolicy= Convert-M365DSCComplexParamToHashtable `
            -DSCComplexParams $PSBoundParameters.FixedDrivePolicy

        $PSBoundParameters.RemovableDrivePolicy= Convert-M365DSCComplexParamToHashtable `
            -DSCComplexParams $PSBoundParameters.RemovableDrivePolicy

        $PSBoundParameters.SystemDrivePolicy= Convert-M365DSCComplexParamToHashtable `
            -DSCComplexParams $PSBoundParameters.SystemDrivePolicy

        $settings = Get-M365DSCIntuneDeviceConfigurationSettings `
            -Properties ([System.Collections.Hashtable]$PSBoundParameters) `
            -DefinitionIdPrefix "windows10EndpointProtectionConfiguration_bitlocker"

        New-MgDeviceManagementIntent -DisplayName $DisplayName `
            -Description $Description `
            -TemplateId $policyTemplateID `
            -Settings $settings

        Write-Verbose -Message "Endpoint Protection Bitlocker Policy {$DisplayName} created successfully."
    }
    elseif ($Ensure -eq 'Present' -and $currentPolicy.Ensure -eq 'Present')
    {
        Write-Verbose -Message "Updating existing Endpoint Protection Bitlocker Policy {$DisplayName}"

        $PSBoundParameters.Remove('Identity') | Out-Null
        $PSBoundParameters.Remove('DisplayName') | Out-Null
        $PSBoundParameters.Remove('Description') | Out-Null

        $PSBoundParameters.FixedDrivePolicy=Convert-M365DSCComplexParamToHashtable `
            -DSCComplexParams $PSBoundParameters.FixedDrivePolicy

        $PSBoundParameters.RemovableDrivePolicy=Convert-M365DSCComplexParamToHashtable `
            -DSCComplexParams $PSBoundParameters.RemovableDrivePolicy

        $PSBoundParameters.SystemDrivePolicy=Convert-M365DSCComplexParamToHashtable `
            -DSCComplexParams $PSBoundParameters.SystemDrivePolicy

        $settings = Get-M365DSCIntuneDeviceConfigurationSettings `
            -Properties ([System.Collections.Hashtable]$PSBoundParameters) `
            -DefinitionIdPrefix "windows10EndpointProtectionConfiguration_bitlocker"

        Update-MgDeviceManagementIntent -ErrorAction Stop `
            -Description $Description `
            -DisplayName $DisplayName `
            -DeviceManagementIntentId $Identity

        $currentSettings=Get-MgDeviceManagementIntentSetting -DeviceManagementIntentId $Identity `
            -ErrorAction Stop

        foreach($setting in $settings)
        {
            $mySetting=$currentSettings|Where-Object{$_.DefinitionId -eq $setting.DefinitionId}
            $setting.add("id",$mySetting.Id)
        }
        $Uri="https://graph.microsoft.com/beta/deviceManagement/intents/$Identity/updateSettings"
        $body=@{"settings"=$settings}
        Invoke-MgGraphRequest -Method POST -Uri $Uri -Body ($body|ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop

        Write-Verbose -Message "Endpoint Protection Bitlocker Policy {$DisplayName} updated successfully."
    }
    elseif ($Ensure -eq 'Absent' -and $currentPolicy.Ensure -eq 'Present')
    {
        Write-Verbose -Message "Removing Endpoint Protection Bitlocker Policy {$DisplayName}"
        Remove-MgDeviceManagementIntent -DeviceManagementIntentId $Identity -ErrorAction Stop
        Write-Verbose -Message "Endpoint Protection Bitlocker Policy {$DisplayName} removed successfully."
    }
}

function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $True)]
        [System.String]
        $Identity,

        [Parameter()]
        [System.String]
        $DisplayName,

        [Parameter()]
        [System.String]
        $Description,

        [Parameter()]
        [System.Boolean]
        $EncryptDevice=$false,

        [Parameter()]
        [System.Boolean]
        $AllowStandardUserEncryption=$false,

        [Parameter()]
        [System.Boolean]
        $EnableStorageCardEncryptionOnMobile=$false,

        [Parameter()]
        [System.Boolean]
        $DisableWarningForOtherDiskEncryption=$false,

        [Parameter()]
        [System.String]
        [ValidateSet("notConfigured","disabled","enabledForAzureAd","enabledForAzureAdAndHybrid")]
        $RecoveryPasswordRotation="notConfigured",

        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $FixedDrivePolicy,

        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $RemovableDrivePolicy,

        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $SystemDrivePolicy,

        [Parameter(Mandatory = $True)]
        [System.String]
        [ValidateSet('Absent', 'Present')]
        $Ensure,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter()]
        [System.String]
        $ApplicationId,

        [Parameter()]
        [System.String]
        $TenantId,

        [Parameter()]
        [System.String]
        $ApplicationSecret,

        [Parameter()]
        [System.String]
        $CertificateThumbprint
    )
    #Ensure the proper dependencies are installed in the current environment.
    Confirm-M365DSCDependencies

    #region Telemetry
    $ResourceName = $MyInvocation.MyCommand.ModuleName -replace "MSFT_", ""
    $CommandName  = $MyInvocation.MyCommand
    $data = Format-M365DSCTelemetryParameters -ResourceName $ResourceName `
        -CommandName $CommandName `
        -Parameters $PSBoundParameters
    Add-M365DSCTelemetryEvent -Data $data
    #endregion
    Write-Verbose -Message "Testing configuration of Endpoint Protection Bitlocker Policy {$DisplayName}"

    $CurrentValues = Get-TargetResource @PSBoundParameters

    #Compare complex object FixedDrivePolicy
    if ($null -ne $CurrentValues.FixedDrivePolicy)
    {
        $policyDiff = Compare-M365DSCComplexObject `
            -Source $FixedDrivePolicy `
            -Target $CurrentValues.FixedDrivePolicy

        if (-Not $policyDiff)
        {
            Write-Verbose -Message "Fixed Drive Policy differ: $($policyDiff | Out-String)"
            Write-Verbose -Message "Test-TargetResource returned $false"
            $EventMessage = "Fixed Drive Policy settings for Bitlocker policy {$DisplayName}" + `
                " were not in the desired state.`r`n" + `
                "The Fixed Drive Policy should contain {$($FixedDrivePolicy| Out-String)} " + `
                "but instead contained {$($CurrentValues.FixedDrivePolicy| Out-String)}"

            Add-M365DSCEvent -Message $EventMessage -EntryType 'Warning' `
                -EventID 1 -Source $($MyInvocation.MyCommand.Source)

            return $false
        }
        else
        {
            Write-Verbose -Message "Fixed Drive Policy settings for Bitlocker policy {$DisplayName} are the same"
        }
    }
    else
    {
        if ($null -ne $FixedDrivePolicy)
        {
            $verboseMessage="No Fixed Drive Policy exist for the current Bitlocker policy," + `
            " but Fixed Drive policy settings were specified for desired state"
            Write-Verbose -Message $verboseMessage
            Write-Verbose -Message "Test-TargetResource returned $false"
            $EventMessage = "Fixed Drive Policy settings for Bitlocker policy {$DisplayName}" + `
                " were not in the desired state.`r`n" + `
                "The Fixed Drive Policy should contain {$($FixedDrivePolicy| Out-String)} " + `
                " but instead contained {`$null}"

            Add-M365DSCEvent -Message $EventMessage -EntryType 'Warning' `
                -EventID 1 -Source $($MyInvocation.MyCommand.Source)

            return $false
        }
        else
        {
            Write-Verbose -Message "No Fixed Drive Policy exist for the current Bitlocker policy and no settings were specified in the desired state"
        }
    }

    #Compare complex object RemovableDrivePolicy
    if ($null -ne $CurrentValues.RemovableDrivePolicy)
    {
        $policyDiff = Compare-M365DSCComplexObject `
            -Source $RemovableDrivePolicy `
            -Target $CurrentValues.RemovableDrivePolicy

        if (-Not $policyDiff)
        {
            Write-Verbose -Message "Removable Drive Policy differ: $($policyDiff | Out-String)"
            Write-Verbose -Message "Test-TargetResource returned $false"
            $EventMessage = "Removable Drive Policy settings for Bitlocker policy {$DisplayName}" +`
                " were not in the desired state.`r`n" + `
                "The Removable Drive Policy should contain {$($RemovableDrivePolicy| Out-String)}" + `
                " but instead contained {$($CurrentValues.RemovableDrivePolicy| Out-String)}"

            Add-M365DSCEvent -Message $EventMessage -EntryType 'Warning' `
                -EventID 1 -Source $($MyInvocation.MyCommand.Source)

            return $false
        }
        else
        {
            Write-Verbose -Message "Removable Drive Policy settings for Bitlocker policy {$DisplayName} are the same"
        }
    }
    else
    {
        if ($null -ne $RemovableDrivePolicy)
        {
            $verboseMessage= "No Removable Drive Policy exist for the current Bitlocker policy," + `
                " but Removable Drive policy settings were specified for desired state"
            Write-Verbose -Message $verboseMessage
            Write-Verbose -Message "Test-TargetResource returned $false"
            $EventMessage = "Removable Drive Policy settings for Bitlocker policy {$DisplayName}" + `
                " were not in the desired state.`r`n" + `
                "The Removable Drive Policy should contain {$($RemovableDrivePolicy| Out-String)}" + `
                " but instead contained {`$null}"

            Add-M365DSCEvent -Message $EventMessage -EntryType 'Warning' `
                -EventID 1 -Source $($MyInvocation.MyCommand.Source)

            return $false
        }
        else
        {
            Write-Verbose -Message "No Removable Drive Policy exist for the current Bitlocker policy and no settings were specified in the desired state"
        }
    }

    #Compare complex object SystemDrivePolicy
    if ($null -ne $CurrentValues.SystemDrivePolicy)
    {
        $policyDiff = Compare-M365DSCComplexObject `
            -Source $SystemDrivePolicy `
            -Target $CurrentValues.SystemDrivePolicy

        if (-Not $policyDiff)
        {
            Write-Verbose -Message "System Drive Policy differ: $($policyDiff | Out-String)"

            Write-Verbose -Message "Test-TargetResource returned $false"

            $EventMessage = "System Drive Policy settings for Bitlocker policy {$DisplayName}" + `
                " were not in the desired state.`r`n" + `
                "The System Drive Policy should contain {$($SystemDrivePolicy| Out-String)} "+ `
                " but instead contained {$($CurrentValues.SystemDrivePolicy| Out-String)}"

            Add-M365DSCEvent -Message $EventMessage -EntryType 'Warning' `
                -EventID 1 -Source $($MyInvocation.MyCommand.Source)

            return $false
        }
        else
        {
            Write-Verbose -Message "System Drive Policy settings for Bitlocker policy {$DisplayName} are the same"
        }
    }
    else
    {
        if ($null -ne $SystemDrivePolicy)
        {
            $verboseMessage= "No System Drive Policy exist for the current Bitlocker policy," + `
                " but System Drive policy settings were specified for desired state"
            Write-Verbose -Message $verboseMessage

            Write-Verbose -Message "Test-TargetResource returned $false"

            $EventMessage = "System Drive Policy settings for Bitlocker policy {$DisplayName} were not in the desired state.`r`n" + `
                "The System Drive Policy should contain {$($SystemDrivePolicy| Out-String)} but instead contained {`$null}"

            Add-M365DSCEvent -Message $EventMessage -EntryType 'Warning' `
                -EventID 1 -Source $($MyInvocation.MyCommand.Source)

            return $false
        }
        else
        {
            Write-Verbose -Message "No System Drive Policy exist for the current Bitlocker policy and no settings were specified in the desired state"
        }
    }

    Write-Verbose -Message "Current Values: $(Convert-M365DscHashtableToString -Hashtable $CurrentValues)"
    Write-Verbose -Message "Target Values: $(Convert-M365DscHashtableToString -Hashtable $PSBoundParameters)"

    #Compare simple objects
    $ValuesToCheck = $PSBoundParameters
    $ValuesToCheck.Remove("FixedDrivePolicy") | Out-Null
    $ValuesToCheck.Remove("RemovableDrivePolicy") | Out-Null
    $ValuesToCheck.Remove("SystemDrivePolicy") | Out-Null
    $ValuesToCheck.Remove("ApplicationId") | Out-Null
    $ValuesToCheck.Remove("Credential") | Out-Null
    $ValuesToCheck.Remove("TenantId") | Out-Null
    $ValuesToCheck.Remove("ApplicationSecret") | Out-Null
    $ValuesToCheck.Remove("CertificateThumbprint") | Out-Null

    $TestResult = Test-M365DSCParameterState -CurrentValues $CurrentValues `
        -Source $($MyInvocation.MyCommand.Source) `
        -DesiredValues $PSBoundParameters `
        -ValuesToCheck $ValuesToCheck.Keys

    #$TestResult=$true
    Write-Verbose -Message "Test-TargetResource returned $TestResult"
    return $TestResult
}

function Export-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter()]
        [System.String]
        $ApplicationId,

        [Parameter()]
        [System.String]
        $TenantId,

        [Parameter()]
        [System.String]
        $ApplicationSecret,

        [Parameter()]
        [System.String]
        $CertificateThumbprint
    )


    $ConnectionMode = New-M365DSCConnection -Workload 'MicrosoftGraph' `
        -InboundParameters $PSBoundParameters `
        -SkipModuleReload:$true

    $context=Get-MgContext
    if($null -eq $context)
    {
        New-M365DSCConnection -Workload 'MicrosoftGraph' -InboundParameters $PSBoundParameters `
            -ErrorAction Stop
    }

    Select-MgProfile -Name 'Beta'
    #Ensure the proper dependencies are installed in the current environment.
    Confirm-M365DSCDependencies

    #region Telemetry
    $ResourceName = $MyInvocation.MyCommand.ModuleName -replace "MSFT_", ""
    $CommandName  = $MyInvocation.MyCommand
    $data = Format-M365DSCTelemetryParameters -ResourceName $ResourceName `
        -CommandName $CommandName `
        -Parameters $PSBoundParameters
    Add-M365DSCTelemetryEvent -Data $data
    #endregion

    $dscContent = ''
    $i = 1

    try
    {
        $policyTemplateID='d1174162-1dd2-4976-affc-6667049ab0ae'
        $policies = Get-MgDeviceManagementIntent -Filter "TemplateID eq '$policyTemplateID'" `
            -ErrorAction Stop

        if ($policies.Length -eq 0)
        {
            Write-Host $Global:M365DSCEmojiGreenCheckMark
        }
        else
        {
            Write-Host "`r`n" -NoNewLine
        }
        foreach ($policy in $policies)
        {
            Write-Host "    |---[$i/$($policies.Count)] $($policy.DisplayName)" -NoNewline

            $params = @{
                Identity                            = $policy.Id
                Ensure                              = 'Present'
                Credential                          = $Credential
                ApplicationId                       = $ApplicationId
                TenantId                            = $TenantId
                ApplicationSecret                   = $ApplicationSecret
                CertificateThumbprint               = $CertificateThumbprint
            }

            $Results = Get-TargetResource @params

            if ($null -ne $Results.FixedDrivePolicy)
            {
                $Results.FixedDrivePolicy = Get-M365DSCIntuneBitlockerPolicySettingsAsString `
                    -Policy $Results.FixedDrivePolicy `
                    -PolicyType "MSFT_IntuneBitlockerFixedDrivePolicySetting"
            }

            if ($null -ne $Results.RemovableDrivePolicy)
            {
                $Results.RemovableDrivePolicy = Get-M365DSCIntuneBitlockerPolicySettingsAsString `
                    -Policy $Results.RemovableDrivePolicy `
                    -PolicyType "MSFT_IntuneBitlockerRemovableDrivePolicySetting"
            }

            if ($null -ne $Results.SystemDrivePolicy)
            {
                $Results.SystemDrivePolicy = Get-M365DSCIntuneBitlockerPolicySettingsAsString `
                    -Policy $Results.SystemDrivePolicy `
                    -PolicyType "MSFT_IntuneBitlockerSystemDrivePolicySetting"
            }

            if ($Results.Ensure -eq 'Present')
            {
                $Results = Update-M365DSCExportAuthenticationResults -ConnectionMode $ConnectionMode `
                    -Results $Results

                $currentDSCBlock = Get-M365DSCExportContentForResource -ResourceName $ResourceName `
                -ConnectionMode $ConnectionMode `
                -ModulePath $PSScriptRoot `
                -Results $Results `
                -Credential $Credential

                if ($null -ne $Results.FixedDrivePolicy)
                {
                    $currentDSCBlock = Convert-M365DSCStringParamToVariable -DSCBlock $currentDSCBlock `
                        -ParameterName "FixedDrivePolicy"
                }
                if ($null -ne $Results.RemovableDrivePolicy)
                {
                    $currentDSCBlock = Convert-M365DSCStringParamToVariable -DSCBlock $currentDSCBlock `
                        -ParameterName "RemovableDrivePolicy"
                }
                if ($null -ne $Results.SystemDrivePolicy)
                {
                    $currentDSCBlock = Convert-M365DSCStringParamToVariable -DSCBlock $currentDSCBlock `
                        -ParameterName "SystemDrivePolicy"
                }

                $dscContent += $currentDSCBlock

                Save-M365DSCPartialExport -Content $currentDSCBlock `
                    -FileName $Global:PartialExportFileName

                Write-Host $Global:M365DSCEmojiGreenCheckMark
                $i++
            }
        }
        return $dscContent
    }
    catch
    {
        Write-Host $Global:M365DSCEmojiRedX
        if ($_.Exception -like '*401*')
        {
            Write-Host "`r`n    $($Global:M365DSCEmojiYellowCircle) The current tenant is not registered for Intune."
        }
        try
        {
            Write-Verbose -Message $_
            $tenantIdValue = $Credential.UserName.Split('@')[1]

            Add-M365DSCEvent -Message $_ -EntryType 'Error' `
                -EventID 1 -Source $($MyInvocation.MyCommand.Source) `
                -TenantId $tenantIdValue
        }
        catch
        {
            Write-Verbose -Message $_
        }
        return ""
    }
}

function Compare-M365DSCComplexObject
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory = 'true')]
        [PSCustomObject]
        $Source,
        [Parameter(Mandatory = 'true')]
        [PSCustomObject]
        $Target
    )

    $sourceProperties=($Source|Get-Member -MemberType Property)
    $sourceProperties=$sourceProperties|Where-Object `
        -FilterScript {$_.name -ne "PSComputerName"}
    foreach ($property in $sourceProperties)
    {
        #Recursive call for complex object
        if($property.definition -like "*CimInstance#InstanceArray*")
        {
            if(($null -ne $Source."$($property.name)") -and ($null -ne $Target."$($property.name)"))
            {
                $compareResult= Compare-M365DSCComplexObject `
                    -Source ($Source."$($property.name)") `
                    -Target ($Target."$($property.name)")

                if(-not $compareResult)
                {
                    return $false
                }

            }
            elseif (($null -eq $Source."$($property.name)") -xor ($null -eq $Target."$($property.name)"))
            {
                return $false
            }
        }
        #Simple object comparison
        else
        {
            $referenceObject=$Target."$($property.name)"
            $differenceObject=$Source."$($property.name)"

            if (($null -eq $referenceObject) -xor ($null -eq $differenceObject))
            {
                return $false
            }
            elseif(($null -ne $referenceObject) -and ($null -ne $differenceObject))
            {
                $compareResult = Compare-Object `
                    -ReferenceObject ($referenceObject) `
                    -DifferenceObject ($differenceObject)

                if ($null -ne $compareResult)
                {
                    return $false
                }
            }
        }
    }

    return $true
}
function Convert-M365DSCComplexParamToHashtable
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param(
        [Parameter(Mandatory = 'true')]
        $DSCComplexParams
    )

    [Array]$paramNames=($DSCComplexParams|Get-Member -MemberType Property).Name
    $paramNames=$paramNames|Where-Object `
        -FilterScript {$_ -ne "PSComputerName"}

    $settings=@{}
    foreach ($paramName in $paramNames)
    {
        if($null -ne $DSCComplexParams."$paramName")
        {
            if (($DSCComplexParams."$paramName".gettype()).Name -eq "CimInstance")
            {
                $settings.Add($paramName,(Convert-M365DSCComplexParamToHashtable -DSCComplexParams $DSCComplexParams."$paramName"))
            }
            else
            {
                $settings.Add($paramName,$DSCComplexParams."$paramName")
            }
        }
        else
        {
            $settings.Add($paramName,$null)
        }
    }

    return $settings
}
function Get-M365DSCIntuneBitlockerPolicySettingsAsString
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = 'true')]
        [PSCustomObject]
        $Policy,
        [Parameter(Mandatory = 'true')]
        [System.String]
        $PolicyType
    )

    $policyProperties=($Policy|Get-Member -MemberType NoteProperty).Name
    $StringContent = ""
    $StringContent += "$($PolicyType) { `r`n"
    foreach ($property in $policyProperties)
    {
        if($null -ne $Policy."$property")
        {
            $StringContent += "                $($property)                = '"
            if($property -eq "RecoveryOptions")
            {
                $Policy."$property"=Get-M365DSCIntuneBitlockerPolicySettingsAsString `
                    -Policy $Policy."$property" `
                    -PolicyType "MSFT_IntuneBitlockerRecoveryOptionsSetting"
            }
            $StringContent += $Policy."$property"
            $StringContent += "'`r`n"
        }


    }
    $StringContent += "            }`r`n"
    $StringContent += "            "
    return $StringContent
}
function Convert-M365DSCStringParamToVariable
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param (
        [Parameter(Mandatory = 'true')]
        [System.String]
        $DSCBlock,
        [Parameter(Mandatory = 'true')]
        [System.String]
        $ParameterName
    )

    $paramLines=$DSCBlock.split(";")

    $paramLine=$paramLines|Where-Object -FilterScript {$_ -like "*$ParameterName*=*"}
    $newline= $paramLine.replace("= `"MSFT","= MSFT").Substring(0,$paramLine.length-3)

    $sublines=$newline.split("`r`n")
    foreach($subline in $sublines)
    {
        if( $subline -like "*= 'MSFT*")
        {
        $newsubline= $subline.replace("= 'MSFT","= MSFT")
        $newline=$newline.replace($subline,$newsubline)
        }
        elseif($subline -like "*= 'True'*")
        {
        $newsubline= $subline.replace("= 'True'","= `$True")
        $newline=$newline.replace($subline,$newsubline)
        }
        elseif($subline -like "*= 'False'*")
        {
        $newsubline= $subline.replace("= 'False'","= `$False")
        $newline=$newline.replace($subline,$newsubline)
        }
        elseif($subline.trim() -eq "'")
        {
        $newsubline= $subline.replace("'","")
        $newline=$newline.replace($subline,$newsubline)
        }
    }

    return $DSCBlock -replace $paramLine,$newline
}

function Get-M365DSCIntuneDeviceConfigurationSettings
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param(
        [Parameter(Mandatory = 'true')]
        [System.Collections.Hashtable]
        $Properties,
        [Parameter()]
        [System.String]
        $DefinitionIdPrefix
    )

    $results = @()
    foreach ($property in $properties.Keys)
    {
        if ($property -ne 'Verbose')
        {
            $setting=@{}
            switch (($properties.$property.gettype()).name) {
                "String" {$settingType="#microsoft.graph.deviceManagementStringSettingInstance"}
                "Boolean" {$settingType="#microsoft.graph.deviceManagementBooleanSettingInstance"}
                "Int32" {$settingType="#microsoft.graph.deviceManagementIntegerSettingInstance"}
                Default {$settingType="#microsoft.graph.deviceManagementComplexSettingInstance"}
            }
            $settingDefinitionIdPrefix="deviceConfiguration--$DefinitionIdPrefix"
            $settingDefinitionId =$settingDefinitionIdPrefix + $property
            $setting.Add("@odata.type",$settingType)
            $setting.Add("definitionId", $settingDefinitionId)
            $setting.Add("valueJson", ($properties.$property|ConvertTo-Json))
            $results+=$setting
        }
    }
    return $results
}

Export-ModuleMember -Function *-TargetResource

