function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        #region resource generator code
        [Parameter(Mandatory = $true)]
        [System.String]
        $Id,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $AttackSurfaceReductionRules,

        [Parameter()]
        [System.String[]]
        $AttackSurfaceReductionOnlyExclusions,

        [Parameter()]
        [ValidateSet(0,1,2,3,4)]
        [System.Int32]
        $EnableControlledFolderAccess,

        [Parameter()]
        [System.String[]]
        $ControlledFolderAccessProtectedFolders,

        [Parameter()]
        [System.String[]]
        $ControlledFolderAccessAllowedApplications,

        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $Assignments,
        #endregion

        [Parameter()]
        [System.String]
        [ValidateSet('Absent', 'Present')]
        $Ensure = 'Present',

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
        [System.Management.Automation.PSCredential]
        $ApplicationSecret,

        [Parameter()]
        [System.String]
        $CertificateThumbprint,

        [Parameter()]
        [Switch]
        $ManagedIdentity
    )

    try
    {
        $ConnectionMode = New-M365DSCConnection -Workload 'MicrosoftGraph' `
            -InboundParameters $PSBoundParameters `
            -ProfileName 'beta'

        #Ensure the proper dependencies are installed in the current environment.
        Confirm-M365DSCDependencies

        #region Telemetry
        $ResourceName = $MyInvocation.MyCommand.ModuleName.Replace('MSFT_', '')
        $CommandName = $MyInvocation.MyCommand
        $data = Format-M365DSCTelemetryParameters -ResourceName $ResourceName `
            -CommandName $CommandName `
            -Parameters $PSBoundParameters
        Add-M365DSCTelemetryEvent -Data $data
        #endregion

        $nullResult = $PSBoundParameters
        $nullResult.Ensure = 'Absent'

        $getValue = $null
        #region resource generator code
        $getValue = Get-MgDeviceManagementConfigurationPolicy -DeviceManagementConfigurationPolicyId $Id  -expandProperty "settings" -ErrorAction SilentlyContinue

        if ($null -eq $getValue)
        {
            Write-Verbose -Message "Could not find an Z D R G Test with Id {$Id}"

            if (-Not [string]::IsNullOrEmpty($Name))
            {
                $getValue = Get-MgDeviceManagementConfigurationPolicy `
                    -Filter "Name eq '$Name'" `
                    -ErrorAction SilentlyContinue
                if ($null -ne $getValue)
                {
                    $getValue = Get-MgDeviceManagementConfigurationPolicy -DeviceManagementConfigurationPolicyId $getValue.Id -expandProperty "settings" -ErrorAction SilentlyContinue
                }
            }
        }
        #endregion
        if ($null -eq $getValue)
        {
            Write-Verbose -Message "Could not find an Z D R G Test with Name {$Name}"
            return $nullResult
        }
        $Id = $getValue.Id
        Write-Verbose -Message "An Z D R G Test with Id {$Id} and Name {$Name} was found."

        #region resource generator code
        $setting = $getValue.settings.SettingInstance | Where-Object {$_.settingDefinitionId -eq ''}
        $simpleId = $setting.AdditionalProperties.system.String.value

        $setting = $getValue.settings.SettingInstance | Where-Object {$_.settingDefinitionId -eq ''}
        $simpleName = $setting.AdditionalProperties.system.String.value

        $setting = $getValue.settings.SettingInstance | Where-Object {$_.settingDefinitionId -eq 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules'}
        $childAttackSurfaceReductionRules = $setting.AdditionalProperties.groupSettingCollectionValue.children | Where-Object {$_.settingDefinitionId -eq 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules'}
        $complexAttackSurfaceReductionRules = @{}
        $childBlockAdobeReaderFromCreatingChildProcesses = $childAttackSurfaceReductionRules.choiceSettingValue.children | Where-Object {$_.settingDefinitionId -eq 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockadobereaderfromcreatingchildprocesses'}
        $hashBlockAdobeReaderFromCreatingChildProcesses = @{}
        $hashBlockAdobeReaderFromCreatingChildProcesses.Add('ASROnlyPerRuleExclusions',$childBlockAdobeReaderFromCreatingChildProcesses.simpleSettingCollectionValue.value)

        $hashBlockAdobeReaderFromCreatingChildProcesses.Add('Value',$childBlockAdobeReaderFromCreatingChildProcesses.choiceSettingValue.value)
        $complexAttackSurfaceReductionRules.Add('BlockAdobeReaderFromCreatingChildProcesses',$hashBlockAdobeReaderFromCreatingChildProcesses)

        $childBlockExecutionOfPotentiallyObfuscatedScripts = $childAttackSurfaceReductionRules.choiceSettingValue.children | Where-Object {$_.settingDefinitionId -eq 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts'}
        $hashBlockExecutionOfPotentiallyObfuscatedScripts = @{}
        $hashBlockExecutionOfPotentiallyObfuscatedScripts.Add('ASROnlyPerRuleExclusions',$childBlockExecutionOfPotentiallyObfuscatedScripts.simpleSettingCollectionValue.value)

        $hashBlockExecutionOfPotentiallyObfuscatedScripts.Add('Value',$childBlockExecutionOfPotentiallyObfuscatedScripts.choiceSettingValue.value)
        $complexAttackSurfaceReductionRules.Add('BlockExecutionOfPotentiallyObfuscatedScripts',$hashBlockExecutionOfPotentiallyObfuscatedScripts)

        $childBlockWin32APICallsFromOfficeMacros = $childAttackSurfaceReductionRules.choiceSettingValue.children | Where-Object {$_.settingDefinitionId -eq 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockwin32apicallsfromofficemacros'}
        $hashBlockWin32APICallsFromOfficeMacros = @{}
        $hashBlockWin32APICallsFromOfficeMacros.Add('ASROnlyPerRuleExclusions',$childBlockWin32APICallsFromOfficeMacros.simpleSettingCollectionValue.value)

        $hashBlockWin32APICallsFromOfficeMacros.Add('Value',$childBlockWin32APICallsFromOfficeMacros.choiceSettingValue.value)
        $complexAttackSurfaceReductionRules.Add('BlockWin32APICallsFromOfficeMacros',$hashBlockWin32APICallsFromOfficeMacros)

        $childBlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = $childAttackSurfaceReductionRules.choiceSettingValue.children | Where-Object {$_.settingDefinitionId -eq 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem'}
        $hashBlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = @{}
        $hashBlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem.Add('ASROnlyPerRuleExclusions',$childBlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem.simpleSettingCollectionValue.value)

        $hashBlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem.Add('Value',$childBlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem.choiceSettingValue.value)
        $complexAttackSurfaceReductionRules.Add('BlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem',$hashBlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem)

        $childBlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = $childAttackSurfaceReductionRules.choiceSettingValue.children | Where-Object {$_.settingDefinitionId -eq 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutablefilesrunningunlesstheymeetprevalenceagetrustedlistcriterion'}
        $hashBlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = @{}
        $hashBlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion.Add('ASROnlyPerRuleExclusions',$childBlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion.simpleSettingCollectionValue.value)

        $hashBlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion.Add('Value',$childBlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion.choiceSettingValue.value)
        $complexAttackSurfaceReductionRules.Add('BlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion',$hashBlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion)

        $childBlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = $childAttackSurfaceReductionRules.choiceSettingValue.children | Where-Object {$_.settingDefinitionId -eq 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockjavascriptorvbscriptfromlaunchingdownloadedexecutablecontent'}
        $hashBlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = @{}
        $hashBlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent.Add('ASROnlyPerRuleExclusions',$childBlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent.simpleSettingCollectionValue.value)

        $hashBlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent.Add('Value',$childBlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent.choiceSettingValue.value)
        $complexAttackSurfaceReductionRules.Add('BlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent',$hashBlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent)

        $childBlockOfficeCommunicationAppFromCreatingChildProcesses = $childAttackSurfaceReductionRules.choiceSettingValue.children | Where-Object {$_.settingDefinitionId -eq 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficecommunicationappfromcreatingchildprocesses'}
        $hashBlockOfficeCommunicationAppFromCreatingChildProcesses = @{}
        $hashBlockOfficeCommunicationAppFromCreatingChildProcesses.Add('ASROnlyPerRuleExclusions',$childBlockOfficeCommunicationAppFromCreatingChildProcesses.simpleSettingCollectionValue.value)

        $hashBlockOfficeCommunicationAppFromCreatingChildProcesses.Add('Value',$childBlockOfficeCommunicationAppFromCreatingChildProcesses.choiceSettingValue.value)
        $complexAttackSurfaceReductionRules.Add('BlockOfficeCommunicationAppFromCreatingChildProcesses',$hashBlockOfficeCommunicationAppFromCreatingChildProcesses)

        $childBlockAllOfficeApplicationsFromCreatingChildProcesses = $childAttackSurfaceReductionRules.choiceSettingValue.children | Where-Object {$_.settingDefinitionId -eq 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockallofficeapplicationsfromcreatingchildprocesses'}
        $hashBlockAllOfficeApplicationsFromCreatingChildProcesses = @{}
        $hashBlockAllOfficeApplicationsFromCreatingChildProcesses.Add('ASROnlyPerRuleExclusions',$childBlockAllOfficeApplicationsFromCreatingChildProcesses.simpleSettingCollectionValue.value)

        $hashBlockAllOfficeApplicationsFromCreatingChildProcesses.Add('Value',$childBlockAllOfficeApplicationsFromCreatingChildProcesses.choiceSettingValue.value)
        $complexAttackSurfaceReductionRules.Add('BlockAllOfficeApplicationsFromCreatingChildProcesses',$hashBlockAllOfficeApplicationsFromCreatingChildProcesses)

        $childBlockUntrustedUnsignedProcessesThatRunFromUSB = $childAttackSurfaceReductionRules.choiceSettingValue.children | Where-Object {$_.settingDefinitionId -eq 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockuntrustedunsignedprocessesthatrunfromusb'}
        $hashBlockUntrustedUnsignedProcessesThatRunFromUSB = @{}
        $hashBlockUntrustedUnsignedProcessesThatRunFromUSB.Add('ASROnlyPerRuleExclusions',$childBlockUntrustedUnsignedProcessesThatRunFromUSB.simpleSettingCollectionValue.value)

        $hashBlockUntrustedUnsignedProcessesThatRunFromUSB.Add('Value',$childBlockUntrustedUnsignedProcessesThatRunFromUSB.choiceSettingValue.value)
        $complexAttackSurfaceReductionRules.Add('BlockUntrustedUnsignedProcessesThatRunFromUSB',$hashBlockUntrustedUnsignedProcessesThatRunFromUSB)

        $childBlockProcessCreationsFromPSExecAndWMICommands = $childAttackSurfaceReductionRules.choiceSettingValue.children | Where-Object {$_.settingDefinitionId -eq 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockprocesscreationsfrompsexecandwmicommands'}
        $hashBlockProcessCreationsFromPSExecAndWMICommands = @{}
        $hashBlockProcessCreationsFromPSExecAndWMICommands.Add('ASROnlyPerRuleExclusions',$childBlockProcessCreationsFromPSExecAndWMICommands.simpleSettingCollectionValue.value)

        $hashBlockProcessCreationsFromPSExecAndWMICommands.Add('Value',$childBlockProcessCreationsFromPSExecAndWMICommands.choiceSettingValue.value)
        $complexAttackSurfaceReductionRules.Add('BlockProcessCreationsFromPSExecAndWMICommands',$hashBlockProcessCreationsFromPSExecAndWMICommands)

        $complexAttackSurfaceReductionRules.Add('BlockPersistenceThroughWMIEventSubscription',$childAttackSurfaceReductionRules.choiceSettingValue.value)

        $childBlockOfficeApplicationsFromCreatingExecutableContent = $childAttackSurfaceReductionRules.choiceSettingValue.children | Where-Object {$_.settingDefinitionId -eq 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficeapplicationsfromcreatingexecutablecontent'}
        $hashBlockOfficeApplicationsFromCreatingExecutableContent = @{}
        $hashBlockOfficeApplicationsFromCreatingExecutableContent.Add('ASROnlyPerRuleExclusions',$childBlockOfficeApplicationsFromCreatingExecutableContent.simpleSettingCollectionValue.value)

        $hashBlockOfficeApplicationsFromCreatingExecutableContent.Add('Value',$childBlockOfficeApplicationsFromCreatingExecutableContent.choiceSettingValue.value)
        $complexAttackSurfaceReductionRules.Add('BlockOfficeApplicationsFromCreatingExecutableContent',$hashBlockOfficeApplicationsFromCreatingExecutableContent)

        $childBlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = $childAttackSurfaceReductionRules.choiceSettingValue.children | Where-Object {$_.settingDefinitionId -eq 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficeapplicationsfrominjectingcodeintootherprocesses'}
        $hashBlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = @{}
        $hashBlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses.Add('ASROnlyPerRuleExclusions',$childBlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses.simpleSettingCollectionValue.value)

        $hashBlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses.Add('Value',$childBlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses.choiceSettingValue.value)
        $complexAttackSurfaceReductionRules.Add('BlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses',$hashBlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses)

        $childUseAdvancedProtectionAgainstRansomware = $childAttackSurfaceReductionRules.choiceSettingValue.children | Where-Object {$_.settingDefinitionId -eq 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_useadvancedprotectionagainstransomware'}
        $hashUseAdvancedProtectionAgainstRansomware = @{}
        $hashUseAdvancedProtectionAgainstRansomware.Add('ASROnlyPerRuleExclusions',$childUseAdvancedProtectionAgainstRansomware.simpleSettingCollectionValue.value)

        $hashUseAdvancedProtectionAgainstRansomware.Add('Value',$childUseAdvancedProtectionAgainstRansomware.choiceSettingValue.value)
        $complexAttackSurfaceReductionRules.Add('UseAdvancedProtectionAgainstRansomware',$hashUseAdvancedProtectionAgainstRansomware)

        $childBlockExecutableContentFromEmailClientAndWebmail = $childAttackSurfaceReductionRules.choiceSettingValue.children | Where-Object {$_.settingDefinitionId -eq 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutablecontentfromemailclientandwebmail'}
        $hashBlockExecutableContentFromEmailClientAndWebmail = @{}
        $hashBlockExecutableContentFromEmailClientAndWebmail.Add('ASROnlyPerRuleExclusions',$childBlockExecutableContentFromEmailClientAndWebmail.simpleSettingCollectionValue.value)

        $hashBlockExecutableContentFromEmailClientAndWebmail.Add('Value',$childBlockExecutableContentFromEmailClientAndWebmail.choiceSettingValue.value)
        $complexAttackSurfaceReductionRules.Add('BlockExecutableContentFromEmailClientAndWebmail',$hashBlockExecutableContentFromEmailClientAndWebmail)

        $childBlockAbuseOfExploitedVulnerableSignedDrivers = $childAttackSurfaceReductionRules.choiceSettingValue.children | Where-Object {$_.settingDefinitionId -eq 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockabuseofexploitedvulnerablesigneddrivers'}
        $hashBlockAbuseOfExploitedVulnerableSignedDrivers = @{}
        $hashBlockAbuseOfExploitedVulnerableSignedDrivers.Add('ASROnlyPerRuleExclusions',$childBlockAbuseOfExploitedVulnerableSignedDrivers.simpleSettingCollectionValue.value)

        $hashBlockAbuseOfExploitedVulnerableSignedDrivers.Add('Value',$childBlockAbuseOfExploitedVulnerableSignedDrivers.choiceSettingValue.value)
        $complexAttackSurfaceReductionRules.Add('BlockAbuseOfExploitedVulnerableSignedDrivers',$hashBlockAbuseOfExploitedVulnerableSignedDrivers)

        $complexAttackSurfaceReductionRules.Add('Value',$childAttackSurfaceReductionRules.groupSettingCollectionValue.value)
        $AttackSurfaceReductionRules = $hashAttackSurfaceReductionRules

        $setting = $getValue.settings.SettingInstance | Where-Object {$_.settingDefinitionId -eq 'device_vendor_msft_policy_config_defender_attacksurfacereductiononlyexclusions'}
        $simpleAttackSurfaceReductionOnlyExclusions = $setting.AdditionalProperties.simpleSettingCollectionValue.value

        $setting = $getValue.settings.SettingInstance | Where-Object {$_.settingDefinitionId -eq 'device_vendor_msft_policy_config_defender_enablecontrolledfolderaccess'}
        $simpleEnableControlledFolderAccess = $setting.AdditionalProperties.choiceSettingValue.value

        $setting = $getValue.settings.SettingInstance | Where-Object {$_.settingDefinitionId -eq 'device_vendor_msft_policy_config_defender_controlledfolderaccessprotectedfolders'}
        $simpleControlledFolderAccessProtectedFolders = $setting.AdditionalProperties.simpleSettingCollectionValue.value

        $setting = $getValue.settings.SettingInstance | Where-Object {$_.settingDefinitionId -eq 'device_vendor_msft_policy_config_defender_controlledfolderaccessallowedapplications'}
        $simpleControlledFolderAccessAllowedApplications = $setting.AdditionalProperties.simpleSettingCollectionValue.value
        #endregion

        $results = @{
            #region resource generator code
            Id                                        = $getValue.Id
            Name                                      = $getValue.Name
            AttackSurfaceReductionRules               = $complexAttackSurfaceReductionRules
            AttackSurfaceReductionOnlyExclusions      = $simpleAttackSurfaceReductionOnlyExclusions
            EnableControlledFolderAccess              = $simpleEnableControlledFolderAccess
            ControlledFolderAccessProtectedFolders    = $simpleControlledFolderAccessProtectedFolders
            ControlledFolderAccessAllowedApplications = $simpleControlledFolderAccessAllowedApplications
            Ensure                                    = 'Present'
            Credential                                = $Credential
            ApplicationId                             = $ApplicationId
            TenantId                                  = $TenantId
            ApplicationSecret                         = $ApplicationSecret
            CertificateThumbprint                     = $CertificateThumbprint
            Managedidentity                           = $ManagedIdentity.IsPresent
            #endregion
        }
        $assignmentsValues = Get-MgDeviceManagementConfigurationPolicyAssignment -DeviceManagementConfigurationPolicyId $Id
        $assignmentResult = @()
        foreach ($assignmentEntry in $AssignmentsValues)
        {
            $assignmentValue = @{
                dataType = $assignmentEntry.Target.AdditionalProperties.'@odata.type'
                deviceAndAppManagementAssignmentFilterType = $(if ($null -ne $assignmentEntry.Target.DeviceAndAppManagementAssignmentFilterType)
                    {$assignmentEntry.Target.DeviceAndAppManagementAssignmentFilterType.ToString()})
                deviceAndAppManagementAssignmentFilterId = $assignmentEntry.Target.DeviceAndAppManagementAssignmentFilterId
                groupId = $assignmentEntry.Target.AdditionalProperties.groupId
            }
            $assignmentResult += $assignmentValue
        }
        $results.Add('Assignments', $assignmentResult)

        return [System.Collections.Hashtable] $results
    }
    catch
    {
        New-M365DSCLogEntry -Message 'Error retrieving data:' `
            -Exception $_ `
            -Source $($MyInvocation.MyCommand.Source) `
            -TenantId $TenantId `
            -Credential $Credential

        return $nullResult
    }
}

function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        #region resource generator code
        [Parameter(Mandatory = $true)]
        [System.String]
        $Id,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $AttackSurfaceReductionRules,

        [Parameter()]
        [System.String[]]
        $AttackSurfaceReductionOnlyExclusions,

        [Parameter()]
        [ValidateSet(0,1,2,3,4)]
        [System.Int32]
        $EnableControlledFolderAccess,

        [Parameter()]
        [System.String[]]
        $ControlledFolderAccessProtectedFolders,

        [Parameter()]
        [System.String[]]
        $ControlledFolderAccessAllowedApplications,

        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $Assignments,
        #endregion
        [Parameter()]
        [System.String]
        [ValidateSet('Absent', 'Present')]
        $Ensure = 'Present',

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
        [System.Management.Automation.PSCredential]
        $ApplicationSecret,

        [Parameter()]
        [System.String]
        $CertificateThumbprint,

        [Parameter()]
        [Switch]
        $ManagedIdentity
    )

    #Ensure the proper dependencies are installed in the current environment.
    Confirm-M365DSCDependencies

    #region Telemetry
    $ResourceName = $MyInvocation.MyCommand.ModuleName.Replace('MSFT_', '')
    $CommandName = $MyInvocation.MyCommand
    $data = Format-M365DSCTelemetryParameters -ResourceName $ResourceName `
        -CommandName $CommandName `
        -Parameters $PSBoundParameters
    Add-M365DSCTelemetryEvent -Data $data
    #endregion

    $currentInstance = Get-TargetResource @PSBoundParameters

    $BoundParameters = Remove-M365DSCAuthenticationParameter -BoundParameters $PSBoundParameters

    if ($Ensure -eq 'Present' -and $currentInstance.Ensure -eq 'Absent')
    {
        Write-Verbose -Message "Creating an Z D R G Test with Name {$DisplayName}"
        $BoundParameters.Remove("Assignments") | Out-Null

        $CreateParameters = ([Hashtable]$BoundParameters).clone()
        $CreateParameters = Rename-M365DSCCimInstanceParameter -Properties $CreateParameters
        $CreateParameters.Remove('Id') | Out-Null

        $keys = (([Hashtable]$CreateParameters).clone()).Keys
        foreach ($key in $keys)
        {
            if ($null -ne $CreateParameters.$key -and $CreateParameters.$key.getType().Name -like '*cimInstance*')
            {
                $CreateParameters.$key = Convert-M365DSCDRGComplexTypeToHashtable -ComplexObject $CreateParameters.$key
            }
        }
        #region resource generator code
        $CreateParameters.Add("@odata.type", "#microsoft.graph.DeviceManagementConfigurationPolicy")
        $policy = New-MgDeviceManagementConfigurationPolicy -BodyParameter $CreateParameters
        $assignmentsHash = @()
        foreach ($assignment in $Assignments)
        {
            $assignmentsHash += Get-M365DSCDRGComplexTypeToHashtable -ComplexObject $Assignment
        }

        if ($policy.id)
        {
            Update-DeviceConfigurationPolicyAssignment -DeviceConfigurationPolicyId  $policy.id `
                -Targets $assignmentsHash `
                -Repository 'deviceManagement/configurationPolicies'
        }
        #endregion
    }
    elseif ($Ensure -eq 'Present' -and $currentInstance.Ensure -eq 'Present')
    {
        Write-Verbose -Message "Updating the Z D R G Test with Id {$($currentInstance.Id)}"
        $BoundParameters.Remove("Assignments") | Out-Null

        $UpdateParameters = ([Hashtable]$BoundParameters).clone()
        $UpdateParameters = Rename-M365DSCCimInstanceParameter -Properties $UpdateParameters

        $UpdateParameters.Remove('Id') | Out-Null

        $keys = (([Hashtable]$UpdateParameters).clone()).Keys
        foreach ($key in $keys)
        {
            if ($null -ne $UpdateParameters.$key -and $UpdateParameters.$key.getType().Name -like '*cimInstance*')
            {
                $UpdateParameters.$key = Convert-M365DSCDRGComplexTypeToHashtable -ComplexObject $UpdateParameters.$key
            }
        }
        #region resource generator code
        $UpdateParameters.Add("@odata.type", "#microsoft.graph.DeviceManagementConfigurationPolicy")
        Update-MgDeviceManagementConfigurationPolicy  `
            -DeviceManagementConfigurationPolicyId $currentInstance.Id `
            -BodyParameter $UpdateParameters
        $assignmentsHash = @()
        foreach ($assignment in $Assignments)
        {
            $assignmentsHash += Get-M365DSCDRGComplexTypeToHashtable -ComplexObject $Assignment
        }
        Update-DeviceConfigurationPolicyAssignment `
            -DeviceConfigurationPolicyId $currentInstance.id `
            -Targets $assignmentsHash `
            -Repository 'deviceManagement/configurationPolicies'
        #endregion
    }
    elseif ($Ensure -eq 'Absent' -and $currentInstance.Ensure -eq 'Present')
    {
        Write-Verbose -Message "Removing the Z D R G Test with Id {$($currentInstance.Id)}" 
        #region resource generator code
Remove-MgDeviceManagementConfigurationPolicy -DeviceManagementConfigurationPolicyId $currentInstance.Id
        #endregion
    }
}

function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        #region resource generator code
        [Parameter(Mandatory = $true)]
        [System.String]
        $Id,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $AttackSurfaceReductionRules,

        [Parameter()]
        [System.String[]]
        $AttackSurfaceReductionOnlyExclusions,

        [Parameter()]
        [ValidateSet(0,1,2,3,4)]
        [System.Int32]
        $EnableControlledFolderAccess,

        [Parameter()]
        [System.String[]]
        $ControlledFolderAccessProtectedFolders,

        [Parameter()]
        [System.String[]]
        $ControlledFolderAccessAllowedApplications,

        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $Assignments,
        #endregion

        [Parameter()]
        [System.String]
        [ValidateSet('Absent', 'Present')]
        $Ensure = 'Present',

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
        [System.Management.Automation.PSCredential]
        $ApplicationSecret,

        [Parameter()]
        [System.String]
        $CertificateThumbprint,

        [Parameter()]
        [Switch]
        $ManagedIdentity
    )

    #Ensure the proper dependencies are installed in the current environment.
    Confirm-M365DSCDependencies

    #region Telemetry
    $ResourceName = $MyInvocation.MyCommand.ModuleName.Replace('MSFT_', '')
    $CommandName = $MyInvocation.MyCommand
    $data = Format-M365DSCTelemetryParameters -ResourceName $ResourceName `
        -CommandName $CommandName `
        -Parameters $PSBoundParameters
    Add-M365DSCTelemetryEvent -Data $data
    #endregion

    Write-Verbose -Message "Testing configuration of the Z D R G Test with Id {$Id} and Name {$Name}"

    $CurrentValues = Get-TargetResource @PSBoundParameters
    $ValuesToCheck = ([Hashtable]$PSBoundParameters).clone()

    if ($CurrentValues.Ensure -ne $PSBoundParameters.Ensure)
    {
        Write-Verbose -Message "Test-TargetResource returned $false"
        return $false
    }
    $testResult = $true

    #Compare Cim instances
    foreach ($key in $PSBoundParameters.Keys)
    {
        $source = $PSBoundParameters.$key
        $target = $CurrentValues.$key
        if ($source.getType().Name -like '*CimInstance*')
        {
            $source = Get-M365DSCDRGComplexTypeToHashtable -ComplexObject $source

            $testResult = Compare-M365DSCComplexObject `
                -Source ($source) `
                -Target ($target)

            if (-Not $testResult)
            {
                $testResult = $false
                break
            }

            $ValuesToCheck.Remove($key) | Out-Null
        }
    }

    $ValuesToCheck.remove('Id') | Out-Null
    $ValuesToCheck.Remove('Credential') | Out-Null
    $ValuesToCheck.Remove('ApplicationId') | Out-Null
    $ValuesToCheck.Remove('TenantId') | Out-Null
    $ValuesToCheck.Remove('ApplicationSecret') | Out-Null

    Write-Verbose -Message "Current Values: $(Convert-M365DscHashtableToString -Hashtable $CurrentValues)"
    Write-Verbose -Message "Target Values: $(Convert-M365DscHashtableToString -Hashtable $ValuesToCheck)"

    if ($testResult)
    {
        $testResult = Test-M365DSCParameterState -CurrentValues $CurrentValues `
            -Source $($MyInvocation.MyCommand.Source) `
            -DesiredValues $PSBoundParameters `
            -ValuesToCheck $ValuesToCheck.Keys
    }

    Write-Verbose -Message "Test-TargetResource returned $testResult"

    return $testResult
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
        [System.Management.Automation.PSCredential]
        $ApplicationSecret,

        [Parameter()]
        [System.String]
        $CertificateThumbprint,

        [Parameter()]
        [Switch]
        $ManagedIdentity
    )

    $ConnectionMode = New-M365DSCConnection -Workload 'MicrosoftGraph' `
        -InboundParameters $PSBoundParameters `
        -ProfileName 'beta'

    #Ensure the proper dependencies are installed in the current environment.
    Confirm-M365DSCDependencies

    #region Telemetry
    $ResourceName = $MyInvocation.MyCommand.ModuleName.Replace('MSFT_', '')
    $CommandName = $MyInvocation.MyCommand
    $data = Format-M365DSCTelemetryParameters -ResourceName $ResourceName `
        -CommandName $CommandName `
        -Parameters $PSBoundParameters
    Add-M365DSCTelemetryEvent -Data $data
    #endregion

    try
    {
        #region resource generator code
        [array]$getValue = Get-MgDeviceManagementConfigurationPolicy `
            -All `
            -ErrorAction Stop
        #endregion

        $i = 1
        $dscContent = ''
        if ($getValue.Length -eq 0)
        {
            Write-Host $Global:M365DSCEmojiGreenCheckMark
        }
        else
        {
            Write-Host "`r`n" -NoNewline
        }
        foreach ($config in $getValue)
        {
            $displayedKey = $config.Id
            if (-not [String]::IsNullOrEmpty($config.displayName))
            {
                $displayedKey = $config.displayName
            }
            Write-Host "    |---[$i/$($getValue.Count)] $displayedKey" -NoNewline
            $params = @{
                Id = $config.Id
                Name           =  $config.Name
                Ensure = 'Present'
                Credential = $Credential
                ApplicationId = $ApplicationId
                TenantId = $TenantId
                ApplicationSecret = $ApplicationSecret
                CertificateThumbprint = $CertificateThumbprint
                Managedidentity = $ManagedIdentity.IsPresent
            }

            $Results = Get-TargetResource @Params
            $Results = Update-M365DSCExportAuthenticationResults -ConnectionMode $ConnectionMode `
                -Results $Results
            if ($null -ne $Results.AttackSurfaceReductionRules)
            {
                $complexMapping = @(
                    @{
                        Name = 'AttackSurfaceReductionRules'
                        CimInstanceName = 'MicrosoftGraphAttackSurfaceReductionRules_Complex'
                        IsRequired = $False
                    }
                    @{
                        Name = 'BlockAdobeReaderFromCreatingChildProcesses'
                        CimInstanceName = 'MicrosoftGraphBlockAdobeReaderFromCreatingChildProcesses_Complex'
                        IsRequired = $False
                    }
                    @{
                        Name = 'BlockExecutionOfPotentiallyObfuscatedScripts'
                        CimInstanceName = 'MicrosoftGraphBlockExecutionOfPotentiallyObfuscatedScripts_Complex'
                        IsRequired = $False
                    }
                    @{
                        Name = 'BlockWin32APICallsFromOfficeMacros'
                        CimInstanceName = 'MicrosoftGraphBlockWin32APICallsFromOfficeMacros_Complex'
                        IsRequired = $False
                    }
                    @{
                        Name = 'BlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem'
                        CimInstanceName = 'MicrosoftGraphBlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem_Complex'
                        IsRequired = $False
                    }
                    @{
                        Name = 'BlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion'
                        CimInstanceName = 'MicrosoftGraphBlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion_Complex'
                        IsRequired = $False
                    }
                    @{
                        Name = 'BlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent'
                        CimInstanceName = 'MicrosoftGraphBlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent_Complex'
                        IsRequired = $False
                    }
                    @{
                        Name = 'BlockOfficeCommunicationAppFromCreatingChildProcesses'
                        CimInstanceName = 'MicrosoftGraphBlockOfficeCommunicationAppFromCreatingChildProcesses_Complex'
                        IsRequired = $False
                    }
                    @{
                        Name = 'BlockAllOfficeApplicationsFromCreatingChildProcesses'
                        CimInstanceName = 'MicrosoftGraphBlockAllOfficeApplicationsFromCreatingChildProcesses_Complex'
                        IsRequired = $False
                    }
                    @{
                        Name = 'BlockUntrustedUnsignedProcessesThatRunFromUSB'
                        CimInstanceName = 'MicrosoftGraphBlockUntrustedUnsignedProcessesThatRunFromUSB_Complex'
                        IsRequired = $False
                    }
                    @{
                        Name = 'BlockProcessCreationsFromPSExecAndWMICommands'
                        CimInstanceName = 'MicrosoftGraphBlockProcessCreationsFromPSExecAndWMICommands_Complex'
                        IsRequired = $False
                    }
                    @{
                        Name = 'BlockOfficeApplicationsFromCreatingExecutableContent'
                        CimInstanceName = 'MicrosoftGraphBlockOfficeApplicationsFromCreatingExecutableContent_Complex'
                        IsRequired = $False
                    }
                    @{
                        Name = 'BlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses'
                        CimInstanceName = 'MicrosoftGraphBlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses_Complex'
                        IsRequired = $False
                    }
                    @{
                        Name = 'UseAdvancedProtectionAgainstRansomware'
                        CimInstanceName = 'MicrosoftGraphUseAdvancedProtectionAgainstRansomware_Complex'
                        IsRequired = $False
                    }
                    @{
                        Name = 'BlockExecutableContentFromEmailClientAndWebmail'
                        CimInstanceName = 'MicrosoftGraphBlockExecutableContentFromEmailClientAndWebmail_Complex'
                        IsRequired = $False
                    }
                    @{
                        Name = 'BlockAbuseOfExploitedVulnerableSignedDrivers'
                        CimInstanceName = 'MicrosoftGraphBlockAbuseOfExploitedVulnerableSignedDrivers_Complex'
                        IsRequired = $False
                    }
                )
                $complexTypeStringResult = Get-M365DSCDRGComplexTypeToString `
                    -ComplexObject $Results.AttackSurfaceReductionRules `
                    -CIMInstanceName 'MicrosoftGraphAttackSurfaceReductionRules_Complex' `
                    -ComplexTypeMapping $complexMapping

                if (-Not [String]::IsNullOrWhiteSpace($complexTypeStringResult))
                {
                    $Results.AttackSurfaceReductionRules = $complexTypeStringResult
                }
                else
                {
                    $Results.Remove('AttackSurfaceReductionRules') | Out-Null
                }
            }
            if ($Results.Assignments)
            {
                $complexTypeStringResult = Get-M365DSCDRGComplexTypeToString -ComplexObject $Results.Assignments -CIMInstanceName DeviceManagementConfigurationPolicyAssignments
                if ($complexTypeStringResult)
                {
                    $Results.Assignments = $complexTypeStringResult
                }
                else
                {
                    $Results.Remove('Assignments') | Out-Null
                }
            }
            $currentDSCBlock = Get-M365DSCExportContentForResource -ResourceName $ResourceName `
                -ConnectionMode $ConnectionMode `
                -ModulePath $PSScriptRoot `
                -Results $Results `
                -Credential $Credential
            if ($Results.AttackSurfaceReductionRules)
            {
                $currentDSCBlock = Convert-DSCStringParamToVariable -DSCBlock $currentDSCBlock -ParameterName "AttackSurfaceReductionRules" -isCIMArray:$True
            }
            if ($Results.Assignments)
            {
                $currentDSCBlock = Convert-DSCStringParamToVariable -DSCBlock $currentDSCBlock -ParameterName "Assignments" -isCIMArray:$true
            }
            #removing trailing commas and semi colons between items of an array of cim instances added by Convert-DSCStringParamToVariable
            $currentDSCBlock = Remove-M365DSCCimInstanceTrailingCharacterFromExport -DSCBlock $currentDSCBlock
            $dscContent += $currentDSCBlock
            Save-M365DSCPartialExport -Content $currentDSCBlock `
                -FileName $Global:PartialExportFileName
            $i++
            Write-Host $Global:M365DSCEmojiGreenCheckMark
        }
        return $dscContent
    }
    catch
    {
        Write-Host $Global:M365DSCEmojiRedX

        New-M365DSCLogEntry -Message 'Error during Export:' `
            -Exception $_ `
            -Source $($MyInvocation.MyCommand.Source) `
            -TenantId $TenantId `
            -Credential $Credential

        return ''
    }
}

function Update-DeviceConfigurationPolicyAssignment
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = 'true')]
        [System.String]
        $DeviceConfigurationPolicyId,

        [Parameter()]
        [Array]
        $Targets,

        [Parameter()]
        [System.String]
        $Repository = 'deviceManagement/configurationPolicies',

        [Parameter()]
        [ValidateSet('v1.0','beta')]
        [System.String]
        $APIVersion = 'beta'
    )
    try
    {
        $deviceManagementPolicyAssignments = @()
        $Uri = "https://graph.microsoft.com/$APIVersion/$Repository/$DeviceConfigurationPolicyId/assign"

        foreach ($target in $targets)
        {
            $formattedTarget = @{"@odata.type" = $target.dataType}
            if ($target.groupId)
            {
                $formattedTarget.Add('groupId',$target.groupId)
            }
            if ($target.collectionId)
            {
                $formattedTarget.Add('collectionId',$target.collectionId)
            }
            if ($target.deviceAndAppManagementAssignmentFilterType)
            {
                $formattedTarget.Add('deviceAndAppManagementAssignmentFilterType',$target.deviceAndAppManagementAssignmentFilterType)
            }
            if ($target.deviceAndAppManagementAssignmentFilterId)
            {
                $formattedTarget.Add('deviceAndAppManagementAssignmentFilterId',$target.deviceAndAppManagementAssignmentFilterId)
            }
            $deviceManagementPolicyAssignments += @{'target' = $formattedTarget}
        }
        $body = @{'assignments' = $deviceManagementPolicyAssignments} | ConvertTo-Json -Depth 20
        #write-verbose -Message $body
        Invoke-MgGraphRequest -Method POST -Uri $Uri -Body $body -ErrorAction Stop
    }
    catch
    {
        New-M365DSCLogEntry -Message 'Error updating data:' `
            -Exception $_ `
            -Source $($MyInvocation.MyCommand.Source) `
            -TenantId $TenantId `
            -Credential $Credential

        return $null
    }
}

Export-ModuleMember -Function *-TargetResource
