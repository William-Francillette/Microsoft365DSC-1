function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        #region resource generator code
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
        $getValue = Get-MgDeviceManagementConfigurationPolicy -DeviceManagementConfigurationPolicyId $Id  -ErrorAction SilentlyContinue

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
        $complexAttackSurfaceReductionRules = @()
        foreach ($currentattackSurfaceReductionRules in $getValue.AdditionalProperties.attackSurfaceReductionRules)
        {
            $myattackSurfaceReductionRules = @{}
            $complexBlockAdobeReaderFromCreatingChildProcesses = @{}
            $complexBlockAdobeReaderFromCreatingChildProcesses.Add('ASROnlyPerRuleExclusions', $currentattackSurfaceReductionRules.blockAdobeReaderFromCreatingChildProcesses.aSROnlyPerRuleExclusions)
            if ($null -ne $currentattackSurfaceReductionRules.blockAdobeReaderFromCreatingChildProcesses.blockAdobeReaderFromCreatingChildProcesses)
            {
                $complexBlockAdobeReaderFromCreatingChildProcesses.Add('BlockAdobeReaderFromCreatingChildProcesses', $currentattackSurfaceReductionRules.blockAdobeReaderFromCreatingChildProcesses.blockAdobeReaderFromCreatingChildProcesses.toString())
            }
            if ($complexBlockAdobeReaderFromCreatingChildProcesses.values.Where({$null -ne $_}).count -eq 0)
            {
                $complexBlockAdobeReaderFromCreatingChildProcesses = $null
            }
            $myattackSurfaceReductionRules.Add('BlockAdobeReaderFromCreatingChildProcesses',$complexBlockAdobeReaderFromCreatingChildProcesses)
            $complexBlockExecutionOfPotentiallyObfuscatedScripts = @{}
            $complexBlockExecutionOfPotentiallyObfuscatedScripts.Add('ASROnlyPerRuleExclusions', $currentattackSurfaceReductionRules.blockExecutionOfPotentiallyObfuscatedScripts.aSROnlyPerRuleExclusions)
            if ($null -ne $currentattackSurfaceReductionRules.blockExecutionOfPotentiallyObfuscatedScripts.blockExecutionOfPotentiallyObfuscatedScripts)
            {
                $complexBlockExecutionOfPotentiallyObfuscatedScripts.Add('BlockExecutionOfPotentiallyObfuscatedScripts', $currentattackSurfaceReductionRules.blockExecutionOfPotentiallyObfuscatedScripts.blockExecutionOfPotentiallyObfuscatedScripts.toString())
            }
            if ($complexBlockExecutionOfPotentiallyObfuscatedScripts.values.Where({$null -ne $_}).count -eq 0)
            {
                $complexBlockExecutionOfPotentiallyObfuscatedScripts = $null
            }
            $myattackSurfaceReductionRules.Add('BlockExecutionOfPotentiallyObfuscatedScripts',$complexBlockExecutionOfPotentiallyObfuscatedScripts)
            $complexBlockWin32APICallsFromOfficeMacros = @{}
            $complexBlockWin32APICallsFromOfficeMacros.Add('ASROnlyPerRuleExclusions', $currentattackSurfaceReductionRules.blockWin32APICallsFromOfficeMacros.aSROnlyPerRuleExclusions)
            if ($null -ne $currentattackSurfaceReductionRules.blockWin32APICallsFromOfficeMacros.blockWin32APICallsFromOfficeMacros)
            {
                $complexBlockWin32APICallsFromOfficeMacros.Add('BlockWin32APICallsFromOfficeMacros', $currentattackSurfaceReductionRules.blockWin32APICallsFromOfficeMacros.blockWin32APICallsFromOfficeMacros.toString())
            }
            if ($complexBlockWin32APICallsFromOfficeMacros.values.Where({$null -ne $_}).count -eq 0)
            {
                $complexBlockWin32APICallsFromOfficeMacros = $null
            }
            $myattackSurfaceReductionRules.Add('BlockWin32APICallsFromOfficeMacros',$complexBlockWin32APICallsFromOfficeMacros)
            $complexBlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = @{}
            $complexBlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem.Add('ASROnlyPerRuleExclusions', $currentattackSurfaceReductionRules.blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem.aSROnlyPerRuleExclusions)
            if ($null -ne $currentattackSurfaceReductionRules.blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem.blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem)
            {
                $complexBlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem.Add('BlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem', $currentattackSurfaceReductionRules.blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem.blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem.toString())
            }
            if ($complexBlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem.values.Where({$null -ne $_}).count -eq 0)
            {
                $complexBlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = $null
            }
            $myattackSurfaceReductionRules.Add('BlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem',$complexBlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem)
            $complexBlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = @{}
            $complexBlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion.Add('ASROnlyPerRuleExclusions', $currentattackSurfaceReductionRules.blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion.aSROnlyPerRuleExclusions)
            if ($null -ne $currentattackSurfaceReductionRules.blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion.blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion)
            {
                $complexBlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion.Add('BlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion', $currentattackSurfaceReductionRules.blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion.blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion.toString())
            }
            if ($complexBlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion.values.Where({$null -ne $_}).count -eq 0)
            {
                $complexBlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = $null
            }
            $myattackSurfaceReductionRules.Add('BlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion',$complexBlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion)
            $complexBlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = @{}
            $complexBlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent.Add('ASROnlyPerRuleExclusions', $currentattackSurfaceReductionRules.blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent.aSROnlyPerRuleExclusions)
            if ($null -ne $currentattackSurfaceReductionRules.blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent.blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent)
            {
                $complexBlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent.Add('BlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent', $currentattackSurfaceReductionRules.blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent.blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent.toString())
            }
            if ($complexBlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent.values.Where({$null -ne $_}).count -eq 0)
            {
                $complexBlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = $null
            }
            $myattackSurfaceReductionRules.Add('BlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent',$complexBlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent)
            $complexBlockOfficeCommunicationAppFromCreatingChildProcesses = @{}
            $complexBlockOfficeCommunicationAppFromCreatingChildProcesses.Add('ASROnlyPerRuleExclusions', $currentattackSurfaceReductionRules.blockOfficeCommunicationAppFromCreatingChildProcesses.aSROnlyPerRuleExclusions)
            if ($null -ne $currentattackSurfaceReductionRules.blockOfficeCommunicationAppFromCreatingChildProcesses.blockOfficeCommunicationAppFromCreatingChildProcesses)
            {
                $complexBlockOfficeCommunicationAppFromCreatingChildProcesses.Add('BlockOfficeCommunicationAppFromCreatingChildProcesses', $currentattackSurfaceReductionRules.blockOfficeCommunicationAppFromCreatingChildProcesses.blockOfficeCommunicationAppFromCreatingChildProcesses.toString())
            }
            if ($complexBlockOfficeCommunicationAppFromCreatingChildProcesses.values.Where({$null -ne $_}).count -eq 0)
            {
                $complexBlockOfficeCommunicationAppFromCreatingChildProcesses = $null
            }
            $myattackSurfaceReductionRules.Add('BlockOfficeCommunicationAppFromCreatingChildProcesses',$complexBlockOfficeCommunicationAppFromCreatingChildProcesses)
            $complexBlockAllOfficeApplicationsFromCreatingChildProcesses = @{}
            $complexBlockAllOfficeApplicationsFromCreatingChildProcesses.Add('ASROnlyPerRuleExclusions', $currentattackSurfaceReductionRules.blockAllOfficeApplicationsFromCreatingChildProcesses.aSROnlyPerRuleExclusions)
            if ($null -ne $currentattackSurfaceReductionRules.blockAllOfficeApplicationsFromCreatingChildProcesses.blockAllOfficeApplicationsFromCreatingChildProcesses)
            {
                $complexBlockAllOfficeApplicationsFromCreatingChildProcesses.Add('BlockAllOfficeApplicationsFromCreatingChildProcesses', $currentattackSurfaceReductionRules.blockAllOfficeApplicationsFromCreatingChildProcesses.blockAllOfficeApplicationsFromCreatingChildProcesses.toString())
            }
            if ($complexBlockAllOfficeApplicationsFromCreatingChildProcesses.values.Where({$null -ne $_}).count -eq 0)
            {
                $complexBlockAllOfficeApplicationsFromCreatingChildProcesses = $null
            }
            $myattackSurfaceReductionRules.Add('BlockAllOfficeApplicationsFromCreatingChildProcesses',$complexBlockAllOfficeApplicationsFromCreatingChildProcesses)
            $complexBlockUntrustedUnsignedProcessesThatRunFromUSB = @{}
            $complexBlockUntrustedUnsignedProcessesThatRunFromUSB.Add('ASROnlyPerRuleExclusions', $currentattackSurfaceReductionRules.blockUntrustedUnsignedProcessesThatRunFromUSB.aSROnlyPerRuleExclusions)
            if ($null -ne $currentattackSurfaceReductionRules.blockUntrustedUnsignedProcessesThatRunFromUSB.blockUntrustedUnsignedProcessesThatRunFromUSB)
            {
                $complexBlockUntrustedUnsignedProcessesThatRunFromUSB.Add('BlockUntrustedUnsignedProcessesThatRunFromUSB', $currentattackSurfaceReductionRules.blockUntrustedUnsignedProcessesThatRunFromUSB.blockUntrustedUnsignedProcessesThatRunFromUSB.toString())
            }
            if ($complexBlockUntrustedUnsignedProcessesThatRunFromUSB.values.Where({$null -ne $_}).count -eq 0)
            {
                $complexBlockUntrustedUnsignedProcessesThatRunFromUSB = $null
            }
            $myattackSurfaceReductionRules.Add('BlockUntrustedUnsignedProcessesThatRunFromUSB',$complexBlockUntrustedUnsignedProcessesThatRunFromUSB)
            $complexBlockProcessCreationsFromPSExecAndWMICommands = @{}
            $complexBlockProcessCreationsFromPSExecAndWMICommands.Add('ASROnlyPerRuleExclusions', $currentattackSurfaceReductionRules.blockProcessCreationsFromPSExecAndWMICommands.aSROnlyPerRuleExclusions)
            if ($null -ne $currentattackSurfaceReductionRules.blockProcessCreationsFromPSExecAndWMICommands.blockProcessCreationsFromPSExecAndWMICommands)
            {
                $complexBlockProcessCreationsFromPSExecAndWMICommands.Add('BlockProcessCreationsFromPSExecAndWMICommands', $currentattackSurfaceReductionRules.blockProcessCreationsFromPSExecAndWMICommands.blockProcessCreationsFromPSExecAndWMICommands.toString())
            }
            if ($complexBlockProcessCreationsFromPSExecAndWMICommands.values.Where({$null -ne $_}).count -eq 0)
            {
                $complexBlockProcessCreationsFromPSExecAndWMICommands = $null
            }
            $myattackSurfaceReductionRules.Add('BlockProcessCreationsFromPSExecAndWMICommands',$complexBlockProcessCreationsFromPSExecAndWMICommands)
            if ($null -ne $currentattackSurfaceReductionRules.blockPersistenceThroughWMIEventSubscription)
            {
                $myattackSurfaceReductionRules.Add('BlockPersistenceThroughWMIEventSubscription', $currentattackSurfaceReductionRules.blockPersistenceThroughWMIEventSubscription.toString())
            }
            $complexBlockOfficeApplicationsFromCreatingExecutableContent = @{}
            $complexBlockOfficeApplicationsFromCreatingExecutableContent.Add('ASROnlyPerRuleExclusions', $currentattackSurfaceReductionRules.blockOfficeApplicationsFromCreatingExecutableContent.aSROnlyPerRuleExclusions)
            if ($null -ne $currentattackSurfaceReductionRules.blockOfficeApplicationsFromCreatingExecutableContent.blockOfficeApplicationsFromCreatingExecutableContent)
            {
                $complexBlockOfficeApplicationsFromCreatingExecutableContent.Add('BlockOfficeApplicationsFromCreatingExecutableContent', $currentattackSurfaceReductionRules.blockOfficeApplicationsFromCreatingExecutableContent.blockOfficeApplicationsFromCreatingExecutableContent.toString())
            }
            if ($complexBlockOfficeApplicationsFromCreatingExecutableContent.values.Where({$null -ne $_}).count -eq 0)
            {
                $complexBlockOfficeApplicationsFromCreatingExecutableContent = $null
            }
            $myattackSurfaceReductionRules.Add('BlockOfficeApplicationsFromCreatingExecutableContent',$complexBlockOfficeApplicationsFromCreatingExecutableContent)
            $complexBlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = @{}
            $complexBlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses.Add('ASROnlyPerRuleExclusions', $currentattackSurfaceReductionRules.blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses.aSROnlyPerRuleExclusions)
            if ($null -ne $currentattackSurfaceReductionRules.blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses.blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses)
            {
                $complexBlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses.Add('BlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses', $currentattackSurfaceReductionRules.blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses.blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses.toString())
            }
            if ($complexBlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses.values.Where({$null -ne $_}).count -eq 0)
            {
                $complexBlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = $null
            }
            $myattackSurfaceReductionRules.Add('BlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses',$complexBlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses)
            $complexUseAdvancedProtectionAgainstRansomware = @{}
            $complexUseAdvancedProtectionAgainstRansomware.Add('ASROnlyPerRuleExclusions', $currentattackSurfaceReductionRules.useAdvancedProtectionAgainstRansomware.aSROnlyPerRuleExclusions)
            if ($null -ne $currentattackSurfaceReductionRules.useAdvancedProtectionAgainstRansomware.useAdvancedProtectionAgainstRansomware)
            {
                $complexUseAdvancedProtectionAgainstRansomware.Add('UseAdvancedProtectionAgainstRansomware', $currentattackSurfaceReductionRules.useAdvancedProtectionAgainstRansomware.useAdvancedProtectionAgainstRansomware.toString())
            }
            if ($complexUseAdvancedProtectionAgainstRansomware.values.Where({$null -ne $_}).count -eq 0)
            {
                $complexUseAdvancedProtectionAgainstRansomware = $null
            }
            $myattackSurfaceReductionRules.Add('UseAdvancedProtectionAgainstRansomware',$complexUseAdvancedProtectionAgainstRansomware)
            $complexBlockExecutableContentFromEmailClientAndWebmail = @{}
            $complexBlockExecutableContentFromEmailClientAndWebmail.Add('ASROnlyPerRuleExclusions', $currentattackSurfaceReductionRules.blockExecutableContentFromEmailClientAndWebmail.aSROnlyPerRuleExclusions)
            if ($null -ne $currentattackSurfaceReductionRules.blockExecutableContentFromEmailClientAndWebmail.blockExecutableContentFromEmailClientAndWebmail)
            {
                $complexBlockExecutableContentFromEmailClientAndWebmail.Add('BlockExecutableContentFromEmailClientAndWebmail', $currentattackSurfaceReductionRules.blockExecutableContentFromEmailClientAndWebmail.blockExecutableContentFromEmailClientAndWebmail.toString())
            }
            if ($complexBlockExecutableContentFromEmailClientAndWebmail.values.Where({$null -ne $_}).count -eq 0)
            {
                $complexBlockExecutableContentFromEmailClientAndWebmail = $null
            }
            $myattackSurfaceReductionRules.Add('BlockExecutableContentFromEmailClientAndWebmail',$complexBlockExecutableContentFromEmailClientAndWebmail)
            $complexBlockAbuseOfExploitedVulnerableSignedDrivers = @{}
            $complexBlockAbuseOfExploitedVulnerableSignedDrivers.Add('ASROnlyPerRuleExclusions', $currentattackSurfaceReductionRules.blockAbuseOfExploitedVulnerableSignedDrivers.aSROnlyPerRuleExclusions)
            if ($null -ne $currentattackSurfaceReductionRules.blockAbuseOfExploitedVulnerableSignedDrivers.blockAbuseOfExploitedVulnerableSignedDrivers)
            {
                $complexBlockAbuseOfExploitedVulnerableSignedDrivers.Add('BlockAbuseOfExploitedVulnerableSignedDrivers', $currentattackSurfaceReductionRules.blockAbuseOfExploitedVulnerableSignedDrivers.blockAbuseOfExploitedVulnerableSignedDrivers.toString())
            }
            if ($complexBlockAbuseOfExploitedVulnerableSignedDrivers.values.Where({$null -ne $_}).count -eq 0)
            {
                $complexBlockAbuseOfExploitedVulnerableSignedDrivers = $null
            }
            $myattackSurfaceReductionRules.Add('BlockAbuseOfExploitedVulnerableSignedDrivers',$complexBlockAbuseOfExploitedVulnerableSignedDrivers)
            if ($myattackSurfaceReductionRules.values.Where({$null -ne $_}).count -gt 0)
            {
                $complexAttackSurfaceReductionRules += $myattackSurfaceReductionRules
            }
        }

        #endregion

        #region resource generator code
        $enumEnableControlledFolderAccess = $null
        if ($null -ne $getValue.AdditionalProperties.enableControlledFolderAccess)
        {
            $enumEnableControlledFolderAccess = $getValue.AdditionalProperties.enableControlledFolderAccess.ToString()
        }
        #endregion

        $results = @{
            #region resource generator code
            AttackSurfaceReductionRules               = $complexAttackSurfaceReductionRules
            AttackSurfaceReductionOnlyExclusions      = $getValue.AdditionalProperties.attackSurfaceReductionOnlyExclusions
            EnableControlledFolderAccess              = $enumEnableControlledFolderAccess
            ControlledFolderAccessProtectedFolders    = $getValue.AdditionalProperties.controlledFolderAccessProtectedFolders
            ControlledFolderAccessAllowedApplications = $getValue.AdditionalProperties.controlledFolderAccessAllowedApplications
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
                        CimInstanceName = 'MicrosoftGraphBlockAdobeReaderFromCreatingChildProcesses_KeyValuePair'
                        IsRequired = $False
                    }
                    @{
                        Name = 'BlockExecutionOfPotentiallyObfuscatedScripts'
                        CimInstanceName = 'MicrosoftGraphBlockExecutionOfPotentiallyObfuscatedScripts_KeyValuePair'
                        IsRequired = $False
                    }
                    @{
                        Name = 'BlockWin32APICallsFromOfficeMacros'
                        CimInstanceName = 'MicrosoftGraphBlockWin32APICallsFromOfficeMacros_KeyValuePair'
                        IsRequired = $False
                    }
                    @{
                        Name = 'BlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem'
                        CimInstanceName = 'MicrosoftGraphBlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem_KeyValuePair'
                        IsRequired = $False
                    }
                    @{
                        Name = 'BlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion'
                        CimInstanceName = 'MicrosoftGraphBlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion_KeyValuePair'
                        IsRequired = $False
                    }
                    @{
                        Name = 'BlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent'
                        CimInstanceName = 'MicrosoftGraphBlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent_KeyValuePair'
                        IsRequired = $False
                    }
                    @{
                        Name = 'BlockOfficeCommunicationAppFromCreatingChildProcesses'
                        CimInstanceName = 'MicrosoftGraphBlockOfficeCommunicationAppFromCreatingChildProcesses_KeyValuePair'
                        IsRequired = $False
                    }
                    @{
                        Name = 'BlockAllOfficeApplicationsFromCreatingChildProcesses'
                        CimInstanceName = 'MicrosoftGraphBlockAllOfficeApplicationsFromCreatingChildProcesses_KeyValuePair'
                        IsRequired = $False
                    }
                    @{
                        Name = 'BlockUntrustedUnsignedProcessesThatRunFromUSB'
                        CimInstanceName = 'MicrosoftGraphBlockUntrustedUnsignedProcessesThatRunFromUSB_KeyValuePair'
                        IsRequired = $False
                    }
                    @{
                        Name = 'BlockProcessCreationsFromPSExecAndWMICommands'
                        CimInstanceName = 'MicrosoftGraphBlockProcessCreationsFromPSExecAndWMICommands_KeyValuePair'
                        IsRequired = $False
                    }
                    @{
                        Name = 'BlockOfficeApplicationsFromCreatingExecutableContent'
                        CimInstanceName = 'MicrosoftGraphBlockOfficeApplicationsFromCreatingExecutableContent_KeyValuePair'
                        IsRequired = $False
                    }
                    @{
                        Name = 'BlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses'
                        CimInstanceName = 'MicrosoftGraphBlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses_KeyValuePair'
                        IsRequired = $False
                    }
                    @{
                        Name = 'UseAdvancedProtectionAgainstRansomware'
                        CimInstanceName = 'MicrosoftGraphUseAdvancedProtectionAgainstRansomware_KeyValuePair'
                        IsRequired = $False
                    }
                    @{
                        Name = 'BlockExecutableContentFromEmailClientAndWebmail'
                        CimInstanceName = 'MicrosoftGraphBlockExecutableContentFromEmailClientAndWebmail_KeyValuePair'
                        IsRequired = $False
                    }
                    @{
                        Name = 'BlockAbuseOfExploitedVulnerableSignedDrivers'
                        CimInstanceName = 'MicrosoftGraphBlockAbuseOfExploitedVulnerableSignedDrivers_KeyValuePair'
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
            $currentDSCBlock = $currentDSCBlock.replace("    ,`r`n" , "    `r`n" )
            $currentDSCBlock = $currentDSCBlock.replace("`r`n;`r`n" , "`r`n" )
            $currentDSCBlock = $currentDSCBlock.replace("`r`n,`r`n" , "`r`n" )
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
