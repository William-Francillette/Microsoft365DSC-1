[CmdletBinding()]
param(
)
$M365DSCTestFolder = Join-Path -Path $PSScriptRoot `
                        -ChildPath '..\..\Unit' `
                        -Resolve
$CmdletModule = (Join-Path -Path $M365DSCTestFolder `
            -ChildPath '\Stubs\Microsoft365.psm1' `
            -Resolve)
$GenericStubPath = (Join-Path -Path $M365DSCTestFolder `
    -ChildPath '\Stubs\Generic.psm1' `
    -Resolve)
Import-Module -Name (Join-Path -Path $M365DSCTestFolder `
        -ChildPath '\UnitTestHelper.psm1' `
        -Resolve)

$Global:DscHelper = New-M365DscUnitTestHelper -StubModule $CmdletModule `
    -DscResource "ZDRGTest" -GenericStubModule $GenericStubPath
Describe -Name $Global:DscHelper.DescribeHeader -Fixture {
    InModuleScope -ModuleName $Global:DscHelper.ModuleName -ScriptBlock {
        Invoke-Command -ScriptBlock $Global:DscHelper.InitializeScript -NoNewScope
        BeforeAll {

            $secpasswd = ConvertTo-SecureString "f@kepassword1" -AsPlainText -Force
            $Credential = New-Object System.Management.Automation.PSCredential ('tenantadmin@mydomain.com', $secpasswd)

            Mock -CommandName Confirm-M365DSCDependencies -MockWith {
            }

            Mock -CommandName Get-PSSession -MockWith {
            }

            Mock -CommandName Remove-PSSession -MockWith {
            }

            Mock -CommandName Update-MgDeviceManagementConfigurationPolicy -MockWith {
            }

            Mock -CommandName New-MgDeviceManagementConfigurationPolicy -MockWith {
            }

            Mock -CommandName Remove-MgDeviceManagementConfigurationPolicy -MockWith {
            }

            Mock -CommandName New-M365DSCConnection -MockWith {
                return "Credentials"
            }

            # Mock Write-Host to hide output during the tests
            Mock -CommandName Write-Host -MockWith {
            }

            Mock -CommandName Get-MgDeviceManagementConfigurationPolicyAssignment -MockWith {
            }

        }
        # Test contexts
        Context -Name "The ZDRGTest should exist but it DOES NOT" -Fixture {
            BeforeAll {
                $testParams = @{
                    attackSurfaceReductionOnlyExclusions = @("FakeStringValue")
                    attackSurfaceReductionRules = [CimInstance[]]@(
                        (New-CimInstance -ClassName MSFT_MicrosoftGraphAttackSurfaceReductionRules_Complex -Property @{
                            blockProcessCreationsFromPSExecAndWMICommands = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockProcessCreationsFromPSExecAndWMICommands_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockProcessCreationsFromPSExecAndWMICommands = "off"
                            } -ClientOnly)
                            blockOfficeCommunicationAppFromCreatingChildProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockOfficeCommunicationAppFromCreatingChildProcesses_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockOfficeCommunicationAppFromCreatingChildProcesses = "off"
                            } -ClientOnly)
                            blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = "off"
                            } -ClientOnly)
                            blockExecutionOfPotentiallyObfuscatedScripts = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockExecutionOfPotentiallyObfuscatedScripts_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockExecutionOfPotentiallyObfuscatedScripts = "off"
                            } -ClientOnly)
                            blockExecutableContentFromEmailClientAndWebmail = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockExecutableContentFromEmailClientAndWebmail_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockExecutableContentFromEmailClientAndWebmail = "off"
                            } -ClientOnly)
                            useAdvancedProtectionAgainstRansomware = (New-CimInstance -ClassName MSFT_MicrosoftGraphUseAdvancedProtectionAgainstRansomware_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                useAdvancedProtectionAgainstRansomware = "off"
                            } -ClientOnly)
                            blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = "off"
                            } -ClientOnly)
                            blockUntrustedUnsignedProcessesThatRunFromUSB = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockUntrustedUnsignedProcessesThatRunFromUSB_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockUntrustedUnsignedProcessesThatRunFromUSB = "off"
                            } -ClientOnly)
                            blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = "off"
                            } -ClientOnly)
                            blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = "off"
                            } -ClientOnly)
                            blockOfficeApplicationsFromCreatingExecutableContent = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockOfficeApplicationsFromCreatingExecutableContent_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockOfficeApplicationsFromCreatingExecutableContent = "off"
                            } -ClientOnly)
                            blockWin32APICallsFromOfficeMacros = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockWin32APICallsFromOfficeMacros_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockWin32APICallsFromOfficeMacros = "off"
                            } -ClientOnly)
                            blockAllOfficeApplicationsFromCreatingChildProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockAllOfficeApplicationsFromCreatingChildProcesses_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockAllOfficeApplicationsFromCreatingChildProcesses = "off"
                            } -ClientOnly)
                            blockPersistenceThroughWMIEventSubscription = "off"
                            blockAbuseOfExploitedVulnerableSignedDrivers = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockAbuseOfExploitedVulnerableSignedDrivers_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockAbuseOfExploitedVulnerableSignedDrivers = "off"
                            } -ClientOnly)
                            blockAdobeReaderFromCreatingChildProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockAdobeReaderFromCreatingChildProcesses_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockAdobeReaderFromCreatingChildProcesses = "off"
                            } -ClientOnly)
                        } -ClientOnly)
                    )
                    controlledFolderAccessAllowedApplications = @("FakeStringValue")
                    controlledFolderAccessProtectedFolders = @("FakeStringValue")
                    Ensure = "Present"
                    Credential = $Credential;
                }

                Mock -CommandName Get-MgDeviceManagementConfigurationPolicy -MockWith {
                    return $null
                }
            }
            It 'Should return Values from the Get method' {
                (Get-TargetResource @testParams).Ensure | Should -Be 'Absent'
            }
            It 'Should return false from the Test method' {
                Test-TargetResource @testParams | Should -Be $false
            }
            It 'Should Create the group from the Set method' {
                Set-TargetResource @testParams
                Should -Invoke -CommandName New-MgDeviceManagementConfigurationPolicy -Exactly 1
            }
        }

        Context -Name "The ZDRGTest exists but it SHOULD NOT" -Fixture {
            BeforeAll {
                $testParams = @{
                    attackSurfaceReductionOnlyExclusions = @("FakeStringValue")
                    attackSurfaceReductionRules = [CimInstance[]]@(
                        (New-CimInstance -ClassName MSFT_MicrosoftGraphAttackSurfaceReductionRules_Complex -Property @{
                            blockProcessCreationsFromPSExecAndWMICommands = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockProcessCreationsFromPSExecAndWMICommands_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockProcessCreationsFromPSExecAndWMICommands = "off"
                            } -ClientOnly)
                            blockOfficeCommunicationAppFromCreatingChildProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockOfficeCommunicationAppFromCreatingChildProcesses_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockOfficeCommunicationAppFromCreatingChildProcesses = "off"
                            } -ClientOnly)
                            blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = "off"
                            } -ClientOnly)
                            blockExecutionOfPotentiallyObfuscatedScripts = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockExecutionOfPotentiallyObfuscatedScripts_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockExecutionOfPotentiallyObfuscatedScripts = "off"
                            } -ClientOnly)
                            blockExecutableContentFromEmailClientAndWebmail = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockExecutableContentFromEmailClientAndWebmail_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockExecutableContentFromEmailClientAndWebmail = "off"
                            } -ClientOnly)
                            useAdvancedProtectionAgainstRansomware = (New-CimInstance -ClassName MSFT_MicrosoftGraphUseAdvancedProtectionAgainstRansomware_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                useAdvancedProtectionAgainstRansomware = "off"
                            } -ClientOnly)
                            blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = "off"
                            } -ClientOnly)
                            blockUntrustedUnsignedProcessesThatRunFromUSB = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockUntrustedUnsignedProcessesThatRunFromUSB_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockUntrustedUnsignedProcessesThatRunFromUSB = "off"
                            } -ClientOnly)
                            blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = "off"
                            } -ClientOnly)
                            blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = "off"
                            } -ClientOnly)
                            blockOfficeApplicationsFromCreatingExecutableContent = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockOfficeApplicationsFromCreatingExecutableContent_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockOfficeApplicationsFromCreatingExecutableContent = "off"
                            } -ClientOnly)
                            blockWin32APICallsFromOfficeMacros = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockWin32APICallsFromOfficeMacros_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockWin32APICallsFromOfficeMacros = "off"
                            } -ClientOnly)
                            blockAllOfficeApplicationsFromCreatingChildProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockAllOfficeApplicationsFromCreatingChildProcesses_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockAllOfficeApplicationsFromCreatingChildProcesses = "off"
                            } -ClientOnly)
                            blockPersistenceThroughWMIEventSubscription = "off"
                            blockAbuseOfExploitedVulnerableSignedDrivers = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockAbuseOfExploitedVulnerableSignedDrivers_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockAbuseOfExploitedVulnerableSignedDrivers = "off"
                            } -ClientOnly)
                            blockAdobeReaderFromCreatingChildProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockAdobeReaderFromCreatingChildProcesses_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockAdobeReaderFromCreatingChildProcesses = "off"
                            } -ClientOnly)
                        } -ClientOnly)
                    )
                    controlledFolderAccessAllowedApplications = @("FakeStringValue")
                    controlledFolderAccessProtectedFolders = @("FakeStringValue")
                    Ensure = 'Absent'
                    Credential = $Credential;
                }

                Mock -CommandName Get-MgDeviceManagementConfigurationPolicy -MockWith {
                    return @{
                        AdditionalProperties = @{
                            controlledFolderAccessProtectedFolders = @("FakeStringValue")
                            attackSurfaceReductionRules = @(
                                @{
                                    blockProcessCreationsFromPSExecAndWMICommands = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockProcessCreationsFromPSExecAndWMICommands = "off"
                                    }
                                    blockOfficeCommunicationAppFromCreatingChildProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockOfficeCommunicationAppFromCreatingChildProcesses = "off"
                                    }
                                    blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = "off"
                                    }
                                    blockExecutionOfPotentiallyObfuscatedScripts = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockExecutionOfPotentiallyObfuscatedScripts = "off"
                                    }
                                    blockExecutableContentFromEmailClientAndWebmail = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockExecutableContentFromEmailClientAndWebmail = "off"
                                    }
                                    useAdvancedProtectionAgainstRansomware = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        useAdvancedProtectionAgainstRansomware = "off"
                                    }
                                    blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = "off"
                                    }
                                    blockUntrustedUnsignedProcessesThatRunFromUSB = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockUntrustedUnsignedProcessesThatRunFromUSB = "off"
                                    }
                                    blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = "off"
                                    }
                                    blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = "off"
                                    }
                                    blockOfficeApplicationsFromCreatingExecutableContent = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockOfficeApplicationsFromCreatingExecutableContent = "off"
                                    }
                                    blockWin32APICallsFromOfficeMacros = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockWin32APICallsFromOfficeMacros = "off"
                                    }
                                    blockAllOfficeApplicationsFromCreatingChildProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockAllOfficeApplicationsFromCreatingChildProcesses = "off"
                                    }
                                    blockPersistenceThroughWMIEventSubscription = "off"
                                    blockAbuseOfExploitedVulnerableSignedDrivers = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockAbuseOfExploitedVulnerableSignedDrivers = "off"
                                    }
                                    blockAdobeReaderFromCreatingChildProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockAdobeReaderFromCreatingChildProcesses = "off"
                                    }
                                }
                            )
                            '@odata.type' = "#microsoft.graph.DeviceManagementConfigurationPolicy"
                            attackSurfaceReductionOnlyExclusions = @("FakeStringValue")
                            controlledFolderAccessAllowedApplications = @("FakeStringValue")
                        }

                    }
                }
            }

            It 'Should return Values from the Get method' {
                (Get-TargetResource @testParams).Ensure | Should -Be 'Present'
            }

            It 'Should return true from the Test method' {
                Test-TargetResource @testParams | Should -Be $false
            }

            It 'Should Remove the group from the Set method' {
                Set-TargetResource @testParams
                Should -Invoke -CommandName Remove-MgDeviceManagementConfigurationPolicy -Exactly 1
            }
        }
        Context -Name "The ZDRGTest Exists and Values are already in the desired state" -Fixture {
            BeforeAll {
                $testParams = @{
                    attackSurfaceReductionOnlyExclusions = @("FakeStringValue")
                    attackSurfaceReductionRules = [CimInstance[]]@(
                        (New-CimInstance -ClassName MSFT_MicrosoftGraphAttackSurfaceReductionRules_Complex -Property @{
                            blockProcessCreationsFromPSExecAndWMICommands = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockProcessCreationsFromPSExecAndWMICommands_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockProcessCreationsFromPSExecAndWMICommands = "off"
                            } -ClientOnly)
                            blockOfficeCommunicationAppFromCreatingChildProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockOfficeCommunicationAppFromCreatingChildProcesses_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockOfficeCommunicationAppFromCreatingChildProcesses = "off"
                            } -ClientOnly)
                            blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = "off"
                            } -ClientOnly)
                            blockExecutionOfPotentiallyObfuscatedScripts = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockExecutionOfPotentiallyObfuscatedScripts_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockExecutionOfPotentiallyObfuscatedScripts = "off"
                            } -ClientOnly)
                            blockExecutableContentFromEmailClientAndWebmail = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockExecutableContentFromEmailClientAndWebmail_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockExecutableContentFromEmailClientAndWebmail = "off"
                            } -ClientOnly)
                            useAdvancedProtectionAgainstRansomware = (New-CimInstance -ClassName MSFT_MicrosoftGraphUseAdvancedProtectionAgainstRansomware_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                useAdvancedProtectionAgainstRansomware = "off"
                            } -ClientOnly)
                            blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = "off"
                            } -ClientOnly)
                            blockUntrustedUnsignedProcessesThatRunFromUSB = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockUntrustedUnsignedProcessesThatRunFromUSB_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockUntrustedUnsignedProcessesThatRunFromUSB = "off"
                            } -ClientOnly)
                            blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = "off"
                            } -ClientOnly)
                            blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = "off"
                            } -ClientOnly)
                            blockOfficeApplicationsFromCreatingExecutableContent = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockOfficeApplicationsFromCreatingExecutableContent_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockOfficeApplicationsFromCreatingExecutableContent = "off"
                            } -ClientOnly)
                            blockWin32APICallsFromOfficeMacros = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockWin32APICallsFromOfficeMacros_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockWin32APICallsFromOfficeMacros = "off"
                            } -ClientOnly)
                            blockAllOfficeApplicationsFromCreatingChildProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockAllOfficeApplicationsFromCreatingChildProcesses_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockAllOfficeApplicationsFromCreatingChildProcesses = "off"
                            } -ClientOnly)
                            blockPersistenceThroughWMIEventSubscription = "off"
                            blockAbuseOfExploitedVulnerableSignedDrivers = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockAbuseOfExploitedVulnerableSignedDrivers_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockAbuseOfExploitedVulnerableSignedDrivers = "off"
                            } -ClientOnly)
                            blockAdobeReaderFromCreatingChildProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockAdobeReaderFromCreatingChildProcesses_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockAdobeReaderFromCreatingChildProcesses = "off"
                            } -ClientOnly)
                        } -ClientOnly)
                    )
                    controlledFolderAccessAllowedApplications = @("FakeStringValue")
                    controlledFolderAccessProtectedFolders = @("FakeStringValue")
                    Ensure = 'Present'
                    Credential = $Credential;
                }

                Mock -CommandName Get-MgDeviceManagementConfigurationPolicy -MockWith {
                    return @{
                        AdditionalProperties = @{
                            controlledFolderAccessProtectedFolders = @("FakeStringValue")
                            attackSurfaceReductionRules = @(
                                @{
                                    blockProcessCreationsFromPSExecAndWMICommands = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockProcessCreationsFromPSExecAndWMICommands = "off"
                                    }
                                    blockOfficeCommunicationAppFromCreatingChildProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockOfficeCommunicationAppFromCreatingChildProcesses = "off"
                                    }
                                    blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = "off"
                                    }
                                    blockExecutionOfPotentiallyObfuscatedScripts = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockExecutionOfPotentiallyObfuscatedScripts = "off"
                                    }
                                    blockExecutableContentFromEmailClientAndWebmail = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockExecutableContentFromEmailClientAndWebmail = "off"
                                    }
                                    useAdvancedProtectionAgainstRansomware = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        useAdvancedProtectionAgainstRansomware = "off"
                                    }
                                    blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = "off"
                                    }
                                    blockUntrustedUnsignedProcessesThatRunFromUSB = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockUntrustedUnsignedProcessesThatRunFromUSB = "off"
                                    }
                                    blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = "off"
                                    }
                                    blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = "off"
                                    }
                                    blockOfficeApplicationsFromCreatingExecutableContent = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockOfficeApplicationsFromCreatingExecutableContent = "off"
                                    }
                                    blockWin32APICallsFromOfficeMacros = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockWin32APICallsFromOfficeMacros = "off"
                                    }
                                    blockAllOfficeApplicationsFromCreatingChildProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockAllOfficeApplicationsFromCreatingChildProcesses = "off"
                                    }
                                    blockPersistenceThroughWMIEventSubscription = "off"
                                    blockAbuseOfExploitedVulnerableSignedDrivers = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockAbuseOfExploitedVulnerableSignedDrivers = "off"
                                    }
                                    blockAdobeReaderFromCreatingChildProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockAdobeReaderFromCreatingChildProcesses = "off"
                                    }
                                }
                            )
                            '@odata.type' = "#microsoft.graph.DeviceManagementConfigurationPolicy"
                            attackSurfaceReductionOnlyExclusions = @("FakeStringValue")
                            controlledFolderAccessAllowedApplications = @("FakeStringValue")
                        }

                    }
                }
            }


            It 'Should return true from the Test method' {
                Test-TargetResource @testParams | Should -Be $true
            }
        }

        Context -Name "The ZDRGTest exists and values are NOT in the desired state" -Fixture {
            BeforeAll {
                $testParams = @{
                    attackSurfaceReductionOnlyExclusions = @("FakeStringValue")
                    attackSurfaceReductionRules = [CimInstance[]]@(
                        (New-CimInstance -ClassName MSFT_MicrosoftGraphAttackSurfaceReductionRules_Complex -Property @{
                            blockProcessCreationsFromPSExecAndWMICommands = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockProcessCreationsFromPSExecAndWMICommands_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockProcessCreationsFromPSExecAndWMICommands = "off"
                            } -ClientOnly)
                            blockOfficeCommunicationAppFromCreatingChildProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockOfficeCommunicationAppFromCreatingChildProcesses_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockOfficeCommunicationAppFromCreatingChildProcesses = "off"
                            } -ClientOnly)
                            blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = "off"
                            } -ClientOnly)
                            blockExecutionOfPotentiallyObfuscatedScripts = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockExecutionOfPotentiallyObfuscatedScripts_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockExecutionOfPotentiallyObfuscatedScripts = "off"
                            } -ClientOnly)
                            blockExecutableContentFromEmailClientAndWebmail = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockExecutableContentFromEmailClientAndWebmail_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockExecutableContentFromEmailClientAndWebmail = "off"
                            } -ClientOnly)
                            useAdvancedProtectionAgainstRansomware = (New-CimInstance -ClassName MSFT_MicrosoftGraphUseAdvancedProtectionAgainstRansomware_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                useAdvancedProtectionAgainstRansomware = "off"
                            } -ClientOnly)
                            blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = "off"
                            } -ClientOnly)
                            blockUntrustedUnsignedProcessesThatRunFromUSB = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockUntrustedUnsignedProcessesThatRunFromUSB_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockUntrustedUnsignedProcessesThatRunFromUSB = "off"
                            } -ClientOnly)
                            blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = "off"
                            } -ClientOnly)
                            blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = "off"
                            } -ClientOnly)
                            blockOfficeApplicationsFromCreatingExecutableContent = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockOfficeApplicationsFromCreatingExecutableContent_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockOfficeApplicationsFromCreatingExecutableContent = "off"
                            } -ClientOnly)
                            blockWin32APICallsFromOfficeMacros = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockWin32APICallsFromOfficeMacros_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockWin32APICallsFromOfficeMacros = "off"
                            } -ClientOnly)
                            blockAllOfficeApplicationsFromCreatingChildProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockAllOfficeApplicationsFromCreatingChildProcesses_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockAllOfficeApplicationsFromCreatingChildProcesses = "off"
                            } -ClientOnly)
                            blockPersistenceThroughWMIEventSubscription = "off"
                            blockAbuseOfExploitedVulnerableSignedDrivers = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockAbuseOfExploitedVulnerableSignedDrivers_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockAbuseOfExploitedVulnerableSignedDrivers = "off"
                            } -ClientOnly)
                            blockAdobeReaderFromCreatingChildProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockAdobeReaderFromCreatingChildProcesses_KeyValuePair -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                blockAdobeReaderFromCreatingChildProcesses = "off"
                            } -ClientOnly)
                        } -ClientOnly)
                    )
                    controlledFolderAccessAllowedApplications = @("FakeStringValue")
                    controlledFolderAccessProtectedFolders = @("FakeStringValue")
                    Ensure = 'Present'
                    Credential = $Credential;
                }

                Mock -CommandName Get-MgDeviceManagementConfigurationPolicy -MockWith {
                    return @{
                        AdditionalProperties = @{
                            controlledFolderAccessProtectedFolders = @("FakeStringValueDrift")
                            attackSurfaceReductionRules = @(
                                @{
                                    blockProcessCreationsFromPSExecAndWMICommands = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        blockProcessCreationsFromPSExecAndWMICommands = "block"
                                    }
                                    blockOfficeCommunicationAppFromCreatingChildProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        blockOfficeCommunicationAppFromCreatingChildProcesses = "block"
                                    }
                                    blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = "block"
                                    }
                                    blockExecutionOfPotentiallyObfuscatedScripts = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        blockExecutionOfPotentiallyObfuscatedScripts = "block"
                                    }
                                    blockExecutableContentFromEmailClientAndWebmail = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        blockExecutableContentFromEmailClientAndWebmail = "block"
                                    }
                                    useAdvancedProtectionAgainstRansomware = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        useAdvancedProtectionAgainstRansomware = "block"
                                    }
                                    blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = "block"
                                    }
                                    blockUntrustedUnsignedProcessesThatRunFromUSB = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        blockUntrustedUnsignedProcessesThatRunFromUSB = "block"
                                    }
                                    blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = "block"
                                    }
                                    blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = "block"
                                    }
                                    blockOfficeApplicationsFromCreatingExecutableContent = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        blockOfficeApplicationsFromCreatingExecutableContent = "block"
                                    }
                                    blockWin32APICallsFromOfficeMacros = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        blockWin32APICallsFromOfficeMacros = "block"
                                    }
                                    blockAllOfficeApplicationsFromCreatingChildProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        blockAllOfficeApplicationsFromCreatingChildProcesses = "block"
                                    }
                                    blockPersistenceThroughWMIEventSubscription = "block"
                                    blockAbuseOfExploitedVulnerableSignedDrivers = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        blockAbuseOfExploitedVulnerableSignedDrivers = "block"
                                    }
                                    blockAdobeReaderFromCreatingChildProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        blockAdobeReaderFromCreatingChildProcesses = "block"
                                    }
                                }
                            )
                            attackSurfaceReductionOnlyExclusions = @("FakeStringValueDrift")
                            enableControlledFolderAccess = 1
                            controlledFolderAccessAllowedApplications = @("FakeStringValueDrift")
                        }
                    }
                }
            }

            It 'Should return Values from the Get method' {
                (Get-TargetResource @testParams).Ensure | Should -Be 'Present'
            }

            It 'Should return false from the Test method' {
                Test-TargetResource @testParams | Should -Be $false
            }

            It 'Should call the Set method' {
                Set-TargetResource @testParams
                Should -Invoke -CommandName Update-MgDeviceManagementConfigurationPolicy -Exactly 1
            }
        }

        Context -Name 'ReverseDSC Tests' -Fixture {
            BeforeAll {
                $Global:CurrentModeIsExport = $true
                $Global:PartialExportFileName = "$(New-Guid).partial.ps1"
                $testParams = @{
                    Credential = $Credential
                }

                Mock -CommandName Get-MgDeviceManagementConfigurationPolicy -MockWith {
                    return @{
                        AdditionalProperties = @{
                            controlledFolderAccessProtectedFolders = @("FakeStringValue")
                            attackSurfaceReductionRules = @(
                                @{
                                    blockProcessCreationsFromPSExecAndWMICommands = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockProcessCreationsFromPSExecAndWMICommands = "off"
                                    }
                                    blockOfficeCommunicationAppFromCreatingChildProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockOfficeCommunicationAppFromCreatingChildProcesses = "off"
                                    }
                                    blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = "off"
                                    }
                                    blockExecutionOfPotentiallyObfuscatedScripts = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockExecutionOfPotentiallyObfuscatedScripts = "off"
                                    }
                                    blockExecutableContentFromEmailClientAndWebmail = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockExecutableContentFromEmailClientAndWebmail = "off"
                                    }
                                    useAdvancedProtectionAgainstRansomware = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        useAdvancedProtectionAgainstRansomware = "off"
                                    }
                                    blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = "off"
                                    }
                                    blockUntrustedUnsignedProcessesThatRunFromUSB = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockUntrustedUnsignedProcessesThatRunFromUSB = "off"
                                    }
                                    blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = "off"
                                    }
                                    blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = "off"
                                    }
                                    blockOfficeApplicationsFromCreatingExecutableContent = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockOfficeApplicationsFromCreatingExecutableContent = "off"
                                    }
                                    blockWin32APICallsFromOfficeMacros = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockWin32APICallsFromOfficeMacros = "off"
                                    }
                                    blockAllOfficeApplicationsFromCreatingChildProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockAllOfficeApplicationsFromCreatingChildProcesses = "off"
                                    }
                                    blockPersistenceThroughWMIEventSubscription = "off"
                                    blockAbuseOfExploitedVulnerableSignedDrivers = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockAbuseOfExploitedVulnerableSignedDrivers = "off"
                                    }
                                    blockAdobeReaderFromCreatingChildProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        blockAdobeReaderFromCreatingChildProcesses = "off"
                                    }
                                }
                            )
                            '@odata.type' = "#microsoft.graph.DeviceManagementConfigurationPolicy"
                            attackSurfaceReductionOnlyExclusions = @("FakeStringValue")
                            controlledFolderAccessAllowedApplications = @("FakeStringValue")
                        }

                    }
                }
            }
            It 'Should Reverse Engineer resource from the Export method' {
                $result = Export-TargetResource @testParams
                $result | Should -Not -BeNullOrEmpty
            }
        }
    }
}

Invoke-Command -ScriptBlock $Global:DscHelper.CleanupScript -NoNewScope
