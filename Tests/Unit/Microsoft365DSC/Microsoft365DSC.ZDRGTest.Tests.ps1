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
                            blockProcessCreationsFromPSExecAndWMICommands = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockProcessCreationsFromPSExecAndWMICommands_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockOfficeCommunicationAppFromCreatingChildProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockOfficeCommunicationAppFromCreatingChildProcesses_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockExecutionOfPotentiallyObfuscatedScripts = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockExecutionOfPotentiallyObfuscatedScripts_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockExecutableContentFromEmailClientAndWebmail = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockExecutableContentFromEmailClientAndWebmail_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            useAdvancedProtectionAgainstRansomware = (New-CimInstance -ClassName MSFT_MicrosoftGraphUseAdvancedProtectionAgainstRansomware_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockUntrustedUnsignedProcessesThatRunFromUSB = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockUntrustedUnsignedProcessesThatRunFromUSB_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockOfficeApplicationsFromCreatingExecutableContent = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockOfficeApplicationsFromCreatingExecutableContent_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockWin32APICallsFromOfficeMacros = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockWin32APICallsFromOfficeMacros_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockAllOfficeApplicationsFromCreatingChildProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockAllOfficeApplicationsFromCreatingChildProcesses_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockPersistenceThroughWMIEventSubscription = "off"
                            blockAbuseOfExploitedVulnerableSignedDrivers = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockAbuseOfExploitedVulnerableSignedDrivers_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockAdobeReaderFromCreatingChildProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockAdobeReaderFromCreatingChildProcesses_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                        } -ClientOnly)
                    )
                    controlledFolderAccessAllowedApplications = @("FakeStringValue")
                    controlledFolderAccessProtectedFolders = @("FakeStringValue")
                    Id = "FakeStringValue"
                    Name = "FakeStringValue"
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
                            blockProcessCreationsFromPSExecAndWMICommands = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockProcessCreationsFromPSExecAndWMICommands_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockOfficeCommunicationAppFromCreatingChildProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockOfficeCommunicationAppFromCreatingChildProcesses_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockExecutionOfPotentiallyObfuscatedScripts = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockExecutionOfPotentiallyObfuscatedScripts_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockExecutableContentFromEmailClientAndWebmail = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockExecutableContentFromEmailClientAndWebmail_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            useAdvancedProtectionAgainstRansomware = (New-CimInstance -ClassName MSFT_MicrosoftGraphUseAdvancedProtectionAgainstRansomware_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockUntrustedUnsignedProcessesThatRunFromUSB = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockUntrustedUnsignedProcessesThatRunFromUSB_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockOfficeApplicationsFromCreatingExecutableContent = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockOfficeApplicationsFromCreatingExecutableContent_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockWin32APICallsFromOfficeMacros = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockWin32APICallsFromOfficeMacros_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockAllOfficeApplicationsFromCreatingChildProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockAllOfficeApplicationsFromCreatingChildProcesses_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockPersistenceThroughWMIEventSubscription = "off"
                            blockAbuseOfExploitedVulnerableSignedDrivers = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockAbuseOfExploitedVulnerableSignedDrivers_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockAdobeReaderFromCreatingChildProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockAdobeReaderFromCreatingChildProcesses_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                        } -ClientOnly)
                    )
                    controlledFolderAccessAllowedApplications = @("FakeStringValue")
                    controlledFolderAccessProtectedFolders = @("FakeStringValue")
                    Id = "FakeStringValue"
                    Name = "FakeStringValue"
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
                                        value = "off"
                                    }
                                    blockOfficeCommunicationAppFromCreatingChildProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockExecutionOfPotentiallyObfuscatedScripts = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockExecutableContentFromEmailClientAndWebmail = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    useAdvancedProtectionAgainstRansomware = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockUntrustedUnsignedProcessesThatRunFromUSB = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockOfficeApplicationsFromCreatingExecutableContent = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockWin32APICallsFromOfficeMacros = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockAllOfficeApplicationsFromCreatingChildProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockPersistenceThroughWMIEventSubscription = "off"
                                    blockAbuseOfExploitedVulnerableSignedDrivers = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockAdobeReaderFromCreatingChildProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                }
                            )
                            '@odata.type' = "#microsoft.graph.DeviceManagementConfigurationPolicy"
                            attackSurfaceReductionOnlyExclusions = @("FakeStringValue")
                            controlledFolderAccessAllowedApplications = @("FakeStringValue")
                        }
                        Id = "FakeStringValue"
                        Name = "FakeStringValue"

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
                            blockProcessCreationsFromPSExecAndWMICommands = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockProcessCreationsFromPSExecAndWMICommands_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockOfficeCommunicationAppFromCreatingChildProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockOfficeCommunicationAppFromCreatingChildProcesses_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockExecutionOfPotentiallyObfuscatedScripts = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockExecutionOfPotentiallyObfuscatedScripts_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockExecutableContentFromEmailClientAndWebmail = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockExecutableContentFromEmailClientAndWebmail_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            useAdvancedProtectionAgainstRansomware = (New-CimInstance -ClassName MSFT_MicrosoftGraphUseAdvancedProtectionAgainstRansomware_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockUntrustedUnsignedProcessesThatRunFromUSB = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockUntrustedUnsignedProcessesThatRunFromUSB_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockOfficeApplicationsFromCreatingExecutableContent = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockOfficeApplicationsFromCreatingExecutableContent_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockWin32APICallsFromOfficeMacros = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockWin32APICallsFromOfficeMacros_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockAllOfficeApplicationsFromCreatingChildProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockAllOfficeApplicationsFromCreatingChildProcesses_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockPersistenceThroughWMIEventSubscription = "off"
                            blockAbuseOfExploitedVulnerableSignedDrivers = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockAbuseOfExploitedVulnerableSignedDrivers_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockAdobeReaderFromCreatingChildProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockAdobeReaderFromCreatingChildProcesses_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                        } -ClientOnly)
                    )
                    controlledFolderAccessAllowedApplications = @("FakeStringValue")
                    controlledFolderAccessProtectedFolders = @("FakeStringValue")
                    Id = "FakeStringValue"
                    Name = "FakeStringValue"
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
                                        value = "off"
                                    }
                                    blockOfficeCommunicationAppFromCreatingChildProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockExecutionOfPotentiallyObfuscatedScripts = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockExecutableContentFromEmailClientAndWebmail = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    useAdvancedProtectionAgainstRansomware = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockUntrustedUnsignedProcessesThatRunFromUSB = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockOfficeApplicationsFromCreatingExecutableContent = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockWin32APICallsFromOfficeMacros = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockAllOfficeApplicationsFromCreatingChildProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockPersistenceThroughWMIEventSubscription = "off"
                                    blockAbuseOfExploitedVulnerableSignedDrivers = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockAdobeReaderFromCreatingChildProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                }
                            )
                            '@odata.type' = "#microsoft.graph.DeviceManagementConfigurationPolicy"
                            attackSurfaceReductionOnlyExclusions = @("FakeStringValue")
                            controlledFolderAccessAllowedApplications = @("FakeStringValue")
                        }
                        Id = "FakeStringValue"
                        Name = "FakeStringValue"

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
                            blockProcessCreationsFromPSExecAndWMICommands = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockProcessCreationsFromPSExecAndWMICommands_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockOfficeCommunicationAppFromCreatingChildProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockOfficeCommunicationAppFromCreatingChildProcesses_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockExecutionOfPotentiallyObfuscatedScripts = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockExecutionOfPotentiallyObfuscatedScripts_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockExecutableContentFromEmailClientAndWebmail = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockExecutableContentFromEmailClientAndWebmail_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            useAdvancedProtectionAgainstRansomware = (New-CimInstance -ClassName MSFT_MicrosoftGraphUseAdvancedProtectionAgainstRansomware_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockUntrustedUnsignedProcessesThatRunFromUSB = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockUntrustedUnsignedProcessesThatRunFromUSB_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockOfficeApplicationsFromCreatingExecutableContent = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockOfficeApplicationsFromCreatingExecutableContent_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockWin32APICallsFromOfficeMacros = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockWin32APICallsFromOfficeMacros_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockAllOfficeApplicationsFromCreatingChildProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockAllOfficeApplicationsFromCreatingChildProcesses_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockPersistenceThroughWMIEventSubscription = "off"
                            blockAbuseOfExploitedVulnerableSignedDrivers = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockAbuseOfExploitedVulnerableSignedDrivers_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                            blockAdobeReaderFromCreatingChildProcesses = (New-CimInstance -ClassName MSFT_MicrosoftGraphBlockAdobeReaderFromCreatingChildProcesses_Complex -Property @{
                                aSROnlyPerRuleExclusions = @("FakeStringValue")
                                value = "off"
                            } -ClientOnly)
                        } -ClientOnly)
                    )
                    controlledFolderAccessAllowedApplications = @("FakeStringValue")
                    controlledFolderAccessProtectedFolders = @("FakeStringValue")
                    Id = "FakeStringValue"
                    Name = "FakeStringValue"
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
                                        value = "block"
                                    }
                                    blockOfficeCommunicationAppFromCreatingChildProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        value = "block"
                                    }
                                    blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        value = "block"
                                    }
                                    blockExecutionOfPotentiallyObfuscatedScripts = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        value = "block"
                                    }
                                    blockExecutableContentFromEmailClientAndWebmail = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        value = "block"
                                    }
                                    useAdvancedProtectionAgainstRansomware = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        value = "block"
                                    }
                                    blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        value = "block"
                                    }
                                    blockUntrustedUnsignedProcessesThatRunFromUSB = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        value = "block"
                                    }
                                    blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        value = "block"
                                    }
                                    blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        value = "block"
                                    }
                                    blockOfficeApplicationsFromCreatingExecutableContent = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        value = "block"
                                    }
                                    blockWin32APICallsFromOfficeMacros = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        value = "block"
                                    }
                                    blockAllOfficeApplicationsFromCreatingChildProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        value = "block"
                                    }
                                    blockPersistenceThroughWMIEventSubscription = "block"
                                    blockAbuseOfExploitedVulnerableSignedDrivers = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        value = "block"
                                    }
                                    blockAdobeReaderFromCreatingChildProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValueDrift")
                                        value = "block"
                                    }
                                }
                            )
                            attackSurfaceReductionOnlyExclusions = @("FakeStringValueDrift")
                            enableControlledFolderAccess = 1
                            controlledFolderAccessAllowedApplications = @("FakeStringValueDrift")
                        }
                        Id = "FakeStringValueDrift"
                        Name = "FakeStringValueDrift"
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
                                        value = "off"
                                    }
                                    blockOfficeCommunicationAppFromCreatingChildProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockExecutableFilesRunningUnlessTheyMeetPrevalenceAgeTrustedListCriterion = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockExecutionOfPotentiallyObfuscatedScripts = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockExecutableContentFromEmailClientAndWebmail = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    useAdvancedProtectionAgainstRansomware = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockUntrustedUnsignedProcessesThatRunFromUSB = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockOfficeApplicationsFromInjectingCodeIntoOtherProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockCredentialStealingFromWindowsLocalSecurityAuthoritySubsystem = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockOfficeApplicationsFromCreatingExecutableContent = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockWin32APICallsFromOfficeMacros = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockAllOfficeApplicationsFromCreatingChildProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockPersistenceThroughWMIEventSubscription = "off"
                                    blockAbuseOfExploitedVulnerableSignedDrivers = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                    blockAdobeReaderFromCreatingChildProcesses = @{
                                        aSROnlyPerRuleExclusions = @("FakeStringValue")
                                        value = "off"
                                    }
                                }
                            )
                            '@odata.type' = "#microsoft.graph.DeviceManagementConfigurationPolicy"
                            attackSurfaceReductionOnlyExclusions = @("FakeStringValue")
                            controlledFolderAccessAllowedApplications = @("FakeStringValue")
                        }
                        Id = "FakeStringValue"
                        Name = "FakeStringValue"

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
