<#
This example is used to test new resources and showcase the usage of new resources being worked on.
It is not meant to use as a production baseline.
#>

Configuration Example
{
    param(
        [Parameter(Mandatory = $true)]
        [PSCredential]
        $Credscredential
    )
    Import-DscResource -ModuleName Microsoft365DSC

    node localhost
    {
        ZDRGTest 'Example'
        {
            Assignments          = @();
            Credential           = $Credscredential;
            Description          = "";
            Ensure               = "Present";
            Id                   = "6c1dcee0-99be-44ed-9b96-4f9b35be0537";
            Name                 = "asr sc";
            Platforms            = "windows10";
            SettingCount         = 1;
            Settings             = @(
                MSFT_MicrosoftGraphdeviceManagementConfigurationSetting4{
                    SettingInstance = MSFT_MicrosoftGraphDeviceManagementConfigurationSettingInstance2{
                        groupSettingCollectionValue = @(
                            MSFT_MicrosoftGraphDeviceManagementConfigurationGroupSettingValue1{
                                Children = @(
                                    MSFT_MicrosoftGraphDeviceManagementConfigurationSettingInstance2{
                                        choiceSettingValue = MSFT_MicrosoftGraphDeviceManagementConfigurationChoiceSettingValue1{
                                            Children = @(
                                                MSFT_MicrosoftGraphDeviceManagementConfigurationSettingInstance2{
                                                    SettingDefinitionId = 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockadobereaderfromcreatingchildprocesses_perruleexclusions'
                                                    simpleSettingCollectionValue = @(
                                                        MSFT_MicrosoftGraphDeviceManagementConfigurationSimpleSettingValue1{
                                                            odataType = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'
                                                            StringValue = 'sf'
                                                        }

                                                        MSFT_MicrosoftGraphDeviceManagementConfigurationSimpleSettingValue1{
                                                            odataType = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'
                                                            StringValue = 'fff'
                                                        }

                                                        MSFT_MicrosoftGraphDeviceManagementConfigurationSimpleSettingValue1{
                                                            odataType = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'
                                                            StringValue = 'sff'
                                                        }
                                                    )
                                                    odataType = '#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance'
                                                }
                                            )
                                            Value = 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockadobereaderfromcreatingchildprocesses_block'
                                        }
                                        SettingDefinitionId = 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockadobereaderfromcreatingchildprocesses'
                                        odataType = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                                    }

                                    MSFT_MicrosoftGraphDeviceManagementConfigurationSettingInstance2{
                                        choiceSettingValue = MSFT_MicrosoftGraphDeviceManagementConfigurationChoiceSettingValue1{
                                            Value = 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts_audit'
                                        }
                                        SettingDefinitionId = 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts'
                                        odataType = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                                    }
                                )
                            }
                        )
                        SettingDefinitionId = 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules'
                        odataType = '#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance'
                    }
                }
            );
            Technologies         = "mdm,microsoftSense";
            TemplateReference    = MSFT_MicrosoftGraphdeviceManagementConfigurationPolicyTemplateReference1{
                TemplateId = 'e8c053d6-9f95-42b1-a7f1-ebfd71c67a4b_1'
            };
        }
    }
}
