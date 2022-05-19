#
# Module manifest for module 'Microsoft365DSC'
#
# Generated by: Microsoft Corporation
#
<<<<<<< HEAD
# Generated on: 2022-04-27
=======
# Generated on: 2022-05-18
>>>>>>> 5cbbb071fe9d1f9f87c15df0bc5d5838f7d59d9a

@{

    # Script module or binary module file associated with this manifest.
    # RootModule = ''

    # Version number of this module.
<<<<<<< HEAD
    ModuleVersion     = '1.22.427.1'
=======
    ModuleVersion     = '1.22.518.1'
>>>>>>> 5cbbb071fe9d1f9f87c15df0bc5d5838f7d59d9a

    # Supported PSEditions
    # CompatiblePSEditions = @()

    # ID used to uniquely identify this module
    GUID              = '39f599a6-d212-4480-83b3-a8ea2124d8cf'

    # Author of this module
    Author            = 'Microsoft Corporation'

    # Company or vendor of this module
    CompanyName       = 'Microsoft Corporation'

    # Copyright statement for this module
    Copyright         = '(c) 2022 Microsoft Corporation. All rights reserved.'

    # Description of the functionality provided by this module
    Description       = 'This DSC module is used to configure and monitor Microsoft tenants, including SharePoint Online, Exchange, Teams, etc.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Name of the PowerShell host required by this module
    # PowerShellHostName = ''

    # Minimum version of the PowerShell host required by this module
    # PowerShellHostVersion = ''

    # Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # DotNetFrameworkVersion = ''

    # Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # CLRVersion = ''

    # Processor architecture (None, X86, Amd64) required by this module
    # ProcessorArchitecture = ''

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules   = @()

    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess = @()

    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
    # FormatsToProcess = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules     = @(
        'modules\M365DSCAgent.psm1',
        'modules\M365DSCErrorHandler.psm1',
        'modules\M365DSCLogEngine.psm1',
        'modules\M365DSCPermissions.psm1',
        'modules\M365DSCReport.psm1',
        'modules\M365DSCReverse.psm1',
        'modules\M365DSCStubsUtility.psm1',
        'modules\M365DSCTelemetryEngine.psm1',
        'modules\M365DSCUtil.psm1',
        'modules\EncodingHelpers\M365DSCEmojis.psm1',
        'modules\EncodingHelpers\M365DSCStringEncoding.psm1'
    )

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    #FunctionsToExport = @()

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport   = @('Assert-M365DSCBlueprint',
        'Assert-M365DSCTemplate',
        'Compare-M365DSCConfigurations',
        'Confirm-M365DSCDependencies',
        'Export-M365DSCConfiguration',
        'Export-M365DSCDiagnosticData',
        'Import-M365DSCDependencies',
        'New-M365DSCDeltaReport',
        'New-M365DSCReportFromConfiguration',
        'New-M365DSCStubFiles',
        'Set-M365DSCAgentCertificateConfiguration',
        'Start-M365DSCConfiguration',
        'Test-M365DSCAgent',
        'Test-M365DSCDependencies',
        'Test-M365DSCDependenciesForNewVersions',
        'Uninstall-M365DSCOutdatedDependencies',
        'Update-M365DSCAllowedGraphScopes',
        'Update-M365DSCDependencies',
        'Update-M365DSCResourcesSettingsJSON')

    # Variables to export from this module
    # VariablesToExport = @()

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport   = @()

    # List of all modules packaged with this module
    # ModuleList = @()

    # List of all files packaged with this module
    # FileList = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData       = @{

        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags         = 'DesiredStateConfiguration', 'DSC', 'DSCResourceKit', 'DSCResource', 'Microsoft365'

            # A URL to the license for this module.
            LicenseUri   = 'https://github.com/Microsoft/Microsoft365DSC/blob/master/LICENSE'

            # A URL to the main website for this project.
            ProjectUri   = 'https://github.com/Microsoft/Microsoft365DSC'

            # A URL to an icon representing this module.
            IconUri      = 'https://github.com/microsoft/Microsoft365DSC/blob/Dev/Modules/Microsoft365DSC/Dependencies/Images/Logo.png?raw=true'

            # ReleaseNotes of this module
<<<<<<< HEAD
            ReleaseNotes = "* AADApplication
            * Fix for Permissions with 'Role,Scope' types.
          * EXOAuthenticationPolicy
            * Fix schema.mof file (FIXES #1896)
          * IntuneAppProtectionPolicyAndroid
            * New resource - (fixes issue #1900 and #1432)
          * IntuneAppProtectionPolicyiOS
            * Fixes #1877
          * DEPENDENCIES
            * Updated Microsoft.PowerApps.Administration.PowerShell to version 2.0.146.
          * MISC
            * Performance updates when doing exports (using StringBuilder over
              appending to string)."
=======
            ReleaseNotes = "* AADConditionalAccessPolicy
            * Fixed export to remove the DeviceFilterMode property
              when empty.
          * EXODataClassification
            * Initial release
          * EXODataEncryptionPolicy
            * Initial release
          * PPTenantIsolationSettings
            * Fixed an issue where credentials weren't passed properly
              during the export.
          * SPOSharingSettings
            * Decoupeling from SPOSharingSettings: add SharingCapability for -my sites aka: OneDrive"
>>>>>>> 5cbbb071fe9d1f9f87c15df0bc5d5838f7d59d9a

            # Flag to indicate whether the module requires explicit user acceptance for install/update
            # RequireLicenseAcceptance = $false

            # External dependent modules of this module
            # ExternalModuleDependencies = @()

        } # End of PSData hashtable

    } # End of PrivateData hashtable

    # HelpInfo URI of this module
    # HelpInfoURI = ''

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''
}
