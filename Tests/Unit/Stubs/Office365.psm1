﻿<# Microsoft.Online.SharePoint.PowerShell #>
 
function Add-SPOGeoAdministrator { 
 [CmdletBinding(DefaultParameterSetName='User')]
param(
    [Parameter(ParameterSetName='Group', Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${GroupAlias},

    [Parameter(ParameterSetName='User', Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${UserPrincipalName},

    [Parameter(ParameterSetName='ObjectId', Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [guid]
    ${ObjectId})

 
 } 


function Add-SPOHubSiteAssociation { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [object]
    ${Site},

    [Parameter(Mandatory=$true)]
    [object]
    ${HubSite})

 
 } 


function Add-SPOSiteCollectionAppCatalog { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [Parameter(Mandatory=$true)]
    [object]
    ${Site})

 
 } 


function Add-SPOSiteDesign { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${Title},

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${WebTemplate},

    [Parameter(Mandatory=$true)]
    [ValidateNotNull()]
    [object]
    ${SiteScripts},

    [string]
    ${Description},

    [string]
    ${PreviewImageUrl},

    [string]
    ${PreviewImageAltText},

    [switch]
    ${IsDefault})

 
 } 


function Add-SPOSiteDesignTask { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [guid]
    ${SiteDesignId},

    [Parameter(Mandatory=$true, Position=1)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${WebUrl})

 
 } 


function Add-SPOSiteScript { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${Title},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${Content},

    [string]
    ${Description})

 
 } 


function Add-SPOTenantCdnOrigin { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true)]
    [string]
    ${OriginUrl},

    [Parameter(Mandatory=$true)]
    [object]
    ${CdnType})

 
 } 


function Add-SPOTenantCentralAssetRepositoryLibrary { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true)]
    [string]
    ${LibraryUrl},

    [Parameter(Mandatory=$true)]
    [string]
    ${DisplayName},

    [string]
    ${ThumbnailUrl},

    [object]
    ${CdnType})

 
 } 


function Add-SPOTheme { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [Alias('Name')]
    [ValidateNotNullOrEmpty()]
    [object]
    ${Identity},

    [Parameter(Mandatory=$true)]
    [object]
    ${Palette},

    [Parameter(Mandatory=$true)]
    [bool]
    ${IsInverted},

    [switch]
    ${Overwrite})

 
 } 


function Add-SPOUser { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=1)]
    [object]
    ${Site},

    [Parameter(Mandatory=$true, Position=2)]
    [string]
    ${LoginName},

    [Parameter(Mandatory=$true, Position=3)]
    [string]
    ${Group})

 
 } 


function Approve-SPOTenantServicePrincipalPermissionGrant { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [Parameter(Mandatory=$true, Position=1)]
    [string]
    ${Resource},

    [Parameter(Mandatory=$true, Position=2)]
    [string]
    ${Scope})

 
 } 


function Approve-SPOTenantServicePrincipalPermissionRequest { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [Parameter(Mandatory=$true)]
    [guid]
    ${RequestId})

 
 } 


function Connect-SPOService { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [ValidateNotNullOrEmpty()]
    [object]
    ${Url},

    [Parameter(Position=1, ValueFromPipeline=$true)]
    [object]
    ${Credential},

    [Parameter(Position=2)]
    [string]
    ${ClientTag},

    [Parameter(ParameterSetName='AuthenticationLocation', Position=3)]
    [object]
    ${Region},

    [Parameter(ParameterSetName='AuthenticationUrl', Mandatory=$true, Position=3)]
    [string]
    ${AuthenticationUrl})

 
 } 


function ConvertTo-SPOMigrationEncryptedPackage { 
 [CmdletBinding()]
param(
    [Parameter(ParameterSetName='ImplicitSourceParameterSet', Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [object]
    ${MigrationSourceLocations},

    [Parameter(ParameterSetName='ExplicitSourceParameterSet', Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${SourceFilesPath},

    [Parameter(ParameterSetName='ExplicitSourceParameterSet', Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${SourcePackagePath},

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [object]
    ${EncryptionParameters},

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${TargetFilesPath},

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${TargetPackagePath},

    [switch]
    ${NoLogFile})

 
 } 


function ConvertTo-SPOMigrationTargetedPackage { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${SourceFilesPath},

    [Parameter(Mandatory=$true, Position=1)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${SourcePackagePath},

    [Parameter(Position=2)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${OutputPackagePath},

    [Parameter(Mandatory=$true, Position=3)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${TargetWebUrl},

    [Parameter(ParameterSetName='DocumentLibraryImport', Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${TargetDocumentLibraryPath},

    [Parameter(ParameterSetName='DocumentLibraryImport')]
    [ValidateNotNullOrEmpty()]
    [string]
    ${TargetDocumentLibrarySubFolderPath},

    [Parameter(ParameterSetName='ListImport', Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${TargetListPath},

    [ValidateNotNullOrEmpty()]
    [string]
    ${UserMappingFile},

    [Parameter(Mandatory=$true)]
    [object]
    ${Credentials},

    [object]
    ${AzureADUserCredentials},

    [switch]
    ${NoAzureADLookup},

    [object]
    ${TargetEnvironment},

    [switch]
    ${ParallelImport},

    [long]
    ${PartitionSizeInBytes},

    [switch]
    ${NoLogFile})

 
 } 


function Deny-SPOTenantServicePrincipalPermissionRequest { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [Parameter(Mandatory=$true)]
    [guid]
    ${RequestId})

 
 } 


function Disable-SPOTenantServicePrincipal { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param()

 
 } 


function Disconnect-SPOService { 
 [CmdletBinding()]
param()

 
 } 


function Enable-SPOTenantServicePrincipal { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param()

 
 } 


function Export-SPOQueryLogs { 
 [CmdletBinding(DefaultParameterSetName='All')]
param(
    [Parameter(Mandatory=$true)]
    [string]
    ${LoginName},

    [System.Nullable[datetime]]
    ${StartTime},

    [string]
    ${OutputFolder})

 
 } 


function Export-SPOUserInfo { 
 [CmdletBinding(DefaultParameterSetName='All')]
param(
    [Parameter(Mandatory=$true)]
    [string]
    ${LoginName},

    [Parameter(Mandatory=$true)]
    [object]
    ${Site},

    [string]
    ${OutputFolder})

 
 } 


function Export-SPOUserProfile { 
 [CmdletBinding(DefaultParameterSetName='All')]
param(
    [Parameter(Mandatory=$true)]
    [string]
    ${LoginName},

    [string]
    ${OutputFolder})

 
 } 


function Get-SPOAppErrors { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=1)]
    [guid]
    ${ProductId},

    [Parameter(Position=2)]
    [datetime]
    ${StartTimeInUtc},

    [Parameter(Position=3)]
    [datetime]
    ${EndTimeInUtc})

 
 } 


function Get-SPOAppInfo { 
 [CmdletBinding()]
param(
    [Parameter(Position=1)]
    [guid]
    ${ProductId},

    [Parameter(Position=2)]
    [string]
    ${Name})

 
 } 


function Get-SPOBrowserIdleSignOut { 
 [CmdletBinding()]
param()

 
 } 


function Get-SPOCrossGeoMovedUsers { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('MoveIn','MoveOut')]
    [string]
    ${Direction})

 
 } 


function Get-SPOCrossGeoMoveReport { 
 [CmdletBinding()]
param(
    [ValidateRange(1, 1000)]
    [uint32]
    ${Limit},

    [datetime]
    ${MoveStartTime},

    [datetime]
    ${MoveEndTime},

    [Parameter(Mandatory=$true)]
    [object]
    ${MoveJobType},

    [object]
    ${MoveState},

    [object]
    ${MoveDirection})

 
 } 


function Get-SPOCrossGeoUsers { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [bool]
    ${ValidDataLocation})

 
 } 


function Get-SPODataEncryptionPolicy { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [object]
    ${Identity})

 
 } 


function Get-SPODeletedSite { 
 [CmdletBinding(DefaultParameterSetName='ParameterSetAllSites')]
param(
    [Parameter(Position=0, ValueFromPipeline=$true)]
    [object]
    ${Identity},

    [string]
    ${Limit},

    [Parameter(ParameterSetName='ParameterSetAllSites')]
    [switch]
    ${IncludePersonalSite},

    [Parameter(ParameterSetName='ParameterSetPersonalSitesOnly', Mandatory=$true)]
    [switch]
    ${IncludeOnlyPersonalSite})

 
 } 


function Get-SPOExternalUser { 
 [CmdletBinding(DefaultParameterSetName='All')]
param(
    [Parameter(ParameterSetName='All', Position=1)]
    [int]
    ${Position},

    [Parameter(ParameterSetName='All', Position=2)]
    [int]
    ${PageSize},

    [Parameter(ParameterSetName='All', Position=3)]
    [string]
    ${Filter},

    [Parameter(ParameterSetName='All', Position=4)]
    [object]
    ${SortOrder},

    [Parameter(ParameterSetName='All', Position=5)]
    [string]
    ${SiteUrl},

    [Parameter(ParameterSetName='All', Position=6)]
    [bool]
    ${ShowOnlyUsersWithAcceptingAccountNotMatchInvitedAccount})

 
 } 


function Get-SPOGeoAdministrator { 
 [CmdletBinding()]
param()

 
 } 


function Get-SPOGeoMoveCrossCompatibilityStatus { 
 [CmdletBinding()]
param()

 
 } 


function Get-SPOGeoStorageQuota { 
 [CmdletBinding()]
param(
    [switch]
    ${AllLocations})

 
 } 


function Get-SPOHideDefaultThemes { 
 [CmdletBinding()]
param()

 
 } 


function Get-SPOHubSite { 
 [CmdletBinding()]
param(
    [Parameter(Position=0, ValueFromPipeline=$true)]
    [object]
    ${Identity})

 
 } 


function Get-SPOMigrationJobProgress { 
 [CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]
    ${TargetWebUrl},

    [Parameter(ParameterSetName='AzureLocationsInline', Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${AzureQueueUri},

    [Parameter(Mandatory=$true)]
    [object]
    ${Credentials},

    [Parameter(ParameterSetName='AzureLocationsImplicit', Mandatory=$true)]
    [object]
    ${MigrationPackageAzureLocations},

    [guid[]]
    ${JobIds},

    [ValidateNotNullOrEmpty()]
    [object]
    ${EncryptionParameters},

    [switch]
    ${DontWaitForEndJob},

    [switch]
    ${NoLogFile})

 
 } 


function Get-SPOMigrationJobStatus { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${TargetWebUrl},

    [ValidateNotNullOrEmpty()]
    [guid]
    ${JobId},

    [Parameter(Mandatory=$true)]
    [object]
    ${Credentials},

    [switch]
    ${NoLogFile})

 
 } 


function Get-SPOMultiGeoCompanyAllowedDataLocation { 
 [CmdletBinding()]
param()

 
 } 


function Get-SPOMultiGeoExperience { 
 [CmdletBinding()]
param()

 
 } 


function Get-SPOPublicCdnOrigins { 
 [CmdletBinding()]
param()

 
 } 


function Get-SPOSite { 
 [CmdletBinding(DefaultParameterSetName='ParamSet1')]
param(
    [Parameter(ParameterSetName='ParamSet1', Position=0, ValueFromPipeline=$true)]
    [Parameter(ParameterSetName='ParamSet3', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [object]
    ${Identity},

    [Parameter(ParameterSetName='ParamSet2')]
    [string]
    ${Filter},

    [Parameter(ParameterSetName='ParamSet2')]
    [Parameter(ParameterSetName='ParamSet1')]
    [string]
    ${Limit},

    [Parameter(ParameterSetName='ParamSet2')]
    [Parameter(ParameterSetName='ParamSet1')]
    [switch]
    ${Detailed},

    [Parameter(ParameterSetName='ParamSet3')]
    [switch]
    ${DisableSharingForNonOwnersStatus},

    [Parameter(ParameterSetName='ParamSet2')]
    [string]
    ${Template},

    [Parameter(ParameterSetName='ParamSet2')]
    [System.Nullable[bool]]
    ${IncludePersonalSite},

    [Parameter(ParameterSetName='ParamSet2')]
    [System.Nullable[bool]]
    ${GroupIdDefined})

 
 } 


function Get-SPOSiteCollectionAppCatalogs { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [object]
    ${Site})

 
 } 


function Get-SPOSiteContentMoveState { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]
    ${SourceSiteUrl})

 
 } 


function Get-SPOSiteDataEncryptionPolicy { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [object]
    ${Identity})

 
 } 


function Get-SPOSiteDesign { 
 [CmdletBinding()]
param(
    [Parameter(Position=0, ValueFromPipeline=$true)]
    [object]
    ${Identity})

 
 } 


function Get-SPOSiteDesignRights { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [ValidateNotNull()]
    [object]
    ${Identity})

 
 } 


function Get-SPOSiteDesignRun { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]
    ${WebUrl},

    [Parameter(Position=1, ValueFromPipeline=$true)]
    [object]
    ${SiteDesignId})

 
 } 


function Get-SPOSiteDesignRunStatus { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [object]
    ${Run})

 
 } 


function Get-SPOSiteDesignTask { 
 [CmdletBinding()]
param(
    [Parameter(Position=0, ValueFromPipeline=$true)]
    [object]
    ${Identity},

    [Parameter(Position=1)]
    [string]
    ${WebUrl})

 
 } 


function Get-SPOSiteGroup { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=1)]
    [object]
    ${Site},

    [Parameter(Position=2)]
    [string]
    ${Group},

    [int]
    ${Limit})

 
 } 


function Get-SPOSiteScript { 
 [CmdletBinding()]
param(
    [Parameter(Position=0, ValueFromPipeline=$true)]
    [object]
    ${Identity})

 
 } 


function Get-SPOSiteScriptFromList { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [string]
    ${ListUrl})

 
 } 


function Get-SPOStorageEntity { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [object]
    ${Site},

    [Parameter(Mandatory=$true, Position=1, ValueFromPipeline=$true)]
    [string]
    ${Key})

 
 } 


function Get-SPOTenant { 
 [CmdletBinding()]
param()

 
 } 


function Get-SPOTenantCdnEnabled { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [object]
    ${CdnType})

 
 } 


function Get-SPOTenantCdnOrigins { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [object]
    ${CdnType})

 
 } 


function Get-SPOTenantCdnPolicies { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [object]
    ${CdnType})

 
 } 


function Get-SPOTenantCentralAssetRepository { 
 [CmdletBinding()]
param()

 
 } 


function Get-SPOTenantContentTypeReplicationParameters { 
 [CmdletBinding()]
param()

 
 } 


function Get-SPOTenantLogEntry { 
 [CmdletBinding(DefaultParameterSetName='SiteSubscriptionId')]
param(
    [Parameter(ParameterSetName='CorrelationId', Mandatory=$true)]
    [guid]
    ${CorrelationId},

    [Parameter(ParameterSetName='Source', Mandatory=$true)]
    [int]
    ${Source},

    [Parameter(ParameterSetName='User', Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${User},

    [Parameter(Position=0)]
    [datetime]
    ${StartTimeInUtc},

    [Parameter(Position=1)]
    [datetime]
    ${EndTimeInUtc},

    [Parameter(Position=2)]
    [ValidateRange(1, 5000)]
    [uint32]
    ${MaxRows})

 
 } 


function Get-SPOTenantLogLastAvailableTimeInUtc { 
 [CmdletBinding()]
param()

 
 } 


function Get-SPOTenantServicePrincipalPermissionGrants { 
 [CmdletBinding()]
param()

 
 } 


function Get-SPOTenantServicePrincipalPermissionRequests { 
 [CmdletBinding()]
param()

 
 } 


function Get-SPOTenantSyncClientRestriction { 
 [CmdletBinding()]
param()

 
 } 


function Get-SPOTenantTaxonomyReplicationParameters { 
 [CmdletBinding()]
param()

 
 } 


function Get-SPOTheme { 
 [CmdletBinding()]
param(
    [Parameter(Position=0, ValueFromPipeline=$true)]
    [string]
    ${Name})

 
 } 


function Get-SPOUnifiedGroup { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${GroupAlias})

 
 } 


function Get-SPOUnifiedGroupMoveState { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]
    ${GroupAlias})

 
 } 


function Get-SPOUser { 
 [CmdletBinding(DefaultParameterSetName='All')]
param(
    [Parameter(Mandatory=$true, Position=1)]
    [object]
    ${Site},

    [Parameter(ParameterSetName='ByGroup', Position=2)]
    [string]
    ${Group},

    [Parameter(ParameterSetName='ByLogin', Position=2)]
    [string]
    ${LoginName},

    [Parameter(ParameterSetName='All', Position=3)]
    [Parameter(ParameterSetName='ByGroup', Position=3)]
    [string]
    ${Limit})

 
 } 


function Get-SPOUserAndContentMoveState { 
 [CmdletBinding(DefaultParameterSetName='MoveReport')]
param(
    [Parameter(ParameterSetName='UserPrincipalName', Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${UserPrincipalName},

    [Parameter(ParameterSetName='OdbMoveId', Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [guid]
    ${OdbMoveId},

    [Parameter(ParameterSetName='MoveReport')]
    [ValidateRange(1, 1000)]
    [uint32]
    ${Limit},

    [Parameter(ParameterSetName='MoveReport')]
    [datetime]
    ${MoveStartTime},

    [Parameter(ParameterSetName='MoveReport')]
    [datetime]
    ${MoveEndTime},

    [Parameter(ParameterSetName='MoveReport')]
    [object]
    ${MoveState},

    [Parameter(ParameterSetName='MoveReport')]
    [object]
    ${MoveDirection})

 
 } 


function Get-SPOUserOneDriveLocation { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]
    ${UserPrincipalName})

 
 } 


function Get-SPOWebTemplate { 
 [CmdletBinding()]
param(
    [Parameter(Position=0)]
    [uint32]
    ${LocaleId},

    [int]
    ${CompatibilityLevel},

    [string]
    ${Name},

    [string]
    ${Title})

 
 } 


function Grant-SPOHubSiteRights { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [Alias('HubSite')]
    [object]
    ${Identity},

    [Parameter(Mandatory=$true)]
    [string[]]
    ${Principals},

    [Parameter(Mandatory=$true)]
    [object]
    ${Rights})

 
 } 


function Grant-SPOSiteDesignRights { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [ValidateNotNull()]
    [object]
    ${Identity},

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string[]]
    ${Principals},

    [Parameter(Mandatory=$true)]
    [object]
    ${Rights})

 
 } 


function Invoke-SPOMigrationEncryptUploadSubmit { 
 [CmdletBinding()]
param(
    [Parameter(ParameterSetName='ImplicitSourceParameterSet', Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [object]
    ${MigrationSourceLocations},

    [Parameter(ParameterSetName='ExplicitSourceParameterSet', Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${SourceFilesPath},

    [Parameter(ParameterSetName='ExplicitSourceParameterSet', Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${SourcePackagePath},

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [object]
    ${Credentials},

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${TargetWebUrl},

    [switch]
    ${NoLogFile},

    [switch]
    ${ParallelUpload})

 
 } 


function Invoke-SPOSiteDesign { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [ValidateNotNull()]
    [object]
    ${Identity},

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${WebUrl})

 
 } 


function New-SPOMigrationEncryptionParameters { 
 [CmdletBinding()]
param()

 
 } 


function New-SPOMigrationPackage { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${SourceFilesPath},

    [Parameter(Mandatory=$true, Position=1)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${OutputPackagePath},

    [Parameter(Position=2)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${TargetWebUrl},

    [Parameter(Position=3)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${TargetDocumentLibraryPath},

    [Parameter(Position=4)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${TargetDocumentLibrarySubFolderPath},

    [switch]
    ${IncludeFileSharePermissions},

    [switch]
    ${ReplaceInvalidCharacters},

    [switch]
    ${IgnoreHidden},

    [switch]
    ${NoLogFile},

    [switch]
    ${NoAzureADLookup})

 
 } 


function New-SPOPublicCdnOrigin { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [string]
    ${Url})

 
 } 


function New-SPOSdnProvider { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [string]
    ${Identity},

    [Parameter(Mandatory=$true, Position=1, ValueFromPipeline=$true)]
    [string]
    ${License})

 
 } 


function New-SPOSite { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [ValidateNotNullOrEmpty()]
    [object]
    ${Url},

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${Owner},

    [Parameter(Mandatory=$true)]
    [long]
    ${StorageQuota},

    [ValidateNotNullOrEmpty()]
    [string]
    ${Title},

    [ValidateNotNullOrEmpty()]
    [string]
    ${Template},

    [uint32]
    ${LocaleId},

    [int]
    ${CompatibilityLevel},

    [double]
    ${ResourceQuota},

    [int]
    ${TimeZoneId},

    [switch]
    ${NoWait})

 
 } 


function New-SPOSiteGroup { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=1)]
    [object]
    ${Site},

    [Parameter(Mandatory=$true, Position=2)]
    [string]
    ${Group},

    [Parameter(Mandatory=$true, Position=4)]
    [string[]]
    ${PermissionLevels})

 
 } 


function Register-SPODataEncryptionPolicy { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [object]
    ${Identity},

    [Parameter(Mandatory=$true)]
    [string]
    ${PrimaryKeyVaultName},

    [Parameter(Mandatory=$true)]
    [string]
    ${PrimaryKeyName},

    [Parameter(Mandatory=$true)]
    [guid]
    ${PrimaryKeyVersion},

    [Parameter(Mandatory=$true)]
    [string]
    ${SecondaryKeyVaultName},

    [Parameter(Mandatory=$true)]
    [string]
    ${SecondaryKeyName},

    [Parameter(Mandatory=$true)]
    [guid]
    ${SecondaryKeyVersion})

 
 } 


function Register-SPOHubSite { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [object]
    ${Site},

    [Parameter(Mandatory=$true)]
    [AllowEmptyCollection()]
    [AllowNull()]
    [string[]]
    ${Principals})

 
 } 


function Remove-SPODeletedSite { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [object]
    ${Identity},

    [switch]
    ${NoWait})

 
 } 


function Remove-SPOExternalUser { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(ParameterSetName='All', Mandatory=$true, Position=1)]
    [string[]]
    ${UniqueIDs})

 
 } 


function Remove-SPOGeoAdministrator { 
 [CmdletBinding(DefaultParameterSetName='User')]
param(
    [Parameter(ParameterSetName='Group', Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${GroupAlias},

    [Parameter(ParameterSetName='User', Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${UserPrincipalName},

    [Parameter(ParameterSetName='ObjectId', Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [guid]
    ${ObjectId})

 
 } 


function Remove-SPOHubSiteAssociation { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [object]
    ${Site})

 
 } 


function Remove-SPOMigrationJob { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${TargetWebUrl},

    [Parameter(Mandatory=$true, Position=1)]
    [ValidateNotNullOrEmpty()]
    [guid]
    ${JobId},

    [Parameter(Mandatory=$true)]
    [object]
    ${Credentials},

    [switch]
    ${NoLogFile})

 
 } 


function Remove-SPOMultiGeoCompanyAllowedDataLocation { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${Location})

 
 } 


function Remove-SPOPublicCdnOrigin { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [string]
    ${Identity})

 
 } 


function Remove-SPOSdnProvider { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param()

 
 } 


function Remove-SPOSite { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [object]
    ${Identity},

    [switch]
    ${NoWait})

 
 } 


function Remove-SPOSiteCollectionAppCatalog { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [object]
    ${Site})

 
 } 


function Remove-SPOSiteCollectionAppCatalogById { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [guid]
    ${SiteId})

 
 } 


function Remove-SPOSiteDesign { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [ValidateNotNull()]
    [object]
    ${Identity})

 
 } 


function Remove-SPOSiteDesignTask { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [object]
    ${Identity})

 
 } 


function Remove-SPOSiteGroup { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=1)]
    [object]
    ${Site},

    [Parameter(Mandatory=$true, Position=2)]
    [string]
    ${Identity})

 
 } 


function Remove-SPOSiteScript { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [ValidateNotNull()]
    [object]
    ${Identity})

 
 } 


function Remove-SPOStorageEntity { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [object]
    ${Site},

    [Parameter(Mandatory=$true, Position=1, ValueFromPipeline=$true)]
    [string]
    ${Key})

 
 } 


function Remove-SPOTenantCdnOrigin { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true)]
    [string]
    ${OriginUrl},

    [Parameter(Mandatory=$true)]
    [object]
    ${CdnType})

 
 } 


function Remove-SPOTenantCentralAssetRepositoryLibrary { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true)]
    [string]
    ${LibraryUrl},

    [Parameter(Mandatory=$true)]
    [bool]
    ${ShouldRemoveFromCdn},

    [object]
    ${CdnType})

 
 } 


function Remove-SPOTenantSyncClientRestriction { 
 [CmdletBinding()]
param()

 
 } 


function Remove-SPOTheme { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [Alias('Name')]
    [object]
    ${Identity})

 
 } 


function Remove-SPOUser { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=1)]
    [object]
    ${Site},

    [Parameter(ParameterSetName='ByLogin', Mandatory=$true, Position=2)]
    [string]
    ${LoginName},

    [Parameter(Position=3)]
    [string]
    ${Group})

 
 } 


function Remove-SPOUserInfo { 
 [CmdletBinding(DefaultParameterSetName='All')]
param(
    [Parameter(Mandatory=$true)]
    [string]
    ${LoginName},

    [Parameter(Mandatory=$true)]
    [object]
    ${Site},

    [string]
    ${RedactName})

 
 } 


function Remove-SPOUserProfile { 
 [CmdletBinding(DefaultParameterSetName='All')]
param(
    [Parameter(Mandatory=$true)]
    [string]
    ${LoginName},

    [string]
    ${UserId})

 
 } 


function Repair-SPOSite { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [object]
    ${Identity},

    [guid]
    ${RuleId},

    [switch]
    ${RunAlways})

 
 } 


function Request-SPOPersonalSite { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [ValidateNotNull()]
    [string[]]
    ${UserEmails},

    [switch]
    ${NoWait})

 
 } 


function Request-SPOUpgradeEvaluationSite { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [object]
    ${Identity},

    [switch]
    ${NoUpgrade},

    [switch]
    ${NoEmail})

 
 } 


function Restore-SPODataEncryptionPolicy { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [object]
    ${Identity},

    [Parameter(Mandatory=$true)]
    [string]
    ${PrimaryKeyVaultName},

    [Parameter(Mandatory=$true)]
    [string]
    ${PrimaryKeyName},

    [Parameter(Mandatory=$true)]
    [guid]
    ${PrimaryKeyVersion},

    [Parameter(Mandatory=$true)]
    [string]
    ${SecondaryKeyVaultName},

    [Parameter(Mandatory=$true)]
    [string]
    ${SecondaryKeyName},

    [Parameter(Mandatory=$true)]
    [guid]
    ${SecondaryKeyVersion})

 
 } 


function Restore-SPODeletedSite { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [ValidateNotNullOrEmpty()]
    [object]
    ${Identity},

    [switch]
    ${NoWait})

 
 } 


function Revoke-SPOHubSiteRights { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [Alias('HubSite')]
    [object]
    ${Identity},

    [Parameter(Mandatory=$true)]
    [string[]]
    ${Principals})

 
 } 


function Revoke-SPOSiteDesignRights { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [ValidateNotNull()]
    [object]
    ${Identity},

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string[]]
    ${Principals})

 
 } 


function Revoke-SPOTenantServicePrincipalPermission { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [Parameter(Mandatory=$true)]
    [string]
    ${ObjectId})

 
 } 


function Revoke-SPOUserSession { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]
    ${User})

 
 } 


function Set-SPOBrowserIdleSignOut { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [bool]
    ${Enabled},

    [timespan]
    ${WarnAfter},

    [timespan]
    ${SignOutAfter})

 
 } 


function Set-SPOGeoStorageQuota { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]
    ${GeoLocation},

    [Parameter(Mandatory=$true)]
    [long]
    ${StorageQuotaMB})

 
 } 


function Set-SPOHideDefaultThemes { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [bool]
    ${HideDefaultThemes})

 
 } 


function Set-SPOHubSite { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [Alias('HubSite')]
    [object]
    ${Identity},

    [string]
    ${Title},

    [string]
    ${LogoUrl},

    [string]
    ${Description},

    [System.Nullable[guid]]
    ${SiteDesignId},

    [System.Nullable[bool]]
    ${RequiresJoinApproval})

 
 } 


function Set-SPOMigrationPackageAzureSource { 
 [CmdletBinding()]
param(
    [Parameter(ParameterSetName='ImplicitSourceImplicitAzure', Mandatory=$true)]
    [Parameter(ParameterSetName='ImplicitSourceExplicitAzure', Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [object]
    ${MigrationSourceLocations},

    [Parameter(ParameterSetName='ExplicitSourceImplicitAzure', Mandatory=$true)]
    [Parameter(ParameterSetName='ExplicitSourceExplicitAzure', Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${SourceFilesPath},

    [Parameter(ParameterSetName='ExplicitSourceExplicitAzure', Mandatory=$true)]
    [Parameter(ParameterSetName='ExplicitSourceImplicitAzure', Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${SourcePackagePath},

    [Parameter(ParameterSetName='ExplicitSourceExplicitAzure')]
    [Parameter(ParameterSetName='ImplicitSourceExplicitAzure')]
    [ValidateNotNullOrEmpty()]
    [string]
    ${FileContainerName},

    [Parameter(ParameterSetName='ExplicitSourceExplicitAzure')]
    [Parameter(ParameterSetName='ImplicitSourceExplicitAzure')]
    [ValidateNotNullOrEmpty()]
    [string]
    ${PackageContainerName},

    [Parameter(ParameterSetName='ImplicitSourceExplicitAzure')]
    [Parameter(ParameterSetName='ExplicitSourceExplicitAzure')]
    [ValidateNotNullOrEmpty()]
    [string]
    ${AzureQueueName},

    [Parameter(ParameterSetName='ImplicitSourceExplicitAzure', Mandatory=$true)]
    [Parameter(ParameterSetName='ExplicitSourceExplicitAzure', Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${AccountName},

    [Parameter(ParameterSetName='ExplicitSourceExplicitAzure', Mandatory=$true)]
    [Parameter(ParameterSetName='ImplicitSourceExplicitAzure', Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${AccountKey},

    [Parameter(ParameterSetName='ExplicitSourceImplicitAzure', Mandatory=$true)]
    [Parameter(ParameterSetName='ImplicitSourceImplicitAzure', Mandatory=$true)]
    [object]
    ${MigrationPackageAzureLocations},

    [ValidateNotNullOrEmpty()]
    [object]
    ${EncryptionParameters},

    [switch]
    ${NoUpload},

    [switch]
    ${NoSnapshotCreation},

    [ValidateNotNullOrEmpty()]
    [object]
    ${EncryptionMetaInfo},

    [switch]
    ${NoLogFile},

    [switch]
    ${Overwrite},

    [switch]
    ${ParallelUpload})

 
 } 


function Set-SPOMultiGeoCompanyAllowedDataLocation { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${Location},

    [Parameter(Mandatory=$true, Position=1)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${InitialDomain})

 
 } 


function Set-SPOMultiGeoExperience { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param()

 
 } 


function Set-SPOSite { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [ValidateNotNullOrEmpty()]
    [object]
    ${Identity},

    [Parameter(ParameterSetName='ParamSet1')]
    [ValidateNotNullOrEmpty()]
    [string]
    ${Owner},

    [Parameter(ParameterSetName='ParamSet1')]
    [ValidateNotNullOrEmpty()]
    [string]
    ${Title},

    [Parameter(ParameterSetName='ParamSet1')]
    [long]
    ${StorageQuota},

    [Parameter(ParameterSetName='ParamSet1')]
    [long]
    ${StorageQuotaWarningLevel},

    [Parameter(ParameterSetName='ParamSet1')]
    [double]
    ${ResourceQuota},

    [Parameter(ParameterSetName='ParamSet1')]
    [double]
    ${ResourceQuotaWarningLevel},

    [Parameter(ParameterSetName='ParamSet1')]
    [uint32]
    ${LocaleId},

    [Parameter(ParameterSetName='ParamSet1')]
    [bool]
    ${AllowSelfServiceUpgrade},

    [Parameter(ParameterSetName='ParamSet4')]
    [Parameter(ParameterSetName='ParamSet1')]
    [switch]
    ${NoWait},

    [Parameter(ParameterSetName='ParamSet1')]
    [string]
    ${LockState},

    [Parameter(ParameterSetName='ParamSet1')]
    [bool]
    ${DenyAddAndCustomizePages},

    [Parameter(ParameterSetName='ParamSet2', Mandatory=$true)]
    [bool]
    ${EnablePWA},

    [Parameter(ParameterSetName='ParamSet1')]
    [System.Nullable[object]]
    ${SharingCapability},

    [Parameter(ParameterSetName='ParamSet1')]
    [bool]
    ${ShowPeoplePickerSuggestionsForGuestUsers},

    [Parameter(ParameterSetName='ParamSet1')]
    [switch]
    ${StorageQuotaReset},

    [Parameter(ParameterSetName='ParamSet1')]
    [System.Nullable[object]]
    ${SandboxedCodeActivationCapability},

    [Parameter(ParameterSetName='ParamSet3')]
    [switch]
    ${DisableSharingForNonOwners},

    [Parameter(ParameterSetName='ParamSet4')]
    [string]
    ${NewUrl},

    [Parameter(ParameterSetName='ParamSet1')]
    [System.Nullable[object]]
    ${DisableCompanyWideSharingLinks},

    [Parameter(ParameterSetName='ParamSet1')]
    [System.Nullable[object]]
    ${SharingDomainRestrictionMode},

    [Parameter(ParameterSetName='ParamSet1')]
    [string]
    ${SharingAllowedDomainList},

    [Parameter(ParameterSetName='ParamSet1')]
    [string]
    ${SharingBlockedDomainList},

    [Parameter(ParameterSetName='ParamSet1')]
    [object]
    ${ConditionalAccessPolicy},

    [Parameter(ParameterSetName='ParamSet1')]
    [bool]
    ${AllowDownloadingNonWebViewableFiles},

    [Parameter(ParameterSetName='ParamSet1')]
    [object]
    ${LimitedAccessFileType},

    [Parameter(ParameterSetName='ParamSet1')]
    [bool]
    ${AllowEditing},

    [Parameter(ParameterSetName='ParamSet1')]
    [guid]
    ${SensitivityLabel},

    [Parameter(ParameterSetName='ParamSet1')]
    [System.Nullable[object]]
    ${DisableAppViews},

    [Parameter(ParameterSetName='ParamSet1')]
    [System.Nullable[object]]
    ${DisableFlows},

    [Parameter(ParameterSetName='ParamSet1')]
    [System.Nullable[object]]
    ${RestrictedToGeo},

    [Parameter(ParameterSetName='ParamSet1')]
    [System.Nullable[bool]]
    ${CommentsOnSitePagesDisabled},

    [Parameter(ParameterSetName='ParamSet1')]
    [switch]
    ${UpdateUserTypeFromAzureAD},

    [Parameter(ParameterSetName='ParamSet1')]
    [System.Nullable[bool]]
    ${SocialBarOnSitePagesDisabled},

    [Parameter(ParameterSetName='ParamSet1')]
    [System.Nullable[guid]]
    ${HubSiteId},

    [Parameter(ParameterSetName='ParamSet1')]
    [System.Nullable[object]]
    ${DefaultSharingLinkType},

    [Parameter(ParameterSetName='ParamSet1')]
    [System.Nullable[object]]
    ${DefaultLinkPermission})

 
 } 


function Set-SPOSiteDesign { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [ValidateNotNull()]
    [object]
    ${Identity},

    [string]
    ${Title},

    [string]
    ${WebTemplate},

    [object]
    ${SiteScripts},

    [string]
    ${Description},

    [string]
    ${PreviewImageUrl},

    [string]
    ${PreviewImageAltText},

    [System.Nullable[bool]]
    ${IsDefault},

    [System.Nullable[int]]
    ${Version})

 
 } 


function Set-SPOSiteGroup { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=1)]
    [object]
    ${Site},

    [Parameter(Mandatory=$true, Position=2)]
    [string]
    ${Identity},

    [Parameter(Position=3)]
    [string]
    ${Name},

    [Parameter(Position=5)]
    [string[]]
    ${PermissionLevelsToAdd},

    [Parameter(Position=6)]
    [string[]]
    ${PermissionLevelsToRemove},

    [Parameter(Position=7)]
    [string]
    ${Owner})

 
 } 


function Set-SPOSiteOffice365Group { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [ValidateNotNullOrEmpty()]
    [object]
    ${Site},

    [Parameter(Mandatory=$true, Position=1)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${DisplayName},

    [Parameter(Mandatory=$true, Position=2)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${Alias},

    [Parameter(Position=3)]
    [switch]
    ${IsPublic},

    [Parameter(Position=4)]
    [string]
    ${Description},

    [Parameter(Position=5)]
    [string]
    ${Classification},

    [Parameter(Position=6)]
    [switch]
    ${KeepOldHomepage})

 
 } 


function Set-SPOSiteScript { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNull()]
    [object]
    ${Identity},

    [ValidateNotNullOrEmpty()]
    [string]
    ${Title},

    [Parameter(ValueFromPipeline=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${Content},

    [string]
    ${Description},

    [System.Nullable[int]]
    ${Version})

 
 } 


function Set-SPOStorageEntity { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [Parameter(Mandatory=$true)]
    [object]
    ${Site},

    [Parameter(Mandatory=$true)]
    [string]
    ${Key},

    [Parameter(Mandatory=$true)]
    [string]
    ${Value},

    [Parameter(Mandatory=$true)]
    [string]
    ${Comments},

    [Parameter(Mandatory=$true)]
    [string]
    ${Description})

 
 } 


function Set-SPOTenant { 
 [CmdletBinding()]
param(
    [int]
    ${MinCompatibilityLevel},

    [int]
    ${MaxCompatibilityLevel},

    [System.Nullable[bool]]
    ${ExternalServicesEnabled},

    [string]
    ${NoAccessRedirectUrl},

    [System.Nullable[object]]
    ${SharingCapability},

    [System.Nullable[bool]]
    ${DisplayStartASiteOption},

    [string]
    ${StartASiteFormUrl},

    [System.Nullable[bool]]
    ${ShowEveryoneClaim},

    [System.Nullable[bool]]
    ${ShowAllUsersClaim},

    [System.Nullable[bool]]
    ${ShowEveryoneExceptExternalUsersClaim},

    [System.Nullable[bool]]
    ${SearchResolveExactEmailOrUPN},

    [System.Nullable[bool]]
    ${OfficeClientADALDisabled},

    [System.Nullable[bool]]
    ${LegacyAuthProtocolsEnabled},

    [System.Nullable[bool]]
    ${RequireAcceptingAccountMatchInvitedAccount},

    [System.Nullable[bool]]
    ${ProvisionSharedWithEveryoneFolder},

    [string]
    ${SignInAccelerationDomain},

    [System.Nullable[bool]]
    ${EnableGuestSignInAcceleration},

    [System.Nullable[bool]]
    ${UsePersistentCookiesForExplorerView},

    [System.Nullable[bool]]
    ${BccExternalSharingInvitations},

    [string]
    ${BccExternalSharingInvitationsList},

    [System.Nullable[bool]]
    ${UserVoiceForFeedbackEnabled},

    [System.Nullable[bool]]
    ${PublicCdnEnabled},

    [string]
    ${PublicCdnAllowedFileTypes},

    [System.Nullable[int]]
    ${RequireAnonymousLinksExpireInDays},

    [string]
    ${SharingAllowedDomainList},

    [string]
    ${SharingBlockedDomainList},

    [System.Nullable[object]]
    ${SharingDomainRestrictionMode},

    [System.Nullable[long]]
    ${OneDriveStorageQuota},

    [System.Nullable[bool]]
    ${OneDriveForGuestsEnabled},

    [System.Nullable[bool]]
    ${IPAddressEnforcement},

    [string]
    ${IPAddressAllowList},

    [System.Nullable[int]]
    ${IPAddressWACTokenLifetime},

    [System.Nullable[bool]]
    ${UseFindPeopleInPeoplePicker},

    [System.Nullable[object]]
    ${DefaultSharingLinkType},

    [System.Nullable[object]]
    ${ODBMembersCanShare},

    [System.Nullable[object]]
    ${ODBAccessRequests},

    [System.Nullable[bool]]
    ${PreventExternalUsersFromResharing},

    [System.Nullable[bool]]
    ${ShowPeoplePickerSuggestionsForGuestUsers},

    [System.Nullable[object]]
    ${FileAnonymousLinkType},

    [System.Nullable[object]]
    ${FolderAnonymousLinkType},

    [System.Nullable[bool]]
    ${NotifyOwnersWhenItemsReshared},

    [System.Nullable[bool]]
    ${NotifyOwnersWhenInvitationsAccepted},

    [System.Nullable[bool]]
    ${NotificationsInOneDriveForBusinessEnabled},

    [System.Nullable[bool]]
    ${NotificationsInSharePointEnabled},

    [System.Nullable[object]]
    ${SpecialCharactersStateInFileFolderNames},

    [System.Nullable[bool]]
    ${OwnerAnonymousNotification},

    [System.Nullable[bool]]
    ${CommentsOnSitePagesDisabled},

    [System.Nullable[bool]]
    ${SocialBarOnSitePagesDisabled},

    [System.Nullable[int]]
    ${OrphanedPersonalSitesRetentionPeriod},

    [System.Nullable[bool]]
    ${PermissiveBrowserFileHandlingOverride},

    [System.Nullable[bool]]
    ${DisallowInfectedFileDownload},

    [System.Nullable[object]]
    ${DefaultLinkPermission},

    [System.Nullable[object]]
    ${ConditionalAccessPolicy},

    [System.Nullable[bool]]
    ${AllowDownloadingNonWebViewableFiles},

    [System.Nullable[object]]
    ${LimitedAccessFileType},

    [System.Nullable[bool]]
    ${AllowEditing},

    [System.Nullable[bool]]
    ${ApplyAppEnforcedRestrictionsToAdHocRecipients},

    [System.Nullable[bool]]
    ${FilePickerExternalImageSearchEnabled},

    [System.Nullable[bool]]
    ${EmailAttestationRequired},

    [System.Nullable[int]]
    ${EmailAttestationReAuthDays},

    [System.Nullable[bool]]
    ${SyncPrivacyProfileProperties},

    [guid[]]
    ${DisabledWebPartIds},

    [string]
    ${OrgNewsSiteUrl},

    [System.Nullable[bool]]
    ${EnableMinimumVersionRequirement})

 
 } 


function Set-SPOTenantCdnEnabled { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [bool]
    ${Enable},

    [object]
    ${CdnType},

    [switch]
    ${NoDefaultOrigins})

 
 } 


function Set-SPOTenantCdnPolicy { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [object]
    ${PolicyType},

    [Parameter(Mandatory=$true)]
    [string]
    ${PolicyValue},

    [Parameter(Mandatory=$true)]
    [object]
    ${CdnType})

 
 } 


function Set-SPOTenantContentTypeReplicationParameters { 
 [CmdletBinding(DefaultParameterSetName='ReplicateSelectedContentTypes')]
param(
    [Parameter(ParameterSetName='ReplicateAllContentTypes', Mandatory=$true)]
    [switch]
    ${ReplicateAllContentTypes},

    [Parameter(ParameterSetName='ReplicateSelectedContentTypes', Mandatory=$true)]
    [AllowEmptyCollection()]
    [string[]]
    ${ReplicatedContentTypes})

 
 } 


function Set-SPOTenantSyncClientRestriction { 
 [CmdletBinding()]
param(
    [Parameter(ParameterSetName='Blocking')]
    [switch]
    ${Enable},

    [Parameter(ParameterSetName='Blocking')]
    [string]
    ${DomainGuids},

    [Parameter(ParameterSetName='Blocking')]
    [switch]
    ${BlockMacSync},

    [Parameter(ParameterSetName='FileExclusion')]
    [string]
    ${ExcludedFileExtensions},

    [Parameter(ParameterSetName='GrooveBlockOptions')]
    [ValidateSet('OptOut','HardOptIn','SoftOptIn')]
    [string]
    ${GrooveBlockOption},

    [Parameter(ParameterSetName='ReportProblemDialogFeature', Mandatory=$true)]
    [bool]
    ${DisableReportProblemDialog})

 
 } 


function Set-SPOTenantTaxonomyReplicationParameters { 
 [CmdletBinding(DefaultParameterSetName='ReplicateSelectedGroups')]
param(
    [Parameter(ParameterSetName='ReplicateAllGroups', Mandatory=$true)]
    [switch]
    ${ReplicateAllGroups},

    [Parameter(ParameterSetName='ReplicateSelectedGroups', Mandatory=$true)]
    [AllowEmptyCollection()]
    [string[]]
    ${ReplicatedGroups})

 
 } 


function Set-SPOUnifiedGroup { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${GroupAlias},

    [Parameter(Mandatory=$true, Position=1)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${PreferredDataLocation})

 
 } 


function Set-SPOUser { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=1)]
    [object]
    ${Site},

    [Parameter(Mandatory=$true, Position=2)]
    [string]
    ${LoginName},

    [Parameter(ParameterSetName='ByLogin', Position=3)]
    [bool]
    ${IsSiteCollectionAdmin},

    [Parameter(ParameterSetName='ByLogin', Position=3)]
    [switch]
    ${UpdateUserTypeFromAzureAD})

 
 } 


function Set-SPOWebTheme { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [Alias('Identity','Name')]
    [object]
    ${Theme},

    [Parameter(Mandatory=$true, Position=1)]
    [object]
    ${Web})

 
 } 


function Start-SPOSiteContentMove { 
 [CmdletBinding(DefaultParameterSetName='UrlAndDestinationDataLocation')]
param(
    [Parameter(ParameterSetName='UrlAndDestinationUrl', Mandatory=$true, Position=0)]
    [Parameter(ParameterSetName='UrlAndDestinationDataLocation', Mandatory=$true, Position=0)]
    [string]
    ${SourceSiteUrl},

    [Parameter(ParameterSetName='UrlAndDestinationDataLocation', Mandatory=$true, Position=1)]
    [string]
    ${DestinationDataLocation},

    [Parameter(ParameterSetName='UrlAndDestinationUrl', Mandatory=$true, Position=1)]
    [string]
    ${DestinationUrl},

    [Parameter(Position=2)]
    [datetime]
    ${PreferredMoveBeginDate},

    [Parameter(Position=3)]
    [datetime]
    ${PreferredMoveEndDate},

    [Parameter(Position=4)]
    [string]
    ${Reserved},

    [Parameter(Position=5)]
    [switch]
    ${ValidationOnly},

    [Parameter(Position=6)]
    [switch]
    ${Force},

    [Parameter(Position=7)]
    [switch]
    ${SuppressMarketplaceAppCheck},

    [Parameter(Position=8)]
    [switch]
    ${SuppressWorkflow2013Check},

    [Parameter(Position=9)]
    [switch]
    ${SuppressAllWarnings})

 
 } 


function Start-SPOSiteRename { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [object]
    ${Identity},

    [Parameter(Mandatory=$true, Position=1)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${NewSiteUrl},

    [Parameter(Position=2)]
    [switch]
    ${SuppressMarketplaceAppCheck},

    [Parameter(Position=3)]
    [switch]
    ${SuppressWorkflow2013Check},

    [Parameter(Position=4)]
    [switch]
    ${SuppressAllWarnings})

 
 } 


function Start-SPOUnifiedGroupMove { 
 [CmdletBinding(DefaultParameterSetName='GroupAliasAndDestinationDataLocation')]
param(
    [Parameter(ParameterSetName='GroupAliasAndDestinationDataLocation', Mandatory=$true, Position=0)]
    [string]
    ${GroupAlias},

    [Parameter(ParameterSetName='GroupAliasAndDestinationDataLocation', Mandatory=$true, Position=1)]
    [string]
    ${DestinationDataLocation},

    [Parameter(Position=2)]
    [datetime]
    ${PreferredMoveBeginDate},

    [Parameter(Position=3)]
    [datetime]
    ${PreferredMoveEndDate},

    [Parameter(Position=4)]
    [string]
    ${Reserved},

    [Parameter(Position=5)]
    [switch]
    ${ValidationOnly},

    [Parameter(Position=6)]
    [switch]
    ${Force},

    [Parameter(Position=7)]
    [switch]
    ${SuppressMarketplaceAppCheck},

    [Parameter(Position=8)]
    [switch]
    ${SuppressWorkflow2013Check},

    [Parameter(Position=9)]
    [switch]
    ${SuppressAllWarnings})

 
 } 


function Start-SPOUserAndContentMove { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=1)]
    [string]
    ${UserPrincipalName},

    [Parameter(Mandatory=$true, Position=2)]
    [string]
    ${DestinationDataLocation},

    [Parameter(Position=3)]
    [datetime]
    ${PreferredMoveBeginDate},

    [Parameter(Position=4)]
    [datetime]
    ${PreferredMoveEndDate},

    [Parameter(Position=5)]
    [string]
    ${Notify},

    [Parameter(Position=6)]
    [string]
    ${Reserved},

    [Parameter(Position=7)]
    [switch]
    ${ValidationOnly})

 
 } 


function Stop-SPOUserAndContentMove { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=1)]
    [string]
    ${UserPrincipalName})

 
 } 


function Submit-SPOMigrationJob { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${TargetWebUrl},

    [Parameter(ParameterSetName='AzureLocationsInline', Mandatory=$true, Position=1)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${FileContainerUri},

    [Parameter(ParameterSetName='AzureLocationsInline', Mandatory=$true, Position=2)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${PackageContainerUri},

    [Parameter(ParameterSetName='AzureLocationsInline')]
    [ValidateNotNullOrEmpty()]
    [string]
    ${AzureQueueUri},

    [Parameter(ParameterSetName='AzureLocationsPipebind', Mandatory=$true, Position=1, ValueFromPipeline=$true)]
    [object]
    ${MigrationPackageAzureLocations},

    [Parameter(Mandatory=$true)]
    [object]
    ${Credentials},

    [switch]
    ${NoLogFile},

    [ValidateNotNullOrEmpty()]
    [object]
    ${EncryptionParameters})

 
 } 


function Test-SPOSite { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [object]
    ${Identity},

    [guid]
    ${RuleId},

    [switch]
    ${RunAlways})

 
 } 


function Unregister-SPOHubSite { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [Alias('HubSite')]
    [object]
    ${Identity},

    [switch]
    ${Force})

 
 } 


function Update-SPODataEncryptionPolicy { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [object]
    ${Identity},

    [Parameter(Mandatory=$true)]
    [string]
    ${KeyVaultName},

    [Parameter(Mandatory=$true)]
    [string]
    ${KeyName},

    [Parameter(Mandatory=$true)]
    [guid]
    ${KeyVersion},

    [Parameter(Mandatory=$true)]
    [object]
    ${KeyType})

 
 } 


function Update-UserType { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=1)]
    [string]
    ${LoginName})

 
 } 


function Upgrade-SPOSite { 
 [CmdletBinding(DefaultParameterSetName='SPSiteById', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [object]
    ${Identity},

    [switch]
    ${VersionUpgrade},

    [switch]
    ${QueueOnly},

    [switch]
    ${NoEmail})

 
 } 

<# MSOnline #>
function Add-MsolAdministrativeUnitMember { 
 [CmdletBinding(DefaultParameterSetName='AddAdministrativeUnitMembers__0')]
param(
    [Parameter(ParameterSetName='AddAdministrativeUnitMembers__0', Mandatory=$true)]
    [guid]
    ${AdministrativeUnitObjectId},

    [Parameter(ParameterSetName='AddAdministrativeUnitMembers__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${AdministrativeUnitMemberObjectId},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Add-MsolForeignGroupToRole { 
 [CmdletBinding(DefaultParameterSetName='AddForeignGroupToRole__0')]
param(
    [Parameter(ParameterSetName='AddForeignGroupToRole__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ForeignGroupObjectId},

    [Parameter(ParameterSetName='AddForeignGroupToRole__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ForeignCompanyObjectId},

    [Parameter(ParameterSetName='AddForeignGroupToRole__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${RoleObjectId},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Add-MsolGroupMember { 
 [CmdletBinding(DefaultParameterSetName='AddGroupMembers__0')]
param(
    [Parameter(ParameterSetName='AddGroupMembers__0', Mandatory=$true)]
    [guid]
    ${GroupObjectId},

    [Parameter(ParameterSetName='AddGroupMembers__0', ValueFromPipelineByPropertyName=$true)]
    [object]
    ${GroupMemberType},

    [Parameter(ParameterSetName='AddGroupMembers__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${GroupMemberObjectId},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Add-MsolRoleMember { 
 [CmdletBinding(DefaultParameterSetName='AddRoleMembers__0')]
param(
    [Parameter(ParameterSetName='AddRoleMembers__0', Mandatory=$true)]
    [guid]
    ${RoleObjectId},

    [Parameter(ParameterSetName='AddRoleMembers__0', ValueFromPipelineByPropertyName=$true)]
    [Parameter(ParameterSetName='AddRoleMembersByRoleName__0', ValueFromPipelineByPropertyName=$true)]
    [object]
    ${RoleMemberType},

    [Parameter(ParameterSetName='AddRoleMembers__0', ValueFromPipelineByPropertyName=$true)]
    [Parameter(ParameterSetName='AddRoleMembersByRoleName__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${RoleMemberObjectId},

    [Parameter(ParameterSetName='AddRoleMembers__0', ValueFromPipelineByPropertyName=$true)]
    [Parameter(ParameterSetName='AddRoleMembersByRoleName__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${RoleMemberEmailAddress},

    [Parameter(ParameterSetName='AddRoleMembersByRoleName__0', Mandatory=$true)]
    [string]
    ${RoleName},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Add-MsolScopedRoleMember { 
 [CmdletBinding(DefaultParameterSetName='AddRoleScopedMembers__0')]
param(
    [Parameter(ParameterSetName='AddRoleScopedMembers__0', Mandatory=$true)]
    [guid]
    ${RoleObjectId},

    [Parameter(ParameterSetName='AddRoleScopedMembers__0', Mandatory=$true)]
    [guid]
    ${AdministrativeUnitObjectId},

    [Parameter(ParameterSetName='AddRoleScopedMembers__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${RoleMemberObjectId},

    [Parameter(ParameterSetName='AddRoleScopedMembers__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${RoleMemberUserPrincipalName},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Confirm-MsolDomain { 
 [CmdletBinding(DefaultParameterSetName='VerifyDomain2__0')]
param(
    [Parameter(ParameterSetName='VerifyDomain2__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${DomainName},

    [Parameter(ParameterSetName='VerifyDomain2__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${SigningCertificate},

    [Parameter(ParameterSetName='VerifyDomain2__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${NextSigningCertificate},

    [Parameter(ParameterSetName='VerifyDomain2__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${LogOffUri},

    [Parameter(ParameterSetName='VerifyDomain2__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${PassiveLogOnUri},

    [Parameter(ParameterSetName='VerifyDomain2__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ActiveLogOnUri},

    [Parameter(ParameterSetName='VerifyDomain2__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${IssuerUri},

    [Parameter(ParameterSetName='VerifyDomain2__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${FederationBrandName},

    [Parameter(ParameterSetName='VerifyDomain2__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${MetadataExchangeUri},

    [Parameter(ParameterSetName='VerifyDomain2__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[object]]
    ${PreferredAuthenticationProtocol},

    [Parameter(ParameterSetName='VerifyDomain2__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${SupportsMfa},

    [Parameter(ParameterSetName='VerifyDomain2__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${DefaultInteractiveAuthenticationMethod},

    [Parameter(ParameterSetName='VerifyDomain2__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${OpenIdConnectDiscoveryEndpoint},

    [Parameter(ParameterSetName='VerifyDomain2__0', ValueFromPipelineByPropertyName=$true)]
    [object]
    ${SigningCertificateUpdateStatus},

    [Parameter(ParameterSetName='VerifyDomain2__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[object]]
    ${PromptLoginBehavior},

    [Parameter(ParameterSetName='VerifyDomain2__0', ValueFromPipelineByPropertyName=$true)]
    [object]
    ${ForceTakeover},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Confirm-MsolEmailVerifiedDomain { 
 [CmdletBinding(DefaultParameterSetName='VerifyEmailVerifiedDomain__0')]
param(
    [Parameter(ParameterSetName='VerifyEmailVerifiedDomain__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${DomainName},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Connect-MsolService { 
 [CmdletBinding(DefaultParameterSetName='None__0')]
param(
    [Parameter(ParameterSetName='Credential')]
    [pscredential]
    ${Credential},

    [Parameter(ParameterSetName='AccessToken')]
    [Alias('AccessToken')]
    [string]
    ${AdGraphAccessToken},

    [Parameter(ParameterSetName='AccessToken')]
    [string]
    ${MsGraphAccessToken},

    [Parameter(ParameterSetName='None__0')]
    [Parameter(ParameterSetName='Credential')]
    [Parameter(ParameterSetName='AccessToken')]
    [object]
    ${AzureEnvironment})

 
 } 


function Convert-MsolDomainToFederated { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [switch]
    ${SupportMultipleDomain},

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${DomainName})

 
 } 


function Convert-MsolDomainToStandard { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [Parameter(Mandatory=$true)]
    [string]
    ${PasswordFile},

    [Parameter(Mandatory=$true)]
    [bool]
    ${SkipUserConversion},

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${DomainName})

 
 } 


function Convert-MsolFederatedUser { 
 [CmdletBinding()]
param(
    [Parameter(ParameterSetName='ConvertFederatedUserToManaged__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${UserPrincipalName},

    [Parameter(ParameterSetName='ConvertFederatedUserToManaged__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${NewPassword},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Disable-MsolDevice { 
 [CmdletBinding(DefaultParameterSetName='DisableDeviceByDeviceId', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [Parameter(ParameterSetName='DisableDeviceByDeviceId', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${DeviceId},

    [switch]
    ${Force},

    [Parameter(ParameterSetName='DisableDeviceByObjectId', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ObjectId})

 
 } 


function Enable-MsolDevice { 
 [CmdletBinding(DefaultParameterSetName='EnableDeviceByDeviceId', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [Parameter(ParameterSetName='EnableDeviceByDeviceId', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${DeviceId},

    [switch]
    ${Force},

    [Parameter(ParameterSetName='EnableDeviceByObjectId', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ObjectId})

 
 } 


function Get-MsolAccountSku { 
 [CmdletBinding(DefaultParameterSetName='ListAccountSkus__0')]
param(
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Get-MsolAdministrativeUnit { 
 [CmdletBinding(DefaultParameterSetName='ListAdministrativeUnits__0')]
param(
    [Parameter(ParameterSetName='GetAdministrativeUnit__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ObjectId},

    [Parameter(ParameterSetName='ListAdministrativeUnits__0')]
    [Parameter(ParameterSetName='All__0')]
    [System.Nullable[guid]]
    ${UserObjectId},

    [Parameter(ParameterSetName='ListAdministrativeUnits__0')]
    [Parameter(ParameterSetName='All__0')]
    [string]
    ${UserPrincipalName},

    [Parameter(ParameterSetName='ListAdministrativeUnits__0')]
    [Parameter(ParameterSetName='All__0')]
    [string]
    ${SearchString},

    [Parameter(ParameterSetName='ListAdministrativeUnits__0')]
    [int]
    ${MaxResults},

    [Parameter(ParameterSetName='All__0', Mandatory=$true)]
    [switch]
    ${All},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Get-MsolAdministrativeUnitMember { 
 [CmdletBinding(DefaultParameterSetName='ListAdministrativeUnitMembers__0')]
param(
    [Parameter(ParameterSetName='ListAdministrativeUnitMembers__0')]
    [Parameter(ParameterSetName='All__0')]
    [guid]
    ${AdministrativeUnitObjectId},

    [Parameter(ParameterSetName='ListAdministrativeUnitMembers__0')]
    [int]
    ${MaxResults},

    [Parameter(ParameterSetName='All__0', Mandatory=$true)]
    [switch]
    ${All},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Get-MsolCompanyAllowedDataLocation { 
 [CmdletBinding()]
param(
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Get-MsolCompanyInformation { 
 [CmdletBinding()]
param(
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Get-MsolContact { 
 [CmdletBinding(DefaultParameterSetName='ListContacts__0')]
param(
    [Parameter(ParameterSetName='GetContact__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ObjectId},

    [Parameter(ParameterSetName='ListContacts__0')]
    [Parameter(ParameterSetName='All__0')]
    [System.Nullable[bool]]
    ${HasErrorsOnly},

    [Parameter(ParameterSetName='ListContacts__0')]
    [Parameter(ParameterSetName='All__0')]
    [string]
    ${SearchString},

    [Parameter(ParameterSetName='ListContacts__0')]
    [int]
    ${MaxResults},

    [Parameter(ParameterSetName='All__0', Mandatory=$true)]
    [switch]
    ${All},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Get-MsolDevice { 
 [CmdletBinding(DefaultParameterSetName='GetDeviceByDeviceName')]
param(
    [Parameter(ParameterSetName='GetDeviceAll', Mandatory=$true)]
    [switch]
    ${All},

    [Parameter(ParameterSetName='GetDeviceAll')]
    [switch]
    ${ReturnRegisteredOwners},

    [Parameter(ParameterSetName='GetDeviceAll')]
    [switch]
    ${IncludeSystemManagedDevices},

    [Parameter(ParameterSetName='GetDeviceAll')]
    [datetime]
    ${LogonTimeBefore},

    [Parameter(ParameterSetName='GetDeviceByDeviceId', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${DeviceId},

    [Parameter(ParameterSetName='GetDeviceByDeviceName', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Name},

    [Parameter(ParameterSetName='GetDeviceByObjectId', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ObjectId},

    [Parameter(ParameterSetName='GetDeviceByRegisteredOwner', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${RegisteredOwnerUpn})

 
 } 


function Get-MsolDeviceRegistrationServicePolicy { 
 [CmdletBinding()]
param()

 
 } 


function Get-MsolDirSyncConfiguration { 
 [CmdletBinding()]
param(
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Get-MsolDirSyncFeatures { 
 [CmdletBinding(DefaultParameterSetName='GetCompanyDirSyncFeatures__0')]
param(
    [Parameter(ParameterSetName='GetCompanyDirSyncFeatures__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Feature},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Get-MsolDirSyncProvisioningError { 
 [CmdletBinding(DefaultParameterSetName='ListDirSyncProvisioningErrors__0')]
param(
    [Parameter(ParameterSetName='ListDirSyncProvisioningErrors__0')]
    [Parameter(ParameterSetName='All__0')]
    [string]
    ${ErrorCategory},

    [Parameter(ParameterSetName='ListDirSyncProvisioningErrors__0')]
    [Parameter(ParameterSetName='All__0')]
    [string]
    ${PropertyName},

    [Parameter(ParameterSetName='ListDirSyncProvisioningErrors__0')]
    [Parameter(ParameterSetName='All__0')]
    [string]
    ${PropertyValue},

    [Parameter(ParameterSetName='ListDirSyncProvisioningErrors__0')]
    [Parameter(ParameterSetName='All__0')]
    [string]
    ${SearchString},

    [Parameter(ParameterSetName='ListDirSyncProvisioningErrors__0')]
    [Parameter(ParameterSetName='All__0')]
    [object]
    ${SortField},

    [Parameter(ParameterSetName='ListDirSyncProvisioningErrors__0')]
    [Parameter(ParameterSetName='All__0')]
    [object]
    ${SortDirection},

    [Parameter(ParameterSetName='ListDirSyncProvisioningErrors__0')]
    [int]
    ${MaxResults},

    [Parameter(ParameterSetName='All__0', Mandatory=$true)]
    [switch]
    ${All},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Get-MsolDomain { 
 [CmdletBinding(DefaultParameterSetName='ListDomains__0')]
param(
    [Parameter(ParameterSetName='GetDomain__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${DomainName},

    [Parameter(ParameterSetName='ListDomains__0')]
    [System.Nullable[object]]
    ${Status},

    [Parameter(ParameterSetName='ListDomains__0')]
    [System.Nullable[object]]
    ${Authentication},

    [Parameter(ParameterSetName='ListDomains__0')]
    [System.Nullable[object]]
    ${Capability},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Get-MsolDomainFederationSettings { 
 [CmdletBinding(DefaultParameterSetName='GetDomainFederationSettings__0')]
param(
    [Parameter(ParameterSetName='GetDomainFederationSettings__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${DomainName},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Get-MsolDomainVerificationDns { 
 [CmdletBinding(DefaultParameterSetName='GetDomainVerificationDns__0')]
param(
    [Parameter(ParameterSetName='GetDomainVerificationDns__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${DomainName},

    [Parameter(ParameterSetName='GetDomainVerificationDns__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[object]]
    ${Mode},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Get-MsolFederationProperty { 
 [CmdletBinding()]
param(
    [switch]
    ${SupportMultipleDomain},

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${DomainName})

 
 } 


function Get-MsolGroup { 
 [CmdletBinding(DefaultParameterSetName='ListGroups__0')]
param(
    [Parameter(ParameterSetName='GetGroup__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ObjectId},

    [Parameter(ParameterSetName='ListGroups__0')]
    [Parameter(ParameterSetName='All__0')]
    [System.Nullable[guid]]
    ${UserObjectId},

    [Parameter(ParameterSetName='ListGroups__0')]
    [Parameter(ParameterSetName='All__0')]
    [switch]
    ${IsAgentRole},

    [Parameter(ParameterSetName='ListGroups__0')]
    [Parameter(ParameterSetName='All__0')]
    [string]
    ${UserPrincipalName},

    [Parameter(ParameterSetName='ListGroups__0')]
    [Parameter(ParameterSetName='All__0')]
    [System.Nullable[object]]
    ${GroupType},

    [Parameter(ParameterSetName='ListGroups__0')]
    [Parameter(ParameterSetName='All__0')]
    [switch]
    ${HasErrorsOnly},

    [Parameter(ParameterSetName='ListGroups__0')]
    [Parameter(ParameterSetName='All__0')]
    [System.Nullable[bool]]
    ${HasLicenseErrorsOnly},

    [Parameter(ParameterSetName='ListGroups__0')]
    [Parameter(ParameterSetName='All__0')]
    [string]
    ${SearchString},

    [Parameter(ParameterSetName='ListGroups__0')]
    [int]
    ${MaxResults},

    [Parameter(ParameterSetName='All__0', Mandatory=$true)]
    [switch]
    ${All},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Get-MsolGroupMember { 
 [CmdletBinding(DefaultParameterSetName='ListGroupMembers__0')]
param(
    [Parameter(ParameterSetName='ListGroupMembers__0')]
    [Parameter(ParameterSetName='All__0')]
    [guid]
    ${GroupObjectId},

    [Parameter(ParameterSetName='ListGroupMembers__0')]
    [Parameter(ParameterSetName='All__0')]
    [AllowEmptyCollection()]
    [string[]]
    ${MemberObjectTypes},

    [Parameter(ParameterSetName='ListGroupMembers__0')]
    [Parameter(ParameterSetName='All__0')]
    [string]
    ${SearchString},

    [Parameter(ParameterSetName='ListGroupMembers__0')]
    [int]
    ${MaxResults},

    [Parameter(ParameterSetName='All__0', Mandatory=$true)]
    [switch]
    ${All},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Get-MsolHasObjectsWithDirSyncProvisioningErrors { 
 [CmdletBinding()]
param(
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Get-MsolPartnerContract { 
 [CmdletBinding(DefaultParameterSetName='ListPartnerContracts__0')]
param(
    [Parameter(ParameterSetName='ListPartnerContracts__0')]
    [Parameter(ParameterSetName='All__0')]
    [string]
    ${DomainName},

    [Parameter(ParameterSetName='ListPartnerContracts__0')]
    [Parameter(ParameterSetName='All__0')]
    [object]
    ${SearchKey},

    [Parameter(ParameterSetName='ListPartnerContracts__0')]
    [int]
    ${MaxResults},

    [Parameter(ParameterSetName='All__0', Mandatory=$true)]
    [switch]
    ${All},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Get-MsolPartnerInformation { 
 [CmdletBinding(DefaultParameterSetName='GetPartnerInformation__0')]
param(
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Get-MsolPasswordPolicy { 
 [CmdletBinding(DefaultParameterSetName='GetPasswordPolicy__0')]
param(
    [Parameter(ParameterSetName='GetPasswordPolicy__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${DomainName},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Get-MsolRole { 
 [CmdletBinding(DefaultParameterSetName='ListRoles__0')]
param(
    [Parameter(ParameterSetName='GetRole__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ObjectId},

    [Parameter(ParameterSetName='GetRoleByName__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${RoleName},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Get-MsolRoleMember { 
 [CmdletBinding(DefaultParameterSetName='ListRoleMembers__0')]
param(
    [Parameter(ParameterSetName='ListRoleMembers__0')]
    [Parameter(ParameterSetName='All__0')]
    [guid]
    ${RoleObjectId},

    [Parameter(ParameterSetName='ListRoleMembers__0')]
    [Parameter(ParameterSetName='All__0')]
    [AllowEmptyCollection()]
    [string[]]
    ${MemberObjectTypes},

    [Parameter(ParameterSetName='ListRoleMembers__0')]
    [Parameter(ParameterSetName='All__0')]
    [string]
    ${SearchString},

    [Parameter(ParameterSetName='ListRoleMembers__0')]
    [int]
    ${MaxResults},

    [Parameter(ParameterSetName='All__0', Mandatory=$true)]
    [switch]
    ${All},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Get-MsolScopedRoleMember { 
 [CmdletBinding(DefaultParameterSetName='ListRoleScopedMembers__0')]
param(
    [Parameter(ParameterSetName='ListRoleScopedMembers__0')]
    [Parameter(ParameterSetName='All__0')]
    [System.Nullable[guid]]
    ${AdministrativeUnitObjectId},

    [Parameter(ParameterSetName='ListRoleScopedMembers__0')]
    [Parameter(ParameterSetName='All__0')]
    [guid]
    ${RoleObjectId},

    [Parameter(ParameterSetName='ListRoleScopedMembers__0')]
    [int]
    ${MaxResults},

    [Parameter(ParameterSetName='All__0', Mandatory=$true)]
    [switch]
    ${All},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Get-MsolServicePrincipal { 
 [CmdletBinding(DefaultParameterSetName='ListServicePrincipals__0')]
param(
    [Parameter(ParameterSetName='GetServicePrincipal__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ObjectId},

    [Parameter(ParameterSetName='GetServicePrincipalByAppPrincipalId__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${AppPrincipalId},

    [Parameter(ParameterSetName='GetServicePrincipalBySpn__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ServicePrincipalName},

    [Parameter(ParameterSetName='ListServicePrincipals__0', ValueFromPipelineByPropertyName=$true)]
    [Parameter(ParameterSetName='All__0')]
    [string]
    ${SearchString},

    [Parameter(ParameterSetName='ListServicePrincipals__0')]
    [int]
    ${MaxResults},

    [Parameter(ParameterSetName='All__0', Mandatory=$true)]
    [switch]
    ${All},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Get-MsolServicePrincipalCredential { 
 [CmdletBinding(DefaultParameterSetName='ListServicePrincipalCredentials__0')]
param(
    [Parameter(ParameterSetName='ListServicePrincipalCredentials__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ObjectId},

    [Parameter(ParameterSetName='ListServicePrincipalCredentials__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [Parameter(ParameterSetName='ListServicePrincipalCredentialsByAppPrincipalId__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [Parameter(ParameterSetName='ListServicePrincipalCredentialsBySpn__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${ReturnKeyValues},

    [Parameter(ParameterSetName='ListServicePrincipalCredentialsByAppPrincipalId__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${AppPrincipalId},

    [Parameter(ParameterSetName='ListServicePrincipalCredentialsBySpn__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ServicePrincipalName},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Get-MsolSubscription { 
 [CmdletBinding(DefaultParameterSetName='ListSubscriptions__0')]
param(
    [Parameter(ParameterSetName='GetSubscription__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${SubscriptionId},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Get-MsolUser { 
 [CmdletBinding(DefaultParameterSetName='ListUsers__0')]
param(
    [Parameter(ParameterSetName='GetUser__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ObjectId},

    [Parameter(ParameterSetName='GetUser__0', ValueFromPipelineByPropertyName=$true)]
    [Parameter(ParameterSetName='GetUserByUpn__0', ValueFromPipelineByPropertyName=$true)]
    [Parameter(ParameterSetName='ListUsers__0')]
    [Parameter(ParameterSetName='All__0')]
    [switch]
    ${ReturnDeletedUsers},

    [Parameter(ParameterSetName='GetUserByUpn__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${UserPrincipalName},

    [Parameter(ParameterSetName='ListUsers__0')]
    [Parameter(ParameterSetName='All__0')]
    [string]
    ${City},

    [Parameter(ParameterSetName='ListUsers__0')]
    [Parameter(ParameterSetName='All__0')]
    [string]
    ${Country},

    [Parameter(ParameterSetName='ListUsers__0')]
    [Parameter(ParameterSetName='All__0')]
    [string]
    ${Department},

    [Parameter(ParameterSetName='ListUsers__0')]
    [Parameter(ParameterSetName='All__0')]
    [string]
    ${DomainName},

    [Parameter(ParameterSetName='ListUsers__0')]
    [Parameter(ParameterSetName='All__0')]
    [System.Nullable[object]]
    ${EnabledFilter},

    [Parameter(ParameterSetName='ListUsers__0')]
    [Parameter(ParameterSetName='All__0')]
    [string]
    ${State},

    [Parameter(ParameterSetName='ListUsers__0')]
    [Parameter(ParameterSetName='All__0')]
    [switch]
    ${Synchronized},

    [Parameter(ParameterSetName='ListUsers__0')]
    [Parameter(ParameterSetName='All__0')]
    [string]
    ${Title},

    [Parameter(ParameterSetName='ListUsers__0')]
    [Parameter(ParameterSetName='All__0')]
    [switch]
    ${HasErrorsOnly},

    [Parameter(ParameterSetName='ListUsers__0')]
    [Parameter(ParameterSetName='All__0')]
    [switch]
    ${LicenseReconciliationNeededOnly},

    [Parameter(ParameterSetName='ListUsers__0')]
    [Parameter(ParameterSetName='All__0')]
    [switch]
    ${UnlicensedUsersOnly},

    [Parameter(ParameterSetName='ListUsers__0')]
    [Parameter(ParameterSetName='All__0')]
    [string]
    ${UsageLocation},

    [Parameter(ParameterSetName='ListUsers__0')]
    [Parameter(ParameterSetName='All__0')]
    [string]
    ${SearchString},

    [Parameter(ParameterSetName='ListUsers__0')]
    [int]
    ${MaxResults},

    [Parameter(ParameterSetName='All__0', Mandatory=$true)]
    [switch]
    ${All},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Get-MsolUserByStrongAuthentication { 
 [CmdletBinding(DefaultParameterSetName='ListUsersByStrongAuthentication__0')]
param(
    [Parameter(ParameterSetName='ListUsersByStrongAuthentication__0')]
    [Parameter(ParameterSetName='All__0')]
    [System.Nullable[guid]]
    ${RoleObjectId},

    [Parameter(ParameterSetName='ListUsersByStrongAuthentication__0')]
    [Parameter(ParameterSetName='All__0')]
    [AllowEmptyCollection()]
    [object]
    ${Requirements},

    [Parameter(ParameterSetName='ListUsersByStrongAuthentication__0')]
    [Parameter(ParameterSetName='All__0')]
    [switch]
    ${RequirementUnsetOnly},

    [Parameter(ParameterSetName='ListUsersByStrongAuthentication__0')]
    [Parameter(ParameterSetName='All__0')]
    [string]
    ${SearchString},

    [Parameter(ParameterSetName='ListUsersByStrongAuthentication__0')]
    [int]
    ${MaxResults},

    [Parameter(ParameterSetName='All__0', Mandatory=$true)]
    [switch]
    ${All},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Get-MsolUserRole { 
 [CmdletBinding(DefaultParameterSetName='ListRolesForUser__0')]
param(
    [Parameter(ParameterSetName='ListRolesForUser__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ObjectId},

    [Parameter(ParameterSetName='ListRolesForUserByUpn__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${UserPrincipalName},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function New-MsolAdministrativeUnit { 
 [CmdletBinding(DefaultParameterSetName='AddAdministrativeUnit__0')]
param(
    [Parameter(ParameterSetName='AddAdministrativeUnit__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${DisplayName},

    [Parameter(ParameterSetName='AddAdministrativeUnit__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Description},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function New-MsolDomain { 
 [CmdletBinding(DefaultParameterSetName='AddDomain__0')]
param(
    [Parameter(ParameterSetName='AddDomain__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Name},

    [Parameter(ParameterSetName='AddDomain__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[object]]
    ${Authentication},

    [Parameter(ParameterSetName='AddDomain__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[object]]
    ${VerificationMethod},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function New-MsolFederatedDomain { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
param(
    [switch]
    ${SupportMultipleDomain},

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${DomainName})

 
 } 


function New-MsolGroup { 
 [CmdletBinding(DefaultParameterSetName='AddGroup__0')]
param(
    [Parameter(ParameterSetName='AddGroup__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${DisplayName},

    [Parameter(ParameterSetName='AddGroup__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Description},

    [Parameter(ParameterSetName='AddGroup__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ManagedBy},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function New-MsolLicenseOptions { 
 [CmdletBinding()]
param(
    [Parameter(ParameterSetName='NewMsolLicenseOptions', Mandatory=$true)]
    [string]
    ${AccountSkuId},

    [Parameter(ParameterSetName='NewMsolLicenseOptions')]
    [System.Collections.Generic.List[string]]
    ${DisabledPlans})

 
 } 


function New-MsolServicePrincipal { 
 [CmdletBinding(DefaultParameterSetName='AddServicePrincipal__0')]
param(
    [Parameter(ParameterSetName='AddServicePrincipal__0', ValueFromPipelineByPropertyName=$true)]
    [AllowEmptyCollection()]
    [string[]]
    ${ServicePrincipalNames},

    [Parameter(ParameterSetName='AddServicePrincipal__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${AppPrincipalId},

    [Parameter(ParameterSetName='AddServicePrincipal__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${DisplayName},

    [Parameter(ParameterSetName='AddServicePrincipal__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${AccountEnabled},

    [Parameter(ParameterSetName='AddServicePrincipal__0', ValueFromPipelineByPropertyName=$true)]
    [AllowEmptyCollection()]
    [object]
    ${Addresses},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[object]]
    ${Type},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Value},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[datetime]]
    ${StartDate},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[datetime]]
    ${EndDate},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[object]]
    ${Usage},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function New-MsolServicePrincipalAddresses { 
 [CmdletBinding()]
param(
    [Parameter(ParameterSetName='NewServicePrincipalAddresses', Mandatory=$true)]
    [string]
    ${Address},

    [Parameter(ParameterSetName='NewServicePrincipalAddresses')]
    [object]
    ${AddressType})

 
 } 


function New-MsolServicePrincipalCredential { 
 [CmdletBinding(DefaultParameterSetName='AddServicePrincipalCredentials__0')]
param(
    [Parameter(ParameterSetName='AddServicePrincipalCredentials__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ObjectId},

    [Parameter(ParameterSetName='AddServicePrincipalCredentialsBySpn__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ServicePrincipalName},

    [Parameter(ParameterSetName='AddServicePrincipalCredentialsByAppPrincipalId__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${AppPrincipalId},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[object]]
    ${Type},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Value},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[datetime]]
    ${StartDate},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[datetime]]
    ${EndDate},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[object]]
    ${Usage},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function New-MsolUser { 
 [CmdletBinding(DefaultParameterSetName='AddUser__0')]
param(
    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ImmutableId},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${UserPrincipalName},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${BlockCredential},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${City},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Country},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Department},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${DisplayName},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Fax},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${FirstName},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${LastName},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[datetime]]
    ${LastPasswordChangeTimestamp},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${MobilePhone},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Office},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${PasswordNeverExpires},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${PhoneNumber},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${PostalCode},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${PreferredDataLocation},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${PreferredLanguage},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[datetime]]
    ${SoftDeletionTimestamp},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${State},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${StreetAddress},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${StrongPasswordRequired},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Title},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${UsageLocation},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [AllowEmptyCollection()]
    [string[]]
    ${AlternateEmailAddresses},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [AllowEmptyCollection()]
    [object]
    ${StrongAuthenticationMethods},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [AllowEmptyCollection()]
    [string[]]
    ${AlternateMobilePhones},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [AllowEmptyCollection()]
    [object]
    ${StrongAuthenticationRequirements},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[datetime]]
    ${StsRefreshTokensValidFrom},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[object]]
    ${UserType},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Password},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [AllowEmptyCollection()]
    [object]
    ${LicenseOptions},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${ForceChangePassword},

    [Parameter(ParameterSetName='AddUser__0', ValueFromPipelineByPropertyName=$true)]
    [string[]]
    ${LicenseAssignment},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function New-MsolWellKnownGroup { 
 [CmdletBinding(DefaultParameterSetName='AddWellKnownGroup__0')]
param(
    [Parameter(ParameterSetName='AddWellKnownGroup__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${WellKnownGroupName},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Redo-MsolProvisionContact { 
 [CmdletBinding()]
param(
    [Parameter(ParameterSetName='RetryContactProvisioning__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ObjectId},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Redo-MsolProvisionGroup { 
 [CmdletBinding()]
param(
    [Parameter(ParameterSetName='RetryGroupProvisioning__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ObjectId},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Redo-MsolProvisionUser { 
 [CmdletBinding()]
param(
    [Parameter(ParameterSetName='RetryUserProvisioning__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ObjectId},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Remove-MsolAdministrativeUnit { 
 [CmdletBinding(DefaultParameterSetName='RemoveAdministrativeUnit__0')]
param(
    [Parameter(ParameterSetName='RemoveAdministrativeUnit__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ObjectId},

    [switch]
    ${Force},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Remove-MsolAdministrativeUnitMember { 
 [CmdletBinding(DefaultParameterSetName='RemoveAdministrativeUnitMembers__0')]
param(
    [Parameter(ParameterSetName='RemoveAdministrativeUnitMembers__0', Mandatory=$true)]
    [guid]
    ${AdministrativeUnitObjectId},

    [Parameter(ParameterSetName='RemoveAdministrativeUnitMembers__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${AdministrativeUnitMemberObjectId},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Remove-MsolApplicationPassword { 
 [CmdletBinding()]
param(
    [Parameter(ParameterSetName='DeleteApplicationPassword__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${UserPrincipalName},

    [Parameter(ParameterSetName='DeleteApplicationPassword__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${PasswordId},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Remove-MsolContact { 
 [CmdletBinding(DefaultParameterSetName='RemoveContact__0')]
param(
    [Parameter(ParameterSetName='RemoveContact__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ObjectId},

    [switch]
    ${Force},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Remove-MsolDevice { 
 [CmdletBinding(DefaultParameterSetName='RemoveDeviceByDeviceId', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [Parameter(ParameterSetName='RemoveDeviceByDeviceId', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${DeviceId},

    [switch]
    ${Force},

    [Parameter(ParameterSetName='RemoveDeviceByObjectId', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ObjectId})

 
 } 


function Remove-MsolDomain { 
 [CmdletBinding(DefaultParameterSetName='RemoveDomain__0')]
param(
    [Parameter(ParameterSetName='RemoveDomain__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${DomainName},

    [switch]
    ${Force},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Remove-MsolFederatedDomain { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [switch]
    ${SupportMultipleDomain},

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${DomainName})

 
 } 


function Remove-MsolForeignGroupFromRole { 
 [CmdletBinding(DefaultParameterSetName='RemoveForeignGroupFromRole__0')]
param(
    [Parameter(ParameterSetName='RemoveForeignGroupFromRole__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ForeignGroupObjectId},

    [Parameter(ParameterSetName='RemoveForeignGroupFromRole__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ForeignCompanyObjectId},

    [Parameter(ParameterSetName='RemoveForeignGroupFromRole__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${RoleObjectId},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Remove-MsolGroup { 
 [CmdletBinding(DefaultParameterSetName='RemoveGroup__0')]
param(
    [Parameter(ParameterSetName='RemoveGroup__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ObjectId},

    [switch]
    ${Force},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Remove-MsolGroupMember { 
 [CmdletBinding(DefaultParameterSetName='RemoveGroupMembers__0')]
param(
    [Parameter(ParameterSetName='RemoveGroupMembers__0', Mandatory=$true)]
    [guid]
    ${GroupObjectId},

    [Parameter(ParameterSetName='RemoveGroupMembers__0', ValueFromPipelineByPropertyName=$true)]
    [object]
    ${GroupMemberType},

    [Parameter(ParameterSetName='RemoveGroupMembers__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${GroupMemberObjectId},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Remove-MsolRoleMember { 
 [CmdletBinding(DefaultParameterSetName='RemoveRoleMembers__0')]
param(
    [Parameter(ParameterSetName='RemoveRoleMembers__0', Mandatory=$true)]
    [guid]
    ${RoleObjectId},

    [Parameter(ParameterSetName='RemoveRoleMembers__0', ValueFromPipelineByPropertyName=$true)]
    [Parameter(ParameterSetName='RemoveRoleMembersByRoleName__0', ValueFromPipelineByPropertyName=$true)]
    [object]
    ${RoleMemberType},

    [Parameter(ParameterSetName='RemoveRoleMembers__0', ValueFromPipelineByPropertyName=$true)]
    [Parameter(ParameterSetName='RemoveRoleMembersByRoleName__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${RoleMemberObjectId},

    [Parameter(ParameterSetName='RemoveRoleMembers__0', ValueFromPipelineByPropertyName=$true)]
    [Parameter(ParameterSetName='RemoveRoleMembersByRoleName__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${RoleMemberEmailAddress},

    [Parameter(ParameterSetName='RemoveRoleMembersByRoleName__0', Mandatory=$true)]
    [string]
    ${RoleName},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Remove-MsolScopedRoleMember { 
 [CmdletBinding(DefaultParameterSetName='RemoveRoleScopedMembers__0')]
param(
    [Parameter(ParameterSetName='RemoveRoleScopedMembers__0', Mandatory=$true)]
    [guid]
    ${RoleObjectId},

    [Parameter(ParameterSetName='RemoveRoleScopedMembers__0', Mandatory=$true)]
    [guid]
    ${AdministrativeUnitObjectId},

    [Parameter(ParameterSetName='RemoveRoleScopedMembers__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${RoleMemberObjectId},

    [Parameter(ParameterSetName='RemoveRoleScopedMembers__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${RoleMemberUserPrincipalName},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Remove-MsolServicePrincipal { 
 [CmdletBinding(DefaultParameterSetName='RemoveServicePrincipal__0')]
param(
    [Parameter(ParameterSetName='RemoveServicePrincipal__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ObjectId},

    [Parameter(ParameterSetName='RemoveServicePrincipalByAppPrincipalId__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${AppPrincipalId},

    [Parameter(ParameterSetName='RemoveServicePrincipalBySpn__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ServicePrincipalName},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Remove-MsolServicePrincipalCredential { 
 [CmdletBinding(DefaultParameterSetName='RemoveServicePrincipalCredentials__0')]
param(
    [Parameter(ParameterSetName='RemoveServicePrincipalCredentials__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ObjectId},

    [Parameter(ParameterSetName='RemoveServicePrincipalCredentials__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [Parameter(ParameterSetName='RemoveServicePrincipalCredentialsBySpn__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [Parameter(ParameterSetName='RemoveServicePrincipalCredentialsByAppPrincipalId__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [AllowEmptyCollection()]
    [guid[]]
    ${KeyIds},

    [Parameter(ParameterSetName='RemoveServicePrincipalCredentialsBySpn__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ServicePrincipalName},

    [Parameter(ParameterSetName='RemoveServicePrincipalCredentialsByAppPrincipalId__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${AppPrincipalId},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Remove-MsolUser { 
 [CmdletBinding(DefaultParameterSetName='RemoveUser__0')]
param(
    [Parameter(ParameterSetName='RemoveUser__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ObjectId},

    [Parameter(ParameterSetName='RemoveUser__0', ValueFromPipelineByPropertyName=$true)]
    [Parameter(ParameterSetName='RemoveUserByUpn__0', ValueFromPipelineByPropertyName=$true)]
    [switch]
    ${RemoveFromRecycleBin},

    [switch]
    ${Force},

    [Parameter(ParameterSetName='RemoveUserByUpn__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${UserPrincipalName},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Reset-MsolStrongAuthenticationMethodByUpn { 
 [CmdletBinding()]
param(
    [Parameter(ParameterSetName='ResetStrongAuthenticationMethodByUpn__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${UserPrincipalName},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Restore-MsolUser { 
 [CmdletBinding(DefaultParameterSetName='RestoreUser__0')]
param(
    [Parameter(ParameterSetName='RestoreUser__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ObjectId},

    [Parameter(ParameterSetName='RestoreUser__0', ValueFromPipelineByPropertyName=$true)]
    [Parameter(ParameterSetName='RestoreUserByUpn__0', ValueFromPipelineByPropertyName=$true)]
    [switch]
    ${AutoReconcileProxyConflicts},

    [Parameter(ParameterSetName='RestoreUser__0', ValueFromPipelineByPropertyName=$true)]
    [Parameter(ParameterSetName='RestoreUserByUpn__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${NewUserPrincipalName},

    [Parameter(ParameterSetName='RestoreUserByUpn__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${UserPrincipalName},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Set-MsolADFSContext { 
 [CmdletBinding()]
param(
    [pscredential]
    ${ADFSUserCredentials},

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${Computer},

    [string]
    ${LogFile})

 
 } 


function Set-MsolAdministrativeUnit { 
 [CmdletBinding(DefaultParameterSetName='SetAdministrativeUnit__0')]
param(
    [Parameter(ParameterSetName='SetAdministrativeUnit__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${ObjectId},

    [Parameter(ParameterSetName='SetAdministrativeUnit__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${DisplayName},

    [Parameter(ParameterSetName='SetAdministrativeUnit__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Description},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Set-MsolCompanyAllowedDataLocation { 
 [CmdletBinding()]
param(
    [Parameter(ParameterSetName='SetCompanyAllowedDataLocation__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ServiceType},

    [Parameter(ParameterSetName='SetCompanyAllowedDataLocation__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Location},

    [Parameter(ParameterSetName='SetCompanyAllowedDataLocation__0', ValueFromPipelineByPropertyName=$true)]
    [bool]
    ${IsDefault},

    [Parameter(ParameterSetName='SetCompanyAllowedDataLocation__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${InitialDomain},

    [Parameter(ParameterSetName='SetCompanyAllowedDataLocation__0', ValueFromPipelineByPropertyName=$true)]
    [bool]
    ${Overwrite},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Set-MsolCompanyContactInformation { 
 [CmdletBinding(DefaultParameterSetName='SetCompanyContactInformation__0')]
param(
    [Parameter(ParameterSetName='SetCompanyContactInformation__0', ValueFromPipelineByPropertyName=$true)]
    [AllowEmptyCollection()]
    [string[]]
    ${TechnicalNotificationEmails},

    [Parameter(ParameterSetName='SetCompanyContactInformation__0', ValueFromPipelineByPropertyName=$true)]
    [AllowEmptyCollection()]
    [string[]]
    ${MarketingNotificationEmails},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Set-MsolCompanyMultiNationalEnabled { 
 [CmdletBinding()]
param(
    [Parameter(ParameterSetName='SetCompanyMultiNationalEnabled__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ServiceType},

    [Parameter(ParameterSetName='SetCompanyMultiNationalEnabled__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [bool]
    ${Enable},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Set-MsolCompanySecurityComplianceContactInformation { 
 [CmdletBinding(DefaultParameterSetName='SetCompanySecurityComplianceContactInformation__0')]
param(
    [Parameter(ParameterSetName='SetCompanySecurityComplianceContactInformation__0', ValueFromPipelineByPropertyName=$true)]
    [AllowEmptyCollection()]
    [string[]]
    ${SecurityComplianceNotificationEmails},

    [Parameter(ParameterSetName='SetCompanySecurityComplianceContactInformation__0', ValueFromPipelineByPropertyName=$true)]
    [AllowEmptyCollection()]
    [string[]]
    ${SecurityComplianceNotificationPhones},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Set-MsolCompanySettings { 
 [CmdletBinding(DefaultParameterSetName='SetCompanySettings__0')]
param(
    [Parameter(ParameterSetName='SetCompanySettings__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${SelfServePasswordResetEnabled},

    [Parameter(ParameterSetName='SetCompanySettings__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${UsersPermissionToCreateGroupsEnabled},

    [Parameter(ParameterSetName='SetCompanySettings__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${UsersPermissionToCreateLOBAppsEnabled},

    [Parameter(ParameterSetName='SetCompanySettings__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${UsersPermissionToReadOtherUsersEnabled},

    [Parameter(ParameterSetName='SetCompanySettings__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${UsersPermissionToUserConsentToAppEnabled},

    [Parameter(ParameterSetName='SetCompanySettings__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${DefaultUsageLocation},

    [Parameter(ParameterSetName='SetCompanySettings__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${AllowAdHocSubscriptions},

    [Parameter(ParameterSetName='SetCompanySettings__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${AllowEmailVerifiedUsers},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Set-MsolDeviceRegistrationServicePolicy { 
 [CmdletBinding()]
param(
    [ValidateSet('All','None','Selected')]
    [System.Nullable[object]]
    ${AllowedToAzureAdJoin},

    [ValidateSet('All','None')]
    [System.Nullable[object]]
    ${AllowedToWorkplaceJoin},

    [ValidateRange(1, 100)]
    [System.Nullable[int]]
    ${MaximumDevicesPerUser},

    [System.Nullable[bool]]
    ${RequireMultiFactorAuth})


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('MSOnline\Set-MsolDeviceRegistrationServicePolicy', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function Set-MsolDirSyncConfiguration { 
 [CmdletBinding(DefaultParameterSetName='SetAccidentalDeletionThreshold__0')]
param(
    [Parameter(ParameterSetName='SetAccidentalDeletionThreshold__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [uint32]
    ${AccidentalDeletionThreshold},

    [switch]
    ${Force},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Set-MsolDirSyncEnabled { 
 [CmdletBinding(DefaultParameterSetName='SetCompanyDirSyncEnabled__0')]
param(
    [Parameter(ParameterSetName='SetCompanyDirSyncEnabled__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [bool]
    ${EnableDirSync},

    [switch]
    ${Force},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Set-MsolDirSyncFeature { 
 [CmdletBinding(DefaultParameterSetName='SetCompanyDirSyncFeature__0')]
param(
    [Parameter(ParameterSetName='SetCompanyDirSyncFeature__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Feature},

    [Parameter(ParameterSetName='SetCompanyDirSyncFeature__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [bool]
    ${Enable},

    [switch]
    ${Force},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Set-MsolDomain { 
 [CmdletBinding(DefaultParameterSetName='SetDomain__0')]
param(
    [Parameter(ParameterSetName='SetDomain__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Name},

    [Parameter(ParameterSetName='SetDomain__0', ValueFromPipelineByPropertyName=$true)]
    [switch]
    ${IsDefault},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Set-MsolDomainAuthentication { 
 [CmdletBinding(DefaultParameterSetName='SetDomainAuthentication__0')]
param(
    [Parameter(ParameterSetName='SetDomainAuthentication__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${DomainName},

    [Parameter(ParameterSetName='SetDomainAuthentication__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [object]
    ${Authentication},

    [Parameter(ParameterSetName='SetDomainAuthentication__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${SigningCertificate},

    [Parameter(ParameterSetName='SetDomainAuthentication__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${NextSigningCertificate},

    [Parameter(ParameterSetName='SetDomainAuthentication__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${LogOffUri},

    [Parameter(ParameterSetName='SetDomainAuthentication__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${PassiveLogOnUri},

    [Parameter(ParameterSetName='SetDomainAuthentication__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ActiveLogOnUri},

    [Parameter(ParameterSetName='SetDomainAuthentication__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${IssuerUri},

    [Parameter(ParameterSetName='SetDomainAuthentication__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${FederationBrandName},

    [Parameter(ParameterSetName='SetDomainAuthentication__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${MetadataExchangeUri},

    [Parameter(ParameterSetName='SetDomainAuthentication__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[object]]
    ${PreferredAuthenticationProtocol},

    [Parameter(ParameterSetName='SetDomainAuthentication__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${SupportsMfa},

    [Parameter(ParameterSetName='SetDomainAuthentication__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${DefaultInteractiveAuthenticationMethod},

    [Parameter(ParameterSetName='SetDomainAuthentication__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${OpenIdConnectDiscoveryEndpoint},

    [Parameter(ParameterSetName='SetDomainAuthentication__0', ValueFromPipelineByPropertyName=$true)]
    [object]
    ${SigningCertificateUpdateStatus},

    [Parameter(ParameterSetName='SetDomainAuthentication__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[object]]
    ${PromptLoginBehavior},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Set-MsolDomainFederationSettings { 
 [CmdletBinding(DefaultParameterSetName='SetDomainFederationSettings__0')]
param(
    [Parameter(ParameterSetName='SetDomainFederationSettings__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${DomainName},

    [Parameter(ParameterSetName='SetDomainFederationSettings__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${SigningCertificate},

    [Parameter(ParameterSetName='SetDomainFederationSettings__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${NextSigningCertificate},

    [Parameter(ParameterSetName='SetDomainFederationSettings__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${LogOffUri},

    [Parameter(ParameterSetName='SetDomainFederationSettings__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${PassiveLogOnUri},

    [Parameter(ParameterSetName='SetDomainFederationSettings__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ActiveLogOnUri},

    [Parameter(ParameterSetName='SetDomainFederationSettings__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${IssuerUri},

    [Parameter(ParameterSetName='SetDomainFederationSettings__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${FederationBrandName},

    [Parameter(ParameterSetName='SetDomainFederationSettings__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${MetadataExchangeUri},

    [Parameter(ParameterSetName='SetDomainFederationSettings__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[object]]
    ${PreferredAuthenticationProtocol},

    [Parameter(ParameterSetName='SetDomainFederationSettings__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${SupportsMfa},

    [Parameter(ParameterSetName='SetDomainFederationSettings__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${DefaultInteractiveAuthenticationMethod},

    [Parameter(ParameterSetName='SetDomainFederationSettings__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${OpenIdConnectDiscoveryEndpoint},

    [Parameter(ParameterSetName='SetDomainFederationSettings__0', ValueFromPipelineByPropertyName=$true)]
    [object]
    ${SigningCertificateUpdateStatus},

    [Parameter(ParameterSetName='SetDomainFederationSettings__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[object]]
    ${PromptLoginBehavior},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Set-MsolGroup { 
 [CmdletBinding(DefaultParameterSetName='SetGroup__0')]
param(
    [Parameter(ParameterSetName='SetGroup__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${ObjectId},

    [Parameter(ParameterSetName='SetGroup__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${DisplayName},

    [Parameter(ParameterSetName='SetGroup__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Description},

    [Parameter(ParameterSetName='SetGroup__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ManagedBy},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Set-MsolPartnerInformation { 
 [CmdletBinding(DefaultParameterSetName='SetPartnerInformation__0')]
param(
    [Parameter(ParameterSetName='SetPartnerInformation__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${ObjectId},

    [Parameter(ParameterSetName='SetPartnerInformation__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[object]]
    ${CompanyType},

    [Parameter(ParameterSetName='SetPartnerInformation__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${PartnerCompanyName},

    [Parameter(ParameterSetName='SetPartnerInformation__0', ValueFromPipelineByPropertyName=$true)]
    [AllowEmptyCollection()]
    [string[]]
    ${PartnerSupportTelephones},

    [Parameter(ParameterSetName='SetPartnerInformation__0', ValueFromPipelineByPropertyName=$true)]
    [AllowEmptyCollection()]
    [string[]]
    ${PartnerSupportEmails},

    [Parameter(ParameterSetName='SetPartnerInformation__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${PartnerCommerceUrl},

    [Parameter(ParameterSetName='SetPartnerInformation__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${PartnerSupportUrl},

    [Parameter(ParameterSetName='SetPartnerInformation__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${PartnerHelpUrl},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Set-MsolPasswordPolicy { 
 [CmdletBinding(DefaultParameterSetName='SetPasswordPolicy__0')]
param(
    [Parameter(ParameterSetName='SetPasswordPolicy__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${DomainName},

    [Parameter(ParameterSetName='SetPasswordPolicy__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[uint32]]
    ${ValidityPeriod},

    [Parameter(ParameterSetName='SetPasswordPolicy__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[uint32]]
    ${NotificationDays},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Set-MsolServicePrincipal { 
 [CmdletBinding(DefaultParameterSetName='SetServicePrincipal__0')]
param(
    [Parameter(ParameterSetName='SetServicePrincipal__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${ObjectId},

    [Parameter(ParameterSetName='SetServicePrincipal__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${AppPrincipalId},

    [Parameter(ParameterSetName='SetServicePrincipal__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${DisplayName},

    [Parameter(ParameterSetName='SetServicePrincipal__0', ValueFromPipelineByPropertyName=$true)]
    [AllowEmptyCollection()]
    [string[]]
    ${ServicePrincipalNames},

    [Parameter(ParameterSetName='SetServicePrincipal__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${AccountEnabled},

    [Parameter(ParameterSetName='SetServicePrincipal__0', ValueFromPipelineByPropertyName=$true)]
    [AllowEmptyCollection()]
    [object]
    ${Addresses},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Set-MsolUser { 
 [CmdletBinding(DefaultParameterSetName='SetUser__0')]
param(
    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ImmutableId},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${ObjectId},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${UserPrincipalName},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${BlockCredential},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${City},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Country},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Department},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${DisplayName},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Fax},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${FirstName},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${LastName},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[datetime]]
    ${LastPasswordChangeTimestamp},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${MobilePhone},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Office},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${PasswordNeverExpires},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${PhoneNumber},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${PostalCode},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${PreferredDataLocation},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${PreferredLanguage},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[datetime]]
    ${SoftDeletionTimestamp},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${State},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${StreetAddress},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${StrongPasswordRequired},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Title},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${UsageLocation},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [AllowEmptyCollection()]
    [string[]]
    ${AlternateEmailAddresses},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [AllowEmptyCollection()]
    [object]
    ${StrongAuthenticationMethods},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [AllowEmptyCollection()]
    [string[]]
    ${AlternateMobilePhones},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [AllowEmptyCollection()]
    [object]
    ${StrongAuthenticationRequirements},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[datetime]]
    ${StsRefreshTokensValidFrom},

    [Parameter(ParameterSetName='SetUser__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[object]]
    ${UserType},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Set-MsolUserLicense { 
 [CmdletBinding(DefaultParameterSetName='SetUserLicenses__0')]
param(
    [Parameter(ParameterSetName='SetUserLicenses__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ObjectId},

    [Parameter(ParameterSetName='SetUserLicenses__0', ValueFromPipelineByPropertyName=$true)]
    [Parameter(ParameterSetName='SetUserLicensesByUpn__0', ValueFromPipelineByPropertyName=$true)]
    [AllowEmptyCollection()]
    [object]
    ${LicenseOptions},

    [Parameter(ParameterSetName='SetUserLicensesByUpn__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${UserPrincipalName},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [string[]]
    ${AddLicenses},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [string[]]
    ${RemoveLicenses},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Set-MsolUserPassword { 
 [CmdletBinding(DefaultParameterSetName='ResetUserPassword__0')]
param(
    [Parameter(ParameterSetName='ResetUserPassword__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ObjectId},

    [Parameter(ParameterSetName='ResetUserPassword__0', ValueFromPipelineByPropertyName=$true)]
    [Parameter(ParameterSetName='ResetUserPasswordByUpn__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${NewPassword},

    [Parameter(ParameterSetName='ResetUserPassword__0', ValueFromPipelineByPropertyName=$true)]
    [Parameter(ParameterSetName='ResetUserPasswordByUpn__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${ForceChangePassword},

    [Parameter(ParameterSetName='ResetUserPassword__0', ValueFromPipelineByPropertyName=$true)]
    [Parameter(ParameterSetName='ResetUserPasswordByUpn__0', ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${ForceChangePasswordOnly},

    [Parameter(ParameterSetName='ResetUserPasswordByUpn__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${UserPrincipalName},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Set-MsolUserPrincipalName { 
 [CmdletBinding(DefaultParameterSetName='ChangeUserPrincipalName__0')]
param(
    [Parameter(ParameterSetName='ChangeUserPrincipalName__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [guid]
    ${ObjectId},

    [Parameter(ParameterSetName='ChangeUserPrincipalName__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [Parameter(ParameterSetName='ChangeUserPrincipalNameByUpn__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${NewUserPrincipalName},

    [Parameter(ParameterSetName='ChangeUserPrincipalName__0', ValueFromPipelineByPropertyName=$true)]
    [Parameter(ParameterSetName='ChangeUserPrincipalNameByUpn__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ImmutableId},

    [Parameter(ParameterSetName='ChangeUserPrincipalName__0', ValueFromPipelineByPropertyName=$true)]
    [Parameter(ParameterSetName='ChangeUserPrincipalNameByUpn__0', ValueFromPipelineByPropertyName=$true)]
    [string]
    ${NewPassword},

    [Parameter(ParameterSetName='ChangeUserPrincipalNameByUpn__0', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${UserPrincipalName},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[guid]]
    ${TenantId})

 
 } 


function Update-MsolFederatedDomain { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [switch]
    ${SupportMultipleDomain},

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${DomainName})

 
 } 


<# AzureAD #>
function Get-AzureADApplicationProxyConnectorGroupMembers { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Id},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Filter})

 
 } 


function Add-AzureADApplicationOwner { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${RefObjectId})

 
 } 


function Add-AzureADDeviceRegisteredOwner { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${RefObjectId})

 
 } 


function Add-AzureADDeviceRegisteredUser { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${RefObjectId})

 
 } 


function Add-AzureADDirectoryRoleMember { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${RefObjectId})

 
 } 


function Add-AzureADGroupMember { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${RefObjectId})

 
 } 


function Add-AzureADGroupOwner { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${RefObjectId})

 
 } 


function Add-AzureADMSLifecyclePolicyGroup { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Id})


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\Add-AzureADMSLifecyclePolicyGroup', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function Add-AzureADServicePrincipalOwner { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${RefObjectId})

 
 } 


function Confirm-AzureADDomain { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Name})

 
 } 


function Connect-AzureAD { 
 [CmdletBinding(DefaultParameterSetName='UserCredential', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [ValidateNotNullOrEmpty()]
    [object]
    ${AzureEnvironmentName},

    [Parameter(ParameterSetName='UserCredential')]
    [Parameter(ParameterSetName='ServicePrincipalCertificate', Mandatory=$true)]
    [Parameter(ParameterSetName='AccessToken')]
    [Alias('Domain','TenantDomain')]
    [ValidateNotNullOrEmpty()]
    [string]
    ${TenantId},

    [Parameter(ParameterSetName='UserCredential')]
    [pscredential]
    ${Credential},

    [Parameter(ParameterSetName='ServicePrincipalCertificate', Mandatory=$true)]
    [string]
    ${CertificateThumbprint},

    [Parameter(ParameterSetName='ServicePrincipalCertificate', Mandatory=$true)]
    [string]
    ${ApplicationId},

    [Parameter(ParameterSetName='AccessToken', Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    ${AadAccessToken},

    [Parameter(ParameterSetName='AccessToken')]
    [ValidateNotNullOrEmpty()]
    [string]
    ${MsAccessToken},

    [Parameter(ParameterSetName='AccessToken', Mandatory=$true)]
    [Parameter(ParameterSetName='UserCredential')]
    [ValidateNotNullOrEmpty()]
    [string]
    ${AccountId},

    [object]
    ${LogLevel},

    [string]
    ${LogFilePath})

 
 } 


function Disconnect-AzureAD { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param()

 
 } 


function Enable-AzureADDirectoryRole { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param()


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\Enable-AzureADDirectoryRole', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function Get-AzureADApplication { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(ParameterSetName='GetVague', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${SearchString},

    [Parameter(ParameterSetName='GetById', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Filter})

 
 } 


function Get-AzureADApplicationExtensionProperty { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})

 
 } 


function Get-AzureADApplicationKeyCredential { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})

 
 } 


function Get-AzureADApplicationLogo { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${FilePath},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${FileName},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [bool]
    ${View})

 
 } 


function Get-AzureADApplicationOwner { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top})

 
 } 


function Get-AzureADApplicationPasswordCredential { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})

 
 } 


function Get-AzureADApplicationProxyApplication { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})

 
 } 


function Get-AzureADApplicationProxyApplicationConnectorGroup { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})

 
 } 


function Get-AzureADApplicationProxyConnector { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(ParameterSetName='GetVague', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${SearchString},

    [Parameter(ParameterSetName='GetById', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Id},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Filter})

 
 } 


function Get-AzureADApplicationProxyConnectorGroup { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(ParameterSetName='GetVague', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${SearchString},

    [Parameter(ParameterSetName='GetById', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Id},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Filter})

 
 } 


function Get-AzureADApplicationProxyConnectorGroupMember { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Id},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Filter})

 
 } 


function Get-AzureADApplicationProxyConnectorMemberOf { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Id})

 
 } 


function Get-AzureADApplicationServiceEndpoint { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top})

 
 } 


function Get-AzureADContact { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(ParameterSetName='GetById', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Filter})

 
 } 


function Get-AzureADContactDirectReport { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top})

 
 } 


function Get-AzureADContactManager { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})

 
 } 


function Get-AzureADContactMembership { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top})

 
 } 


function Get-AzureADContactThumbnailPhoto { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${FilePath},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${FileName},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [bool]
    ${View})

 
 } 


function Get-AzureADContract { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(ParameterSetName='GetById', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Filter})

 
 } 


function Get-AzureADCurrentSessionInfo { 
 [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param()

 
 } 


function Get-AzureADDeletedApplication { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(ParameterSetName='GetVague', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${SearchString},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Filter})

 
 } 


function Get-AzureADDevice { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(ParameterSetName='GetVague', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${SearchString},

    [Parameter(ParameterSetName='GetById', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Filter})

 
 } 


function Get-AzureADDeviceConfiguration { 
 [CmdletBinding()]
param()

 
 } 


function Get-AzureADDeviceRegisteredOwner { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top})

 
 } 


function Get-AzureADDeviceRegisteredUser { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top})

 
 } 


function Get-AzureADDirectoryRole { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(ParameterSetName='GetById', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Filter})

 
 } 


function Get-AzureADDirectoryRoleMember { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Filter})

 
 } 


function Get-AzureADDirectoryRoleTemplate { 
 [CmdletBinding()]
param()

 
 } 


function Get-AzureADDomain { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(ParameterSetName='GetById', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Name})

 
 } 


function Get-AzureADDomainNameReference { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Name})

 
 } 


function Get-AzureADDomainServiceConfigurationRecord { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Name})

 
 } 


function Get-AzureADDomainVerificationDnsRecord { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Name})

 
 } 


function Get-AzureADExtensionProperty { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param()


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\Get-AzureADExtensionProperty', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function Get-AzureADGroup { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(ParameterSetName='GetVague', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${SearchString},

    [Parameter(ParameterSetName='GetById', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Filter})

 
 } 


function Get-AzureADGroupAppRoleAssignment { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top})

 
 } 


function Get-AzureADGroupMember { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top})

 
 } 


function Get-AzureADGroupOwner { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top})

 
 } 


function Get-AzureADMSDeletedDirectoryObject { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Id})

 
 } 


function Get-AzureADMSDeletedGroup { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(ParameterSetName='GetVague', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${SearchString},

    [Parameter(ParameterSetName='GetById', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Id},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Filter})

 
 } 


function Get-AzureADMSGroup { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(ParameterSetName='GetVague', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${SearchString},

    [Parameter(ParameterSetName='GetById', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Id},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Filter})

 
 } 


function Get-AzureADMSGroupLifecyclePolicy { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(ParameterSetName='GetById', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Id})

 
 } 


function Get-AzureADMSLifecyclePolicyGroup { 
 [CmdletBinding()]
param(
    [Parameter(ParameterSetName='GetById', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Id})

 
 } 


function Get-AzureADOAuth2PermissionGrant { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top})

 
 } 


function Get-AzureADObjectByObjectId { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param()


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\Get-AzureADObjectByObjectId', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function Get-AzureADServiceAppRoleAssignedTo { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top})

 
 } 


function Get-AzureADServiceAppRoleAssignment { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top})

 
 } 


function Get-AzureADServicePrincipal { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(ParameterSetName='GetVague', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${SearchString},

    [Parameter(ParameterSetName='GetById', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Filter})

 
 } 


function Get-AzureADServicePrincipalCreatedObject { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top})

 
 } 


function Get-AzureADServicePrincipalKeyCredential { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})

 
 } 


function Get-AzureADServicePrincipalMembership { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top})

 
 } 


function Get-AzureADServicePrincipalOAuth2PermissionGrant { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top})

 
 } 


function Get-AzureADServicePrincipalOwnedObject { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top})

 
 } 


function Get-AzureADServicePrincipalOwner { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top})

 
 } 


function Get-AzureADServicePrincipalPasswordCredential { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})

 
 } 


function Get-AzureADSubscribedSku { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(ParameterSetName='GetById', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})

 
 } 


function Get-AzureADTenantDetail { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top})

 
 } 


function Get-AzureADTrustedCertificateAuthority { 
 [CmdletBinding()]
param(
    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, HelpMessage='The ID of the tenant of instance of Azure Active Directory')]
    [string]
    ${TrustedIssuer},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, HelpMessage='The ID of the tenant of instance of Azure Active Directory')]
    [string]
    ${TrustedIssuerSki})

 
 } 


function Get-AzureADUser { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(ParameterSetName='GetVague', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${SearchString},

    [Parameter(ParameterSetName='GetById', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Filter})

 
 } 


function Get-AzureADUserAppRoleAssignment { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top})

 
 } 


function Get-AzureADUserCreatedObject { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top})

 
 } 


function Get-AzureADUserDirectReport { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top})

 
 } 


function Get-AzureADUserExtension { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})

 
 } 


function Get-AzureADUserLicenseDetail { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})

 
 } 


function Get-AzureADUserManager { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})

 
 } 


function Get-AzureADUserMembership { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top})

 
 } 


function Get-AzureADUserOAuth2PermissionGrant { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top})

 
 } 


function Get-AzureADUserOwnedDevice { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top})

 
 } 


function Get-AzureADUserOwnedObject { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top})

 
 } 


function Get-AzureADUserRegisteredDevice { 
 [CmdletBinding(DefaultParameterSetName='GetQuery')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${All},

    [Parameter(ParameterSetName='GetQuery', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[int]]
    ${Top})

 
 } 


function Get-AzureADUserThumbnailPhoto { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${FilePath},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${FileName},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [bool]
    ${View})

 
 } 


function New-AzureADApplication { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param()


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\New-AzureADApplication', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function New-AzureADApplicationExtensionProperty { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\New-AzureADApplicationExtensionProperty', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function New-AzureADApplicationKeyCredential { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${CustomKeyIdentifier},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[datetime]]
    ${StartDate},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[datetime]]
    ${EndDate},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[object]]
    ${Type},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[object]]
    ${Usage},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Value})

 
 } 


function New-AzureADApplicationPasswordCredential { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${CustomKeyIdentifier},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[datetime]]
    ${StartDate},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[datetime]]
    ${EndDate},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Value})

 
 } 


function New-AzureADApplicationProxyApplication { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${DisplayName},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ExternalUrl},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${InternalUrl},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[object]]
    ${ExternalAuthenticationType},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${IsTranslateHostHeaderEnabled},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${IsHttpOnlyCookieEnabled},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${IsTranslateLinksInBodyEnabled},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[object]]
    ${ApplicationServerTimeout},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ConnectorGroupId})

 
 } 


function New-AzureADApplicationProxyConnectorGroup { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [object]
    ${Name})

 
 } 


function New-AzureADDevice { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param()


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\New-AzureADDevice', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function New-AzureADDomain { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param()


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\New-AzureADDomain', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function New-AzureADGroup { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param()


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\New-AzureADGroup', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function New-AzureADGroupAppRoleAssignment { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\New-AzureADGroupAppRoleAssignment', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function New-AzureADMSGroup { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param()


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\New-AzureADMSGroup', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function New-AzureADMSGroupLifecyclePolicy { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param()


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\New-AzureADMSGroupLifecyclePolicy', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function New-AzureADMSInvitation { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param()


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\New-AzureADMSInvitation', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function New-AzureADServiceAppRoleAssignment { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\New-AzureADServiceAppRoleAssignment', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function New-AzureADServicePrincipal { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param()


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\New-AzureADServicePrincipal', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function New-AzureADServicePrincipalKeyCredential { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${CustomKeyIdentifier},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[datetime]]
    ${StartDate},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[datetime]]
    ${EndDate},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[object]]
    ${Type},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[object]]
    ${Usage},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Value})

 
 } 


function New-AzureADServicePrincipalPasswordCredential { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${CustomKeyIdentifier},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[datetime]]
    ${StartDate},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[datetime]]
    ${EndDate},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Value})

 
 } 


function New-AzureADTrustedCertificateAuthority { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, HelpMessage='Trusted certificate authority list')]
    [object]
    ${CertificateAuthorityInformation})

 
 } 


function New-AzureADUser { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param()


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\New-AzureADUser', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function New-AzureADUserAppRoleAssignment { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\New-AzureADUserAppRoleAssignment', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function Remove-AzureADApplication { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})

 
 } 


function Remove-AzureADApplicationExtensionProperty { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ExtensionPropertyId})

 
 } 


function Remove-AzureADApplicationKeyCredential { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${KeyId})

 
 } 


function Remove-AzureADApplicationOwner { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${OwnerId})

 
 } 


function Remove-AzureADApplicationPasswordCredential { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${KeyId})

 
 } 


function Remove-AzureADApplicationProxyApplication { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${RemoveADApplication})

 
 } 


function Remove-AzureADApplicationProxyApplicationConnectorGroup { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})

 
 } 


function Remove-AzureADApplicationProxyConnectorGroup { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Id})

 
 } 


function Remove-AzureADContact { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})

 
 } 


function Remove-AzureADContactManager { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})

 
 } 


function Remove-AzureADDeletedApplication { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})

 
 } 


function Remove-AzureADDevice { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})

 
 } 


function Remove-AzureADDeviceRegisteredOwner { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${OwnerId})

 
 } 


function Remove-AzureADDeviceRegisteredUser { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${UserId})

 
 } 


function Remove-AzureADDirectoryRoleMember { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${MemberId})

 
 } 


function Remove-AzureADDomain { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Name})

 
 } 


function Remove-AzureADGroup { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})

 
 } 


function Remove-AzureADGroupAppRoleAssignment { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${AppRoleAssignmentId})

 
 } 


function Remove-AzureADGroupMember { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${MemberId})

 
 } 


function Remove-AzureADGroupOwner { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${OwnerId})

 
 } 


function Remove-AzureADMSDeletedDirectoryObject { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Id})

 
 } 


function Remove-AzureADMSGroup { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Id})

 
 } 


function Remove-AzureADMSGroupLifecyclePolicy { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Id})

 
 } 


function Remove-AzureADMSLifecyclePolicyGroup { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Id})


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\Remove-AzureADMSLifecyclePolicyGroup', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function Remove-AzureADOAuth2PermissionGrant { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})

 
 } 


function Remove-AzureADServiceAppRoleAssignment { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${AppRoleAssignmentId})

 
 } 


function Remove-AzureADServicePrincipal { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})

 
 } 


function Remove-AzureADServicePrincipalKeyCredential { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${KeyId})

 
 } 


function Remove-AzureADServicePrincipalOwner { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${OwnerId})

 
 } 


function Remove-AzureADServicePrincipalPasswordCredential { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${KeyId})

 
 } 


function Remove-AzureADTrustedCertificateAuthority { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, HelpMessage='The unique identifier of the object specific Azure Active Directory object')]
    [object]
    ${CertificateAuthorityInformation})

 
 } 


function Remove-AzureADUser { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})

 
 } 


function Remove-AzureADUserAppRoleAssignment { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${AppRoleAssignmentId})

 
 } 


function Remove-AzureADUserExtension { 
 [CmdletBinding()]
param(
    [Parameter(ParameterSetName='SetSingle', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [Parameter(ParameterSetName='SetMultiple', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ParameterSetName='SetSingle', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ExtensionName},

    [Parameter(ParameterSetName='SetMultiple', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Collections.Generic.List[string]]
    ${ExtensionNames})

 
 } 


function Remove-AzureADUserManager { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})

 
 } 


function Reset-AzureADMSLifeCycleGroup { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Id})

 
 } 


function Restore-AzureADDeletedApplication { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\Restore-AzureADDeletedApplication', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function Restore-AzureADMSDeletedDirectoryObject { 
 [CmdletBinding()]
param(
    [Parameter(ParameterSetName='GetById', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Id})

 
 } 


function Revoke-AzureADSignedInUserAllRefreshToken { 
 [CmdletBinding()]
param()

 
 } 


function Revoke-AzureADUserAllRefreshToken { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})

 
 } 


function Select-AzureADGroupIdsContactIsMemberOf { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [object]
    ${GroupIdsForMembershipCheck})

 
 } 


function Select-AzureADGroupIdsGroupIsMemberOf { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [object]
    ${GroupIdsForMembershipCheck})

 
 } 


function Select-AzureADGroupIdsServicePrincipalIsMemberOf { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [object]
    ${GroupIdsForMembershipCheck})

 
 } 


function Select-AzureADGroupIdsUserIsMemberOf { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [object]
    ${GroupIdsForMembershipCheck})

 
 } 


function Set-AzureADApplication { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\Set-AzureADApplication', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function Set-AzureADApplicationLogo { 
 [CmdletBinding(DefaultParameterSetName='File')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [Parameter(ParameterSetName='Stream')]
    [Parameter(ParameterSetName='File')]
    [Parameter(ParameterSetName='ByteArray')]
    [string]
    ${ObjectId},

    [Parameter(ParameterSetName='Stream', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.IO.Stream]
    ${FileStream},

    [Parameter(ParameterSetName='File', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${FilePath},

    [Parameter(ParameterSetName='ByteArray', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [byte[]]
    ${ImageByteArray})

 
 } 


function Set-AzureADApplicationProxyApplication { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ExternalUrl},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${InternalUrl},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[object]]
    ${ExternalAuthenticationType},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${IsTranslateHostHeaderEnabled},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${IsHttpOnlyCookieEnabled},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[bool]]
    ${IsTranslateLinksInBodyEnabled},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[object]]
    ${ApplicationServerTimeout},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ConnectorGroupId})

 
 } 


function Set-AzureADApplicationProxyApplicationConnectorGroup { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ConnectorGroupId})

 
 } 


function Set-AzureADApplicationProxyApplicationCustomDomainCertificate { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${PfxFilePath},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [securestring]
    ${Password})

 
 } 


function Set-AzureADApplicationProxyApplicationSingleSignOn { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[object]]
    ${SingleSignOnMode},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${KerberosInternalApplicationServicePrincipalName},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Nullable[object]]
    ${KerberosDelegatedLoginIdentity})

 
 } 


function Set-AzureADApplicationProxyConnector { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Id},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ConnectorGroupId})

 
 } 


function Set-AzureADApplicationProxyConnectorGroup { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Id},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [object]
    ${Name})

 
 } 


function Set-AzureADDevice { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\Set-AzureADDevice', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function Set-AzureADDomain { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Name})


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\Set-AzureADDomain', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function Set-AzureADGroup { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\Set-AzureADGroup', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function Set-AzureADMSGroup { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Id})


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\Set-AzureADMSGroup', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function Set-AzureADMSGroupLifecyclePolicy { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${Id})


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\Set-AzureADMSGroupLifecyclePolicy', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function Set-AzureADServicePrincipal { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\Set-AzureADServicePrincipal', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function Set-AzureADTenantDetail { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param()


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\Set-AzureADTenantDetail', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function Set-AzureADTrustedCertificateAuthority { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, HelpMessage='Trusted certificate authority list')]
    [object]
    ${CertificateAuthorityInformation})

 
 } 


function Set-AzureADUser { 
 [CmdletBinding(DefaultParameterSetName='InvokeByDynamicParameters')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId})


dynamicparam
{
    try {
        $targetCmd = $ExecutionContext.InvokeCommand.GetCommand('azuread\Set-AzureADUser', [System.Management.Automation.CommandTypes]::Cmdlet, $PSBoundParameters)
        $dynamicParams = @($targetCmd.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })
        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    } catch {
        throw
    }
}

 
 } 


function Set-AzureADUserExtension { 
 [CmdletBinding()]
param(
    [Parameter(ParameterSetName='SetSingle', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [Parameter(ParameterSetName='SetMultiple', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(ParameterSetName='SetSingle', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ExtensionName},

    [Parameter(ParameterSetName='SetSingle', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ExtensionValue},

    [Parameter(ParameterSetName='SetMultiple', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.Collections.Generic.Dictionary[string,string]]
    ${ExtensionNameValues})

 
 } 


function Set-AzureADUserLicense { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [object]
    ${AssignedLicenses})

 
 } 


function Set-AzureADUserManager { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${RefObjectId})

 
 } 


function Set-AzureADUserPassword { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${ObjectId},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [securestring]
    ${Password},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [bool]
    ${ForceChangePasswordNextLogin},

    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [bool]
    ${EnforceChangePasswordPolicy})

 
 } 


function Set-AzureADUserThumbnailPhoto { 
 [CmdletBinding(DefaultParameterSetName='File')]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [Parameter(ParameterSetName='Stream')]
    [Parameter(ParameterSetName='File')]
    [Parameter(ParameterSetName='ByteArray')]
    [string]
    ${ObjectId},

    [Parameter(ParameterSetName='Stream', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [System.IO.Stream]
    ${FileStream},

    [Parameter(ParameterSetName='File', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]
    ${FilePath},

    [Parameter(ParameterSetName='ByteArray', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [byte[]]
    ${ImageByteArray})

 
 } 


function Update-AzureADSignedInUserPassword { 
 [CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [securestring]
    ${CurrentPassword},

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [securestring]
    ${NewPassword})

 
 } 



