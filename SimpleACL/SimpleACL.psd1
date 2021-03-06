@{
# Script module or binary module file associated with this manifest.
RootModule = 'SimpleACL.psm1'

# Version number of this module.
ModuleVersion = '0.9.0'

# ID used to uniquely identify this module
GUID = '052ca186-ba2b-421e-8d83-90bb8b04f4c8'

# Author of this module
Author = 'MartinGC94'

# Company or vendor of this module
CompanyName = ''

# Copyright statement for this module
Copyright = '(c) 2018 MartinGC94. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Easier management of ACLs in Powershell. Primarily focused on filesystem ACLs, but has limited support for other providers like the registry.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.0'

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module
# CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
NestedModules = '.\Cmdlets.dll'

# Functions to export from this module
FunctionsToExport = @(
	'Disable-AccessInheritance'
	'Enable-AccessInheritance'
	'Set-Owner'
	'New-AccessRule'
	'Add-AccessRuleForItem'
	'Remove-AccessRuleForItem'
	'Set-AccessRuleForItem'
	'Get-AccessRuleForItem'
)

# Cmdlets to export from this module
CmdletsToExport = 'Test-EffectiveAccess'

# Variables to export from this module
VariablesToExport = $null

# Aliases to export from this module
AliasesToExport = @(
	'Get-Owner'
	'Remove-AccessRuleFromItem'
)

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess
# PrivateData = ''

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''
}