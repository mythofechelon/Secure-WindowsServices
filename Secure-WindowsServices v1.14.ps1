<#
.SYNOPSIS
	Name: Secure-WindowsServices.ps1
	Description: The purpose of this script is to secure any Windows services with insecure permissions and unquoted paths.

.NOTES
	Author:                                 Ben Hooper (https://mythofechelon.co.uk/ / https://github.com/mythofechelon/Secure-WindowsServices/releases/latest)
	Tested on:                              Windows 10 v20H2 64-bit, Windows Server 2019 Active Directory Domain Services (AD DS) Domain Controller (DC)
	Version:                                1.14
	Changes in v1.14 (2021/10/17 14:21):    Added parameter "ReportOnly" and tweaked wording accordingly; overhauled summary output process to be more reliable and to include lists of both secured and unsecured services.
	Changes in v1.13 (2021/10/16 14:45):    Added parameter "Services"; tweaked warning message; added Info output of new image path.
	Changes in v1.12 (2021/10/15 19:26):    Added parameter "FullOutput"; changed structure of output to make it clear what each piece of information is, include the image path by default, and use less indentation; added interactive warning prompt and parameter "Force" to suppress this; tested on Windows Server 2019 AD DS DC; changed unknown colour from yellow to gray to differentiate from warnings; changed pass colour from green to dark green so it's easier to make out for colourblind people.
	Changes in v1.11 (2021/10/13 21:48):    Changed detection of security principals from English string matching to SID matching to facilitate usage in non-English environments / OSes.
	Changes in v1.10 (2021/10/11 21:58):    Added handling of services where the executable / image path (1) contains spaces, (2) isn't quoted, and (3) has restrictive permissions for administrators (e.g., 'C:\Program Files\WindowsApps\Microsoft.GamingServices_2.57.20005.0_x64__8wekyb3d8bbwe\GamingServices.exe') by changing method from "sc config" to "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\"; changed reporting from using display names to service names because some services have the same display names but different service names (e.g, "Gaming Services" x 2 vs "GamingServices" and "GamingServicesNet").
	Changes in v1.9 (2021/02/06 20:48):     Added fixing of services with spaces and without quotation marks, fixed bug where summary would report that Windows services couldn't be secured when they actually had been, added summary deduplication.
	Changes in v1.8 (2020/03/06 14:08):     Added handling for Windows services where the paths don't actually exist.
	Changes in v1.7 (2019/11/21 10:14):     Corrected "Windows service secured" logic so that it'll only report if it was actually successful in securing it.
	Changes in v1.6 (2019/11/20 14:31):     Fixed compatibility with Windows 7 / PowerShell < 3.0.
	Changes in v1.5 (2019/11/20 13:43):     Added special handling for Windows services located in "C:\Windows\system32\" so that the permissions are reduced to read & execute instead of being removed.
	Changes in v1.4 (2019/11/20 12:33):     Added post-run report of which, if any, services were secured.
	Changes in v1.3 (2019/11/20 11:39):     Updated to bring in line with enhancements of Update-hMailServerCertificate v1.13 (write access check to log file, auto-elevate, coloured statuses, etc) and changed tags to Info, Unknown, Pass, FAIL, Success, and ERROR.
	Changes in v1.2 (2018/10/15):           Enhanced output by (1) changing output type from "check performed-action result" with just "action result" which makes it easier to read with less indentations, (2) adding tags ("[FAILED]", "[SUCCESS]", and "[NOTIFICATION]") for quick checking of results, and (3) tweaking logging behaviour.
	Changes in v1.1 (2018/10/05):           Added handling of inherited permissions.
	
.PARAMETER FullOutput
	Outputs (to console and log file) the full detail (e.g., original ACLs).
	
.PARAMETER LogOutput
	Logs the output to the default file path "C:\<hostname>_Secure-WindowsServices.txt".
	
.PARAMETER LogFile
	When used in combination with -LogOutput, logs the output to the custom specified file path.
	
.PARAMETER Force
	Suppresses (and, therefore, agrees to) the interactive warning prompt.
	
.PARAMETER Services
	List of Windows services' service names (NOT display names) to secure, rather than all. Case insensitive.
	
.PARAMETER ReportOnly
	Only report on insecure services - do not fix them.

.EXAMPLE
	Run with the default settings:
		Secure-WindowsServices

.EXAMPLE
	Run with full output:
		Secure-WindowsServices -FullOutput
		
.EXAMPLE 
	Run with the default settings AND logging to the default path:
		Secure-WindowsServices -LogOutput
	
.EXAMPLE 
	Run with the default settings AND logging to a custom local path:
		Secure-WindowsServices -LogOutput -LogPath "C:\$env:computername_Secure-WindowsServices.txt"
	
.EXAMPLE 
	Run with the default settings AND logging to a custom network path:
		Secure-WindowsServices -LogOutput -LogPath "\\servername\filesharename\$env:computername_Secure-WindowsServices.txt"
	
.EXAMPLE 
	Run without interactive warning prompt:
		Secure-WindowsServices -Force
	
.EXAMPLE 
	Run with a list of specific services to secure:
		Secure-WindowsServices -Services serviceNameExample1, serviceNameExample2
	
.EXAMPLE 
	Run but only report on vulnerabilities - do not fix them:
		Secure-WindowsServices -ReportOnly
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

Param(
	[switch]$FullOutput,
	[switch]$LogOutput,
	[string]$LogPath,
	[switch]$Force,
	[string[]]$Services,
	[switch]$ReportOnly
)

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$RunAsAdministrator = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);

$global:FirstRun = $null;
$global:Script_PS1File_Name = Split-Path $MyInvocation.MyCommand.Path -Leaf;
$global:Script_PS1File_FullPath = $MyInvocation.MyCommand.Path;
[System.Collections.ArrayList]$global:InsecureWindowsServices = @();
[System.Collections.ArrayList]$global:SecuredWindowsServices = @();

$LogPath_Default = "C:\$env:computername`_$global:Script_PS1File_Name.log";

#-----------------------------------------------------------[Functions]------------------------------------------------------------

Function Secure-WindowsServices {
	Param()
	
	Begin {
		Write-Host "";
	}
	
	Process {
		Try {
			If ($FirstRun -Eq $Null){
				$FirstRun = $False;
			} Else {
				$FirstRun = $True;
			}
			
			If ($FirstRun -Eq $False){
				[System.Collections.ArrayList]$FilesChecked = @(); # This is critical to ensuring that the array isn't a fixed size so that items can be added;
				[System.Collections.ArrayList]$FoldersChecked = @(); # This is critical to ensuring that the array isn't a fixed size so that items can be added;
			}
			
			If ($Services){
				$Services_Count = $Services.Length;
				
				Write-Host "List of $Services_Count services defined:";
				
				$WindowsServices = @();
				
				ForEach ($Service in $Services){
					$WindowsService = Get-WmiObject Win32_Service -Filter "Name = '$Service'" | Select Name, DisplayName, PathName;
					
					If ($WindowsService){
						Write-Host "`t• '$Service' : Found";
						
						$WindowsServices += $WindowsService;
					} Else {
						Write-Host "`t• '$Service' : Not found - ensure that you've provided a service name, not a display name, and that the service exists";
					}
				}
			} Else {
				$WindowsServices = Get-WmiObject Win32_Service -ErrorAction Stop | Select Name, DisplayName, PathName | Sort-Object DisplayName;
			}
			
			If (-Not ($WindowsServices)) {
				Write-Host -ForegroundColor Red "[ERROR] Could not find any Windows services. Exiting...";
				
				Break;
			}
			
			Write-Host "";
			
			$WindowsServices_Total = $WindowsServices.Length;
			
			For ($i = 0; $i -LT $WindowsServices_Total; $i++) {
				$Count = $i + 1;
				
				$WindowsService_ServiceName = $WindowsServices[$i].Name;
				$WindowsService_DisplayName = $WindowsServices[$i].DisplayName;
				$WindowsService_Path = $WindowsServices[$i].PathName;
				$WindowsService_Path -Match '(.+exe"*)(.*)' | Out-Null;
				$WindowsService_File_Path_Original = $Matches[1];
				$WindowsService_File_Path_NoQuotes = $WindowsService_File_Path_Original.Trim('"');
				$WindowsService_Path_Arguments = $Matches[2]
				$WindowsService_Folder_Path = Split-Path -Parent $WindowsService_File_Path_NoQuotes;
				
				Write-Host "Count                                              : #$Count of #$WindowsServices_Total";
				Write-Host "Display name                                       : $WindowsService_DisplayName";
				Write-Host "Service name                                       : $WindowsService_ServiceName";
				Write-Host "Image path / path to executable and any parameters : $WindowsService_Path";
				
				If ($FoldersChecked -Contains $WindowsService_Folder_Path){
					Write-Host -ForegroundColor DarkGreen "[Pass] Folder ($WindowsService_Folder_Path): Security has already been checked.";
				} Else {
					$FoldersChecked += $WindowsService_Folder_Path;
					
					If (Test-Path $WindowsService_Folder_Path) {
						Write-Host -ForegroundColor Gray "[Unknown] Folder ($WindowsService_Folder_Path): Security has not yet been checked...";
						
						Ensure-SecurePermissions -Path $WindowsService_Folder_Path -ServiceName $WindowsService_ServiceName;
					} Else {
						Write-Host -ForegroundColor DarkGreen "[Pass] Folder ($WindowsService_Folder_Path): Ignoring as doesn't actually exist.";
					}
				}
				
				If ($FilesChecked -Contains $WindowsService_File_Path_NoQuotes){
					Write-Host -ForegroundColor DarkGreen "[Pass] File ($WindowsService_File_Path_NoQuotes): Security has already been checked.";
				} Else {
					$FilesChecked += $WindowsService_File_Path_NoQuotes;
					
					If (Test-Path $WindowsService_File_Path_NoQuotes) {
						Write-Host -ForegroundColor Gray "[Unknown] File ($WindowsService_File_Path_NoQuotes): Security has not yet been checked...";
						
						Ensure-SecurePermissions -Path $WindowsService_File_Path_NoQuotes -ServiceName $WindowsService_ServiceName;
					} Else {
						Write-Host -ForegroundColor DarkGreen "[Pass] File ($WindowsService_File_Path_NoQuotes): Ignoring as doesn't actually exist.";
					}
				}
				
				If ($WindowsService_File_Path_Original -Like '* *'){
					If ($WindowsService_File_Path_Original -Match '^".+".*$'){
						Write-Host -ForegroundColor DarkGreen "[Pass] Executable path ($WindowsService_File_Path_Original): Spaces AND wrapping quotation marks found.";
					} Else {
						Write-Host -ForegroundColor Yellow "[WARNING] Executable path ($WindowsService_File_Path_Original): Spaces but no wrapping quotation marks found.";
						
						$global:InsecureWindowsServices += $WindowsService_ServiceName;
						# Write-Host "$WindowsService_ServiceName added to InsecureWindowsServices";
						
						If (-Not $ReportOnly){
							If ($WindowsService_Path_Arguments){
								Ensure-QuotesAndSpaces -ServiceName $WindowsService_ServiceName -ServicePath $WindowsService_File_Path_Original -Arguments $WindowsService_Path_Arguments;
							} Else {
								Ensure-QuotesAndSpaces -ServiceName $WindowsService_ServiceName -ServicePath $WindowsService_File_Path_Original;
							}
						}
					}
				} Else {
					Write-Host -ForegroundColor DarkGreen "[Pass] Executable path ($WindowsService_File_Path_Original): No spaces found.";
				}
				
				Write-Host "";
			}
		}
		
		Catch {
			Write-Host -ForegroundColor Red "[ERROR] Could not secure all Windows services.";
			$_.Exception.Message;
			$_.Exception.ItemName;
			Break;
		}
	}
	
	End {
		If($?){
			$SecuredWindowsServices_Unique = @(); # Must initialise as array because if there's only one instance then it'd be a string and only the first character will be printed later;
			$SecuredWindowsServices_Unique += $global:SecuredWindowsServices | Get-Unique;
			$SecuredWindowsServices_Unique_Total = $SecuredWindowsServices_Unique.Count;
			$InsecureWindowsServices_Unique = @();
			$InsecureWindowsServices_Unique += $global:InsecureWindowsServices | Get-Unique;
			$InsecureWindowsServices_Unique_Total = $InsecureWindowsServices_Unique.Count;
			
			If (($SecuredWindowsServices_Unique_Total -Eq 0) -And ($InsecureWindowsServices_Unique_Total -Eq 0)){
				Write-Host -ForegroundColor DarkGreen "[Pass] All $WindowsServices_Total services were already secure.";
			} Else {
				Write-Host "Of $WindowsServices_Total services, $SecuredWindowsServices_Unique_Total were insecure and have now been secured.";
				If ($SecuredWindowsServices_Unique_Total -GE 1){
					
					For ($i = 0; $i -LT $SecuredWindowsServices_Unique_Total; $i++) {
						$Count = $i + 1;
						
						$SecuredWindowsServices_Name = $SecuredWindowsServices_Unique[$i];
						Write-Host "`t$Count. '$SecuredWindowsServices_Name'";
					}
				}
				
				Write-Host "";
				
				Write-Host "Of $WindowsServices_Total services, $InsecureWindowsServices_Unique_Total were insecure and were not secured.";
				If ($InsecureWindowsServices_Unique_Total -GE 1){
					
					For ($i = 0; $i -LT $InsecureWindowsServices_Unique_Total; $i++) {
						$Count = $i + 1;
						
						$InsecureWindowsServices_Name = $InsecureWindowsServices_Unique[$i];
						Write-Host "`t$Count. '$InsecureWindowsServices_Name'";
					}
				}
				
				Write-Host "";
				
				Write-Host "For details, review the output.";
			}
		}
	}
}

Function Ensure-SecurePermissions {
	Param(
		[Parameter(Mandatory=$true)][String]$Path,
		[Parameter(Mandatory=$true)][String]$ServiceName
	)
	
	Begin {
		
	}
	
	Process {
		Try {
			$BuiltInGroup_Everyone_SID = "S-1-1-0";
			$BuiltInGroup_AuthenticatedUsers_SID = "S-1-5-11";
			$BuiltInGroup_BUILTINUsers_SID = "S-1-5-32-545";
			$BuiltInGroup_DomainUsers_SID_Regex = "^S-1-5-\d{2}-\d{8,10}-\d{8,10}-\d{8,10}-513$"; # Example: S-1-5-21-825004127-3361314978-501030651-513
			
			$ACL = Get-ACL $Path;
			$ACL_Access = $ACL | Select -Expand Access;
			
			$InsecurePermissionsFound = $False;
			
			ForEach ($ACE_Current in $ACL_Access) {
				$SecurityPrincipal_Name = $ACE_Current.IdentityReference;
				If ($FullOutput -Eq $True) { Write-Host "`t[Info] Current / original ACE security principal identity reference: $SecurityPrincipal_Name"; }
				Try {
					# Identity references such as SIDs (where the principal has been deleted), "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES", and "APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES" cause error 'Exception calling "Translate" with "1" argument(s): "Some or all identity references could not be translated."' so we need to do this in a Try-Catch
					$SecurityPrincipal_SID = (New-Object System.Security.Principal.NTAccount($SecurityPrincipal_Name)).Translate([System.Security.Principal.SecurityIdentifier]).Value;
					If ($FullOutput -Eq $True) { Write-Host "`t[Info] Current / original ACE security principal SID: $SecurityPrincipal_SID"; }
				} Catch {
					If ($FullOutput -Eq $True) { Write-Host "`t[Info] Current / original ACE security principal SID: Untranslatable, skipping"; Write-Host ""; }
					# Skip this loop iteration
					Continue;
				}
				$Permissions = $ACE_Current.FileSystemRights.ToString() -Split ", ";
				If ($FullOutput -Eq $True) { Write-Host "`t[Info] Current / original ACE security principal rights: $Permissions"; }
				$Inheritance = $ACE_Current.IsInherited;
				If ($FullOutput -Eq $True) { Write-Host "`t[Info] Current / original ACE security principal rights inherited: $Inheritance"; }
				
				ForEach ($Permission in $Permissions){
					If ((($Permission -Eq "FullControl") -Or ($Permission -Eq "Modify") -Or ($Permission -Eq "Write")) -And (($SecurityPrincipal_SID -Eq $BuiltInGroup_Everyone_SID) -Or ($SecurityPrincipal_SID -Eq $BuiltInGroup_AuthenticatedUsers_SID) -Or ($SecurityPrincipal_SID -Eq $BuiltInGroup_BUILTINUsers_SID) -Or ($SecurityPrincipal_SID -Match $BuiltInGroup_DomainUsers_SID_Regex))) {
						$InsecurePermissionsFound = $True;
						$WindowsServiceSecured = $False;
						
						Write-Host -ForegroundColor Yellow "`t[WARNING] Insecure Access Control Entry (ACE) found: '$Permission' granted to '$SecurityPrincipal_Name'.";
						
						$global:InsecureWindowsServices += $ServiceName;
						# Write-Host "$ServiceName added to InsecureWindowsServices";
						
						If (-Not $ReportOnly){
							If ($Inheritance -Eq $True){
								$Error.Clear();
								Try {
									$ACL.SetAccessRuleProtection($True,$True);
									Set-Acl -Path $Path -AclObject $ACL;
								} Catch {
									Write-Host -ForegroundColor Red "`t`t[FAIL] Could not convert Access Control List (ACL) from inherited to explicit.";
								}
								If (!$Error){
									Write-Host -ForegroundColor DarkGreen "`t`t[Success] Converted Access Control List (ACL) from inherited to explicit.";
								}
								
								# Once permission inheritance has been disabled, the permissions need to be re-acquired in order to remove ACEs
								$ACL = Get-ACL $Path;
							}
						
							$Error.Clear();
							If ((($Path -Eq "C:\Windows\system32\svchost.exe") -Or ($Path -Eq "C:\Windows\system32")) -And ($SecurityPrincipal_SID -Eq $BuiltInGroup_BUILTINUsers_SID)) {
								Write-Host "`t`t[Info] Windows service is a default located in a system location so Access Control Entry (ACE) for 'BUILTIN\Users' should be read & execute.";
								Try {
									$ACE = New-Object System.Security.AccessControl.FileSystemAccessRule($SecurityPrincipal_Name, "ReadAndExecute", , , "Allow");
									$ACL.SetAccessRule($ACE);
									Set-Acl -Path $Path -AclObject $ACL;
								} Catch {
									Write-Host -ForegroundColor Red "`t`t[FAIL] Insecure Access Control Entry (ACE) could not be corrected.";
									$global:SecuredWindowsServices.Remove($ServiceName);
									# Write-Host "$ServiceName removed from SecuredWindowsServices";
								}
								If (!$Error){
									$WindowsServiceSecured = $True;
									Write-Host -ForegroundColor DarkGreen "`t`t[Pass] Corrected insecure Access Control Entry (ACE).";
								}
							} Else {
								Try {
									$ACE = New-Object System.Security.AccessControl.FileSystemAccessRule($SecurityPrincipal_Name, $Permission, , , "Allow");
									$ACL.RemoveAccessRuleAll($ACE);
									Set-Acl -Path $Path -AclObject $ACL;
								} Catch {
									Write-Host -ForegroundColor Red "`t`t[FAIL] Insecure Access Control Entry (ACE) could not be removed.";
									$global:SecuredWindowsServices.Remove($ServiceName);
									# Write-Host "$ServiceName removed from SecuredWindowsServices";
								}
								If (!$Error){
									$WindowsServiceSecured = $True;
									Write-Host -ForegroundColor DarkGreen "`t`t[Pass] Removed insecure Access Control Entry (ACE).";
								}
							}
						}
						
						If ($WindowsServiceSecured -Eq $True){
							$global:InsecureWindowsServices.Remove($ServiceName);
							# Write-Host "$ServiceName removed from InsecureWindowsServices";
							
							$global:SecuredWindowsServices += $ServiceName;
							# Write-Host "$ServiceName added to SecuredWindowsServices";
						}
					}
				}
				If ($FullOutput -Eq $True) { Write-Host ""; }
			}
			
			If ($InsecurePermissionsFound -Eq $False) {
				Write-Host -ForegroundColor DarkGreen "`t[Pass] No insecure Access Control Entries (ACEs) found.";
			}
		}
		
		Catch {
			Write-Host -ForegroundColor Red "`t[ERROR] Could not ensure security of Windows service.";
			$_.Exception.Message;
			$_.Exception.ItemName;
			Break;
		}
	}
	
	End {
		If($?){
			
		}
	}
}

Function Ensure-QuotesAndSpaces {
	Param(
		[Parameter(Mandatory=$true)][String]$ServiceName,
		[Parameter(Mandatory=$true)][String]$ServicePath,
		[String]$Arguments
	)
	
	Begin {
		
	}
	
	Process {
		Try {			
			$RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\" + $ServiceName;
			$RegistryValue = '"' + $ServicePath + '"';	
						
			If ($Arguments){
				$RegistryValue += $Arguments;
			}
			
			Set-ItemProperty -Path $RegistryPath -Name "ImagePath" -Value $RegistryValue -Force -ErrorAction SilentlyContinue | Out-Null;
			
			If ((Get-ItemProperty -Path $RegistryPath -Name "ImagePath").ImagePath -Eq $RegistryValue){
				Write-Host -ForegroundColor DarkGreen "`t[Pass] Changed path to executable, wrapping in quotation marks.";
				Write-Host "`t[Info] New image path: $RegistryValue";
				
				$global:InsecureWindowsServices.Remove($ServiceName);
				# Write-Host "$ServiceName removed from InsecureWindowsServices";
				
				$global:SecuredWindowsServices += $ServiceName;
				# Write-Host "$ServiceName added to SecuredWindowsServices";
				
			} Else {
				Write-Host -ForegroundColor Red "`t[FAIL] Path to executable could not be changed.";
				$global:SecuredWindowsServices.Remove($ServiceName);
				# Write-Host "$ServiceName removed from SecuredWindowsServices";
			}
		}
		
		Catch {
			Write-Host -ForegroundColor Red "[ERROR] Could not add wrapping quotation marks to the path to executable for the Windows service.";
			$_.Exception.Message;
			$_.Exception.ItemName;
			Break;
		}
	}
	
	End {
		If($?){
			
		}
	}
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------

If (-Not $LogPath) {
	$LogPath = $LogPath_Default;
}

# Check write access to log file
If ($LogOutput -Eq $True) {
	Try {
		[io.file]::OpenWrite($LogPath).Close();
	}
	Catch {
		Write-Host -ForegroundColor Red "[ERROR] Unable to log output to file '$LogPath' due to insufficient permissions.";
		Write-Host "";
		
		$LogOutput = $False;
	}
}

# Set up logging
If ($LogOutput -Eq $True) {
	Start-Transcript -Path $LogPath -Append | Out-Null;
	
	Write-Host "Logging output to file.";
	Write-Host "Path: '$LogPath'" 
	
	Write-Host "";
	Write-Host "----------------------------------------------------------------";
	Write-Host "";
}

# Handle admin
If ($RunAsAdministrator -Eq $False) {
	Write-Host "This script requires administrative permissions but was not run as administrator. Elevate now? (y/n)";
	$Elevate = Read-Host "[Input]";

	If (($Elevate -Like "y") -Or ($Elevate -Like "yes")){
		Write-Host "'Yes' selected. Launching a new session in a new window and ending this session...";
		
		# Preserve original parameters
		$AllParameters_String = "";
		ForEach ($Parameter in $PsBoundParameters.GetEnumerator()){
			$Parameter_Key = $Parameter.Key;
			$Parameter_Value = $Parameter.Value;
			$Parameter_Value_Type = $Parameter_Value.GetType().Name;
			
			If ($Parameter_Value_Type -Eq "SwitchParameter"){
				$AllParameters_String += " -$Parameter_Key";
				
			} ElseIf ($Parameter_Value_Type -Eq "String") {
				$AllParameters_String += ' -' + $Parameter_Key + ' "' + $Parameter_Value + '"';
			} Else {
				$AllParameters_String += " -$Parameter_Key $Parameter_Value";
			}
		}
		
		$Arguments = ' -NoExit -File "' + $global:Script_PS1File_FullPath + '"' + $AllParameters_String;
		
		If ($LogOutput -Eq $True) {
			Stop-Transcript | Out-Null;
		}
		
		Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $Arguments;
		
		# Stop-Process -Id $PID;
		
		Break;
	} Else {
		Write-Host "'No' selected. Exiting...";
		
		If ($LogOutput -Eq $True) {
			Stop-Transcript | Out-Null;
		}
		
		Break;
	}
} Else {
	If ((-Not $Force) -And (-Not $ReportOnly)){
		Write-Host "(The following warning can be suppressed by using the parameter / argument / switch '-Force', which will also facilitate usage programmatically.)";
		Write-Host "";
		Write-Host -ForegroundColor Yellow "[WARNING] This script will likely make changes to this computer (e.g., file system rights and image paths / paths to executable) which could break certain functionality. It is recommended that you first perform (1) system backups and (2) small-scale and/or non-production testing. You proceed at your own risk. Are you sure you want to proceed? (y/n)";
		$Proceed = Read-Host "[Input]";

		If (($Proceed -Like "y") -Or ($Proceed -Like "yes")){
			Write-Host "'Yes' selected. Proceeding...";
		} Else {
			Write-Host "'No' selected. Exiting...";
			
			If ($LogOutput -Eq $True) {
				Stop-Transcript | Out-Null;
			}
			
			Break;
		}
	}
	
	Secure-WindowsServices;
}

Write-Host "";
Write-Host "----------------------------------------------------------------";
Write-Host "";

Write-Host "Script complete.";

If ($LogOutput -Eq $True) {
	Stop-Transcript | Out-Null;
}