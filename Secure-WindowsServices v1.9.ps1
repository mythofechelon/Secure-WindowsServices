<#
.SYNOPSIS
	Name: Secure-WindowsServices.ps1
	Description: The purpose of this script is to secure any Windows services with insecure permissions and unquoted paths.

.NOTES
	Author:								Ben Hooper (https://mythofechelon.co.uk/ / https://github.com/mythofechelon/Secure-WindowsServices/)
	Tested on:							Windows 10 v20H2 64-bit
	Version:							1.9
	Changes in v1.9 (2021/02/06 20:48):	Added fixing of services with spaces and without quotation marks, fixed bug where summary would report that Windows services couldn't be secured when they actually had been, added summary deduplication.
	Changes in v1.8 (2020/03/06 14:08):	Added handling for Windows services where the paths don't actually exist.
	Changes in v1.7 (2019/11/21 10:14):	Corrected "Windows service secured" logic so that it'll only report if it was actually successful in securing it.
	Changes in v1.6 (2019/11/20 14:31):	Fixed compatibility with Windows 7 / PowerShell < 3.0.
	Changes in v1.5 (2019/11/20 13:43):	Added special handling for Windows services located in "C:\Windows\system32\" so that the permissions are reduced to read & execute instead of being removed.
	Changes in v1.4 (2019/11/20 12:33):	Added post-run report of which, if any, services were secured.
	Changes in v1.3 (2019/11/20 11:39):	Updated to bring in line with enhancements of Update-hMailServerCertificate v1.13 (write access check to log file, auto-elevate, coloured statuses, etc) and changed tags to Info, Unknown, Pass, FAIL, Success, and ERROR.
	Changes in v1.2 (2018/10/15):		Enhanced output by (1) changing output type from "check performed-action result" with just "action result" which makes it easier to read with less indentations, (2) adding tags ("[FAILED]", "[SUCCESS]", and "[NOTIFICATION]") for quick checking of results, and (3) tweaking logging behaviour.
	Changes in v1.1 (2018/10/05):		Added handling of inherited permissions.
	
.PARAMETER LogOutput
	Logs the output to the default file path "C:\<hostname>_Secure-WindowsServices.txt".
	
.PARAMETER LogFile
	When used in combination with -LogOutput, logs the output to the custom specified file path.

.EXAMPLE
	Run with the default settings:
		Secure-WindowsServices
		
.EXAMPLE 
	Run with the default settings AND logging to the default path:
		Secure-WindowsServices -LogOutput
	
.EXAMPLE 
	Run with the default settings AND logging to a custom local path:
		Secure-WindowsServices -LogOutput -LogPath "C:\$env:computername_Secure-WindowsServices.txt"
	
.EXAMPLE 
	Run with the default settings AND logging to a custom network path:
		Secure-WindowsServices -LogOutput -LogPath "\\servername\filesharename\$env:computername_Secure-WindowsServices.txt"
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

Param(
	[switch]$LogOutput,
	[string]$LogPath
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
		Write-Host "Securing all Windows services...";
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
			
			$WindowsServices = Get-WmiObject Win32_Service -ErrorAction Stop | Select Name, DisplayName, PathName | Sort-Object DisplayName;
			
			If (-Not ($WindowsServices)) {
				Write-Host -ForegroundColor Red "`t[ERROR] Could not find any Windows services. Exiting...";
				
				Break;
			}
			
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
				
				Write-Host "`tWindows service '$WindowsService_DisplayName' ($Count of $WindowsServices_Total)...";
				
				If ($FoldersChecked -Contains $WindowsService_Folder_Path){
					Write-Host -ForegroundColor Green "`t`t[Pass] Folder '$WindowsService_Folder_Path': Security has already been ensured.";
				} Else {
					$FoldersChecked += $WindowsService_Folder_Path;
					
					If (Test-Path $WindowsService_Folder_Path) {
						Write-Host -ForegroundColor Yellow "`t`t[Unknown] Folder '$WindowsService_Folder_Path': Security has not yet been ensured...";
						
						Ensure-SecurePermissions -Path $WindowsService_Folder_Path -DisplayName $WindowsService_DisplayName;
					} Else {
						Write-Host -ForegroundColor Green "`t`t[Pass] Folder '$WindowsService_Folder_Path': Ignoring as doesn't actually exist.";
					}
				}
				
				If ($FilesChecked -Contains $WindowsService_File_Path_NoQuotes){
					Write-Host -ForegroundColor Green "`t`t[Pass] File '$WindowsService_File_Path_NoQuotes': Security has already been ensured.";
				} Else {
					$FilesChecked += $WindowsService_File_Path_NoQuotes;
					
					If (Test-Path $WindowsService_File_Path_NoQuotes) {
						Write-Host -ForegroundColor Yellow "`t`t[Unknown] File '$WindowsService_File_Path_NoQuotes': Security has not yet been ensured...";
						
						Ensure-SecurePermissions -Path $WindowsService_File_Path_NoQuotes -DisplayName $WindowsService_DisplayName;
					} Else {
						Write-Host -ForegroundColor Green "`t`t[Pass] File '$WindowsService_File_Path_NoQuotes': Ignoring as doesn't actually exist.";
					}
				}
				
				If ($WindowsService_File_Path_Original -Like '* *'){
					If ($WindowsService_File_Path_Original -Match '^".+".*$'){
						Write-Host -ForegroundColor Green "`t`t[Pass] Executable path '$WindowsService_File_Path_Original': Spaces AND wrapping quotation marks found.";
					} Else {
						Write-Host -ForegroundColor Yellow "`t`t[WARNING] Executable path '$WindowsService_File_Path_Original': Spaces but no wrapping quotation marks found.";
						
						$global:InsecureWindowsServices += $WindowsService_DisplayName;
						# Write-Host "$WindowsService_DisplayName added to InsecureWindowsServices";
						
						If ($WindowsService_Path_Arguments){
							Ensure-QuotesAndSpaces -ServiceName $WindowsService_ServiceName -DisplayName $WindowsService_DisplayName -Path $WindowsService_File_Path_Original -Arguments $WindowsService_Path_Arguments;
						} Else {
							Ensure-QuotesAndSpaces -ServiceName $WindowsService_ServiceName -DisplayName $WindowsService_DisplayName -Path $WindowsService_File_Path_Original;
						}
					}
				} Else {
					Write-Host -ForegroundColor Green "`t`t[Pass] Executable path '$WindowsService_File_Path_Original': No spaces found.";
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
			$InsecureWindowsServices_Unique = @();
			$InsecureWindowsServices_Unique += $global:InsecureWindowsServices | Get-Unique;
			$SecuredWindowsServices_Unique_Total = $SecuredWindowsServices_Unique.Count;
			$InsecureWindowsServices_Unique_Total = $InsecureWindowsServices_Unique.Count;
			
			If ($SecuredWindowsServices_Unique_Total -Eq $InsecureWindowsServices_Unique_Total){
				If ($SecuredWindowsServices_Unique_Total -Eq 0){
					Write-Host -ForegroundColor Green "[Pass] All Windows services were already secure.";
				} Else {
					If ($SecuredWindowsServices_Unique_Total -Eq 1){
						Write-Host -ForegroundColor Green "[Success] The sole insecure Windows service was secured:";
					} Else {
						Write-Host -ForegroundColor Green "[Success] All $SecuredWindowsServices_Unique_Total insecure Windows services were secured:";
					}
					
					For ($i = 0; $i -LT $SecuredWindowsServices_Unique_Total; $i++) {
						$Count = $i + 1;
						
						$SecuredWindowsServices_DisplayName = $SecuredWindowsServices_Unique[$i];
						Write-Host "`t$Count. '$SecuredWindowsServices_DisplayName'";
					}
				}
			} Else {
				Write-Host -ForegroundColor Red "[ERROR] Not all Windows services could be secured. Please review the log.";
			}
		}
	}
}

Function Ensure-SecurePermissions {
	Param(
		[Parameter(Mandatory=$true)][String]$Path,
		[Parameter(Mandatory=$true)][String]$DisplayName
	)
	
	Begin {
		
	}
	
	Process {
		Try {
			$ACL = Get-ACL $Path;
			$ACL_Access = $ACL | Select -Expand Access;
			
			$InsecurePermissionsFound = $False;
			
			ForEach ($ACE_Current in $ACL_Access) {
				$SecurityPrincipal = $ACE_Current.IdentityReference;
				$Permissions = $ACE_Current.FileSystemRights.ToString() -Split ", ";
				$Inheritance = $ACE_Current.IsInherited;
				
				ForEach ($Permission in $Permissions){
					If ((($Permission -Eq "FullControl") -Or ($Permission -Eq "Modify") -Or ($Permission -Eq "Write")) -And (($SecurityPrincipal -Eq "Everyone") -Or ($SecurityPrincipal -Eq "NT AUTHORITY\Authenticated Users") -Or ($SecurityPrincipal -Eq "BUILTIN\Users") -Or ($SecurityPrincipal -Eq "$Env:USERDOMAIN\Domain Users"))) {
						$InsecurePermissionsFound = $True;
						$WindowsServiceSecured = $False;
						
						Write-Host -ForegroundColor Yellow "`t`t`t[WARNING] Insecure Access Control Entry (ACE) found: '$Permission' granted to '$SecurityPrincipal'.";
						
						If (-Not ($global:InsecureWindowsServices -Contains $DisplayName)){
							$global:InsecureWindowsServices += $DisplayName;
							# Write-Host "$DisplayName added to InsecureWindowsServices";
						}
						
						If ($Inheritance -Eq $True){
							$Error.Clear();
							Try {
								$ACL.SetAccessRuleProtection($True,$True);
								Set-Acl -Path $Path -AclObject $ACL;
							} Catch {
								Write-Host -ForegroundColor Red "`t`t`t`t[FAIL] Could not convert Access Control List (ACL) from inherited to explicit.";
							}
							If (!$Error){
								Write-Host -ForegroundColor Green "`t`t`t`t[Success] Converted Access Control List (ACL) from inherited to explicit.";
							}
							
							# Once permission inheritance has been disabled, the permissions need to be re-acquired in order to remove ACEs
							$ACL = Get-ACL $Path;
						}
						
						$Error.Clear();
						If ((($Path -Eq "C:\Windows\system32\svchost.exe") -Or ($Path -Eq "C:\Windows\system32")) -And ($SecurityPrincipal -Eq "BUILTIN\Users")) {
							Write-Host "`t`t`t`t[Info] Windows service is a default located in a system location so Access Control Entry (ACE) for 'BUILTIN\Users' should be read & execute.";
							Try {
								$ACE = New-Object System.Security.AccessControl.FileSystemAccessRule($SecurityPrincipal, "ReadAndExecute", , , "Allow");
								$ACL.SetAccessRule($ACE);
								Set-Acl -Path $Path -AclObject $ACL;
							} Catch {
								Write-Host -ForegroundColor Red "`t`t`t`t[FAIL] Insecure Access Control Entry (ACE) could not be corrected.";
							}
							If (!$Error){
								$WindowsServiceSecured = $True;
								Write-Host -ForegroundColor Green "`t`t`t`t[Pass] Corrected insecure Access Control Entry (ACE).";
							}
						} Else {
							Try {
								$ACE = New-Object System.Security.AccessControl.FileSystemAccessRule($SecurityPrincipal, $Permission, , , "Allow");
								$ACL.RemoveAccessRuleAll($ACE);
								Set-Acl -Path $Path -AclObject $ACL;
							} Catch {
								Write-Host -ForegroundColor Red "`t`t`t`t[FAIL] Insecure Access Control Entry (ACE) could not be removed.";
							}
							If (!$Error){
								$WindowsServiceSecured = $True;
								Write-Host -ForegroundColor Green "`t`t`t`t[Pass] Removed insecure Access Control Entry (ACE).";
							}
						}
						
						If (($WindowsServiceSecured -Eq $True) -And (-Not ($global:SecuredWindowsServices -Contains $DisplayName))){
							$global:SecuredWindowsServices += $DisplayName;
							# Write-Host "$DisplayName added to SecuredWindowsServices";
						}	
					}
				}
			}
			
			If ($InsecurePermissionsFound -Eq $False) {
				Write-Host -ForegroundColor Green "`t`t`t[Pass] No insecure Access Control Entries (ACEs) found.";
			}
		}
		
		Catch {
			Write-Host -ForegroundColor Red "`t`t`t[ERROR] Could not ensure security of Windows service.";
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
		[Parameter(Mandatory=$true)][String]$DisplayName,
		[Parameter(Mandatory=$true)][String]$Path,
		[String]$Arguments
	)
	
	Begin {
		
	}
	
	Process {
		Try {
			$SCArguments = 'config ' + $ServiceName + ' binPath= "\"' + $Path + '\"';
			
			If ($Arguments){
				$SCArguments += $Arguments + '"'; 
			} Else {
				$SCArguments += '"';
			}
			
			$Process = Start-Process -FilePath "sc" -ArgumentList $SCArguments -WindowStyle Hidden -PassThru -Wait;
			If ($Process.ExitCode -Eq 0){
				Write-Host -ForegroundColor Green "`t`t`t[Pass] Modified / reconfigured path to executable wrapping in quotation marks.";
				
				$global:SecuredWindowsServices += $DisplayName;
				# Write-Host "$DisplayName added to SecuredWindowsServices";
			} Else {
				Write-Host -ForegroundColor Red "`t`t`t[FAIL] Windows service could not be modified / reconfigured.";
			}
		}
		
		Catch {
			Write-Host -ForegroundColor Red "`t`t[ERROR] Could not add wrapping quotation marks to the path to executable for the Windows service.";
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
	Secure-WindowsServices;
}

Write-Host "";
Write-Host "----------------------------------------------------------------";
Write-Host "";

Write-Host "Script complete.";

If ($LogOutput -Eq $True) {
	Stop-Transcript | Out-Null;
}