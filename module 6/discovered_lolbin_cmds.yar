rule asefaExecution
{
	meta:
		author = "Ryan Rogowski"
		description = "Check for a cmd execution of asefa.bat"
	strings:
		$cmd = "Cmd.exe /c C:\ProgramData\asefa.bat"
	condition:
		$cmd
}

rule conhostCMD
{
	meta:
		author = "Ryan Rogowski"
		description = "Check for conhost with args"
	strings:
		$cmd = "\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1"
	condition:
		$cmd
}

rule reqQueryCMD
{
	meta:
		author = "Ryan Rogowski"
		description = "Check for a req query CMD"
	strings:
		$cmd = "reg  query HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
	condition:
		$cmd
}

rule reqAddCMDWindowsDefender
{
	meta:
		author = "Ryan Rogowski"
		description = "Check for a req add CMD WindowsDefender"
	strings:
		$cmd = "reg  add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsDefender" /t REG_SZ /d "C:\ProgramData\SecurityUpdate\svchost.exe" /f"
	condition:
		$cmd
}

rule reqAddCMDSecurityScan
{
	meta:
		author = "Ryan Rogowski"
		description = "Check for a req add CMD SecurityScan"
	strings:
		$cmd = "reg  add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "SecurityScan" /t REG_SZ /d "C:\ProgramData\SecurityUpdate\svchost.exe" /f"
	condition:
		$cmd
}

rule schtasksCMD
{
	meta:
		author = "Ryan Rogowski"
		description = "Check for a schtasks cmd"
	strings:
		$cmd = "schtasks  /create /tn "WindowsUpdateCheck" /tr "C:\ProgramData\SecurityUpdate\svchost.exe" /sc onlogon /rl HIGHEST /f"
	condition:
		$cmd
}

rule attribCMD
{
	meta:
		author = "Ryan Rogowski"
		description = "Check for a attrib CMD that makes file hidden and system"
	strings:
		$cmd = "attrib  +h +s C:\ProgramData\config.dat"
		$cmd2 = "attrib  +h +s C:\ProgramData\network.dat"
		$cmd3 = "attrib  +h +s C:\ProgramData\dns.dat"
		$cmd4 = "attrib  +h +s C:\ProgramData\connections.dat"
		$cmd5 = "attrib  +h +s C:\ProgramData\accounts.dat"
		$cmd6 = "attrib  +h +s C:\ProgramData\userlist.dat"
		$cmd7 = "attrib  +h +s C:\ProgramData\services.dat"
		$cmd8 = "attrib  +h +s C:\ProgramData\jobs.dat"
		$cmd9 = "attrib  +h +s C:\ProgramData\apps.dat"
		$cmd10 = "attrib  +h +s C:\ProgramData\autorun.dat"
		$cmd11 = "attrib  +h +s C:\ProgramData\SecurityUpdate"
	condition:
		$cmd1 or $cmd2 or $cmd3 or $cmd4 or $cmd4 or $cmd5 or $cmd6 or $cmd7 or $cmd8 or $cmd9 or $cmd10 or $cmd11
}

rule netUserCMD
{
	meta:
		author = "Ryan Rogowski"
		description = "Check for net user commands"
	strings:
		$cmd = "net  user Administators Secur1ty@2025 /add"
		$cmd2 = "net  user SYSTEM_SERVICE Svc@Admin#99 /add"
		$cmd3 = "C:\Windows\system32\net1  user Administators Secur1ty@2025 /add"
		$cmd4 = "C:\Windows\system32\net1  user SYSTEM_SERVICE Svc@Admin#99 /add"
	condition:
		$cmd1 or $cmd2 or $cmd3 or $cmd4
}

rule netLocalGroupCMD
{
	meta:
		author = "Ryan Rogowski"
		description = "Check for net user commands"
	strings:
		$cmd = "net  localgroup Administrators Administators /add"
		$cmd2 = "C:\Windows\system32\net1  localgroup Administrators Administators /add "
		$cmd3 = "net  localgroup Administrators SYSTEM_SERVICE /add "
		$cmd4 = "C:\Windows\system32\net1  localgroup Administrators SYSTEM_SERVICE /add"
	condition:
		$cmd1 or $cmd2 or $cmd3 or $cmd4
}

rule wevtutilCMD
{
	meta:
		author = "Ryan Rogowski"
		description = "Check for wevt commands"
	strings:
		$cmd = "wevtutil  cl System"
		$cmd2 = "wevtutil  cl Security"
		$cmd3 = "wevtutil  cl Application"
	condition:
		$cmd1 or $cmd2 or $cmd3
}



 