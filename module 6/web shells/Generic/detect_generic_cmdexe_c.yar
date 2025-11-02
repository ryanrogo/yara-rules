rule detect_generic_cmdexe_c
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the cmd.exe /c"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "cmd.exe /c"
		
	condition:
		$func
}
