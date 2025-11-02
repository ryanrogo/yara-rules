rule detect_generic_powershellexe
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for powershellexe"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "\"powershell.exe \""
		
	condition:
		$func
}
