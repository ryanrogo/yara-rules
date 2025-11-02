rule detect_generic_powershell
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for powershell"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "\"powershell \""
		
	condition:
		$func
}
