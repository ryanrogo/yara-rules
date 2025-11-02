rule detect_generic_cmd_c
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the cmd /c"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "cmd /c"
		
	condition:
		$func
}
