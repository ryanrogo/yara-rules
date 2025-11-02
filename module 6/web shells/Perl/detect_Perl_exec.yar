rule detect_Perl_exec
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the exec function being called (Perl)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "exec("
		
	condition:
		$func
}
