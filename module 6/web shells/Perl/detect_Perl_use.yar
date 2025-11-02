rule detect_Perl_use
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the use function being called (Perl)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "use("
		
	condition:
		$func
}
