rule detect_Perl_do
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the do function being called (Perl)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "do("
		
	condition:
		$func
}
