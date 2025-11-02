rule detect_Perl_eval
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the eval function being called (Perl)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "eval("
		
	condition:
		$func
}
