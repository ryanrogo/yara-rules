rule detect_Perl_readpipe
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the readpipe function being called (Perl)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "readpipe("
		
	condition:
		$func
}
