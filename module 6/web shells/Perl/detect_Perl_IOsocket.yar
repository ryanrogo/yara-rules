rule detect_Perl_IOsocket
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the IO::Socket being used (Perl)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "IO::Socket("
		
	condition:
		$func
}
