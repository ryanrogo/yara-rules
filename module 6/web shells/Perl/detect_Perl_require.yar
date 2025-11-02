rule detect_Perl_require
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the require function being called (Perl)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "require("
		
	condition:
		$func
}
