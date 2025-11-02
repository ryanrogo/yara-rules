rule detect_Perl_backticks
{
	meta:
		author = "Ryan Rogowski"
		description = "Check for backticks (Perl)"
		date = "10/31/2025"
		version = "1.0"
	strings:
        $a = "`"
		
	condition:
		$a
}
