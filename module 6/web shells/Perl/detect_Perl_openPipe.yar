rule detect_Perl_openPipe
{
	meta:
		author = "Ryan Rogowski"
		description = "Check for open func and a pipe (Perl)"
		date = "10/31/2025"
		version = "1.0"
	strings:
        $a = /open\s*\([^,]+,\s*["'].*\|.*["']\s*\)/
		
	condition:
		$a
}
