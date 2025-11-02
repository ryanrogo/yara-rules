rule detect_PHP_gzinflate
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the gzinflate function being called (PHP)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "gzinflate("
		
	condition:
		$func
}
