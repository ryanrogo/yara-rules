rule detect_PHP_popen
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the popen function being called (PHP)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "popen("
		
	condition:
		$func
}
