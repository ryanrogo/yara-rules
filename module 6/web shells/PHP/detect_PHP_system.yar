rule detect_PHP_system
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the system function being called (PHP)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "system("
		
	condition:
		$func
}
