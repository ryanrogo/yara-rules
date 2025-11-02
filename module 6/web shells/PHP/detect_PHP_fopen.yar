rule detect_PHP_fopen
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the fopen function being called (PHP)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "fopen("
		
	condition:
		$func
}
