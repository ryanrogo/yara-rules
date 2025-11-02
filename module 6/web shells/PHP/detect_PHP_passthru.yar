rule detect_PHP_passthru
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the passthru function being called (PHP)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "passthru("
		
	condition:
		$func
}
