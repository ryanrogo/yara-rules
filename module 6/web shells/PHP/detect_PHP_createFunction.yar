rule detect_PHP_createFunction
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the create_function function being called (PHP)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "create_function("
		
	condition:
		$func
}
