rule detect_PHP_assert
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the assert function being called (PHP)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "assert("
		
	condition:
		$func
}
