rule detect_PHP_includeOnce
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the include_once function being called (PHP)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "include_once("
		
	condition:
		$func
}
