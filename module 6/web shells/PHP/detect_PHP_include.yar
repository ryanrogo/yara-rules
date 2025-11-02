rule detect_PHP_include
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the include function being called (PHP)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "include("
		
	condition:
		$func
}
