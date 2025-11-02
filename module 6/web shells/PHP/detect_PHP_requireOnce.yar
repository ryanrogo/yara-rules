rule detect_PHP_requireOnce
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the require_once function being called (PHP)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "require_once("
		
	condition:
		$func
}
