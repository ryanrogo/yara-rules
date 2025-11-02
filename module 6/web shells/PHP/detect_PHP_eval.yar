rule detect_PHP_eval
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the eval function being called (PHP)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "eval("
		
	condition:
		$func
}
