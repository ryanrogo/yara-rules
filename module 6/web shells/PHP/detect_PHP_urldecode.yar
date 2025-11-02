rule detect_PHP_urldecode
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the urldecode function being called (PHP)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "urldecode("
		
	condition:
		$func
}
