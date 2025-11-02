rule detect_PHP_escapeshellarg
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the escapeshellarg function being called (PHP)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "escapeshellarg("
		
	condition:
		$func
}
