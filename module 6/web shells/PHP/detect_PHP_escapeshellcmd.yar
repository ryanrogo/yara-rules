rule detect_PHP_escapeshellcmd
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the escapeshellcmd function being called (PHP)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "escapeshellcmd("
		
	condition:
		$func
}
