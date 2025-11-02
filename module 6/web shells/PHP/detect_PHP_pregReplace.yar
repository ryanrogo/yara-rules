rule detect_PHP_pregReplace
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the preg_replace function being called (PHP)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "preg_replace("
		$modif = "/e"
		
	condition:
		$func and $modif
}
