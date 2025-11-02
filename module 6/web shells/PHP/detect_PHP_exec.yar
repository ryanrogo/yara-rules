rule detect_PHP_exec
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the exec function being called (PHP)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "exec("
		
	condition:
		$func
}
