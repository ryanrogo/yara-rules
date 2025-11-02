rule detect_PHP_shellExec
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the shell_exec function being called (PHP)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "shell_exec("
		
	condition:
		$func
}
