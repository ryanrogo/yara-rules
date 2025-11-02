rule detect_PHP_procOpen
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the proc_open function being called (PHP)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "proc_open("
		
	condition:
		$func
}
