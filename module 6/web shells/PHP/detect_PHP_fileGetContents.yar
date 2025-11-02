rule detect_PHP_fileGetContents
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the file_get_contents function being called (PHP)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "file_get_contents("
		
	condition:
		$func
}
