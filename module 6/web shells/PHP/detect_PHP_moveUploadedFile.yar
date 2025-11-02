rule detect_PHP_moveUploadedFile
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the move_uploaded_file function being called (PHP)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "move_uploaded_file("
		
	condition:
		$func
}
