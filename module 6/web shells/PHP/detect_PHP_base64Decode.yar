rule detect_PHP_base64Decode
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the base64_decode function being called (PHP)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "base64_decode("
		
	condition:
		$func
}
