rule detect_NodeJS_require_createWriteStream
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the require and createWriteStream function being called (NodeJS)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "require('fs').createWriteStream("
		
	condition:
		$func
}
