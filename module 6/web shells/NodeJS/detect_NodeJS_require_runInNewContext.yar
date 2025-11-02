rule detect_NodeJS_require_runInNewContext
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the require and runInNewContext function being called (NodeJS)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "require('vm').runInNewContext("
		
	condition:
		$func
}
