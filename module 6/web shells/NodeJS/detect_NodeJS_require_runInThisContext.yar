rule detect_NodeJS_require_runInThisContext
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the require and runInThisContext function being called (NodeJS)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "require('vm').runInThisContext("
		
	condition:
		$func
}
