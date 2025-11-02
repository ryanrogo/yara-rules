rule detect_NodeJS_require_spawn
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the require and spawn function being called (NodeJS)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "require('child_process').spawn("
		
	condition:
		$func
}
