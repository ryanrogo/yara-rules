rule detect_NodeJS_require_spawnSync
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the require and spawnSync function being called (NodeJS)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "require('child_process').spawnSync("
		
	condition:
		$func
}
