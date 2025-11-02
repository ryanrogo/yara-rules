rule detect_NodeJS_require_writeFileSync
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the require and writeFileSync function being called (NodeJS)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "require('fs').writeFileSync("
		
	condition:
		$func
}
