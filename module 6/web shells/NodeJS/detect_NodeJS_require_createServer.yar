rule detect_NodeJS_require_createServer
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the require and createServer function being called (NodeJS) - used for reverse shell"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "require('http').createServer("
		
	condition:
		$func
}
