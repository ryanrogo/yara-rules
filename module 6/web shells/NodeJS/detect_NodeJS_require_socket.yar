rule detect_NodeJS_require_socket
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the require and socket function being called (NodeJS) - for outbound connections"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "require('net').Socket("
		
	condition:
		$func
}
