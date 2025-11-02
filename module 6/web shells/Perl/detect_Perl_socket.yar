rule detect_Perl_socket
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the socket function being called (Perl)"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$func = "socket("
		
	condition:
		$func
}
