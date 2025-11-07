rule networkSockets
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for calls that create network sockets (socket, bind, connect) - could be used for backdoor/C2 communication"
		date = "11/07/2025"
		version = "1.0"
	strings:
		$call1 = "socket("
		$call2 = "bind("
		$call3 = "connect("
		
	condition:
		any of them
}