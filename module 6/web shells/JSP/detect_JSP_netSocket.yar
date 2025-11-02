rule detect_JSP_netSocket
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for java.net.Socket being called (JSP) - for reverse/bind shells"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "java.net.Socket"
		
	condition:
		$func
}
