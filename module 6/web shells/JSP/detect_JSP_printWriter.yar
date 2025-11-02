rule detect_JSP_printWriter
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for new java.io.PrintWriter being called (JSP)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "new java.io.PrintWriter("
		
	condition:
		$func
}
