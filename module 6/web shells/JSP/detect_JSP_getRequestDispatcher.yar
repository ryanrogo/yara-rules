rule detect_JSP_getRequestDispatcher
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for getRequestDispatcher and include being called (JSP)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = /request.getRequestDispatcher\(.*\).include\(/
		
	condition:
		$func
}
