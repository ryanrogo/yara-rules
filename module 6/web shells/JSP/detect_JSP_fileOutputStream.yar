rule detect_JSP_fileOutputStream
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for new java.io.FileOutputStream being called (JSP)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "new java.io.FileOutputStream("
		
	condition:
		$func
}
