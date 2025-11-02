rule detect_JSP_Classloader_defineClass
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for ClassLoader.defineClass being called (JSP)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "ClassLoader.defineClass("
		
	condition:
		$func
}
