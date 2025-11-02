rule detect_JSP_reflect_invoke
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the java.lang.reflect.Method.invoke being called (JSP)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "java.lang.reflect.Method.invoke("
		
	condition:
		$func
}
