rule detect_JSP_SystemSet_streamManip
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for System.setIn/Out/Err (JSP) - stream manipulation"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = /System.setIn\(.*\), System.setOut\(.*\), System.setErr\(/
		
	condition:
		$func
}
