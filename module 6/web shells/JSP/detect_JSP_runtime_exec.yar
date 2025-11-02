rule detect_JSP_runtime_exec
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for runtime and exec being called (JSP)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = /Runtime\.getRuntime\(.*\).exec\(/
		
	condition:
		$func
}
