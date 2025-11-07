rule forkExeve
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for a fork() call followed by an execve()"
		date = "11/07/2025"
		version = "1.0"
	strings:
		$call1 = "fork("
		$call2 = "execve("
		
	condition:
		$call1 and $call2
}