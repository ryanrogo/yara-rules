rule detect_Perl_forkexec
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for fork and exec being called (Perl)"
		date = "10/31/2025"
		version = "1.0"
	strings:
        $fork = "fork("
        $exec = "exec("
		
	condition:
		$fork and $exec
}
