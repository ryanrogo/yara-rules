rule detect_PHP
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects PHP files by for their tag."
		date = "11/01/2025"
		version = "1.0"
	strings:
		$phptag = "<?php"
		
	condition:
		$phptag
}
