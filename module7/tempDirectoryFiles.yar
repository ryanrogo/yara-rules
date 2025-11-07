rule tempDirectoryFiles
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for calls that involve temporary directories, as common place to hide files"
		date = "11/07/2025"
		version = "1.0"
	strings:
		$call = /fopen\("\/tmp\/.*", "w"\)/
		
	condition:
		$call
}