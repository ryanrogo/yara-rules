rule detect_QEMU
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects QEMU files by checking the magic number."
		date = "10/31/2025"
		version = "1.0"
	strings:
		$header = {51 46 49 FB}
		
	condition:
		$header at 0
}
