import "pe"

rule hasDOStext
{
	meta:
		author = "Ryan Rogowski"
	description = "check if PE contains DOS stub"
	date = "2025-09-17"

	strings:
		$dos = {54 68 69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F 74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20 6D 6F 64 65}

	condition:
	// check as only PE will contain this stub
	// could be more specific
		pe.is_pe and $dos
}