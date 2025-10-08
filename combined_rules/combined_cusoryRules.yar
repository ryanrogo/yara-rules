import "pe"
import "math"

rule fileUsingUPX
{
	meta:
		author = "Ryan Rogowski"
		description = "check if file is packed with UPX"
		date = "2025-09-15"
	strings:
		$upx0 = "UPX0"
		$upx1 = "UPX1"
		$upx2 = "UPX2"
	condition:
		$upx0 or $upx1 or $upx2

}


rule detect_unusual_string
{
	meta:
	   author = "Kenneth Moran"
	   description = "Alert if strings found in sections with no strings usually"
	   date = "9/17/2025"

	strings:
	   $expectedException1 = ".?AVbad_alloc@std@@"
	   $expectedException2 = ".?AVlength_error@std@@"
	   $expectedException3 = ".?AVlogic_error@std@@"
	   $expectedException4 = ".?AVout_of_range@std@@"

	condition:
		pe.is_pe and
		for any section in pe.sections : (
		   section.name == ".data" and
		   not $expectedException1 in (section.raw_data_offset..section.raw_data_offset + section.raw_data_size) and
		   not $expectedException2 in (section.raw_data_offset..section.raw_data_offset + section.raw_data_size) and
		   not $expectedException3 in (section.raw_data_offset..section.raw_data_offset + section.raw_data_size) and
		   not $expectedException4 in (section.raw_data_offset..section.raw_data_offset + section.raw_data_size)
		)
}


rule EntropyGreaterThan7
{
	meta: 
		author = "Suat Gungor"
		description = "Checks if the entropy of any PE resource is greater than 7.0"
		date = "2025-09-15"
	condition:
		for any resource in pe.resources : (
			math.in_range(
				math.entropy(resource.offset, resource.length), 7.0, 8.0
			)
		)
}

rule detect_pe_exe
   /*
   This should be run against files which do not have the extension of a PE file,
   */

   {
   meta:
      author = "Kenneth Moran"
      description = "This rule is to check if the header does not match the extension of the file"
      date = "9/15/2025"

   strings:
      $DOS_String = "This program cannot be run in DOS mode" nocase

   condition:
      $DOS_String

}


rule OtherThanUsual
/*
DLLs and EXEs don't usually have anything other than the following 6 sections:
.text, .rdata, .data, .pdata, .rsrc, and .reloc

Due to this, it would be suspicious, though not confirmed malicious, if a DLL/EXE
has something other than these six sections within it.
*/
{
meta:
   author = "Kenneth Moran"
   description = "Check for uncommon sections in DLL/EXE files"
   date = "9/17/2025"

condition:
   pe.is_pe and
   for any section in pe.sections : (
   section.name != ".text"
   and section.name != ".rdata"
   and section.name != ".data"
   and section.name != ".pdata"
   and section.name != ".rsrc"
   and section.name != ".reloc"
   )
}



rule EXESectionsCount
{
meta:
		author = "Ryan Rogowski"
	description = "check to see if abnormal amount of sections in EXE"
	date = "2025-09-17"

condition:
		pe.number_of_sections > 7 or pe.number_of_sections < 6

}


rule check_rsrc
/*
Each RSRC file contains metadata like fields within them. Due to this, it is important to check if this has been tampered with.
If any of the expected fields are missing, thats a clear sign that the file needs more investigation

*/
{

meta:
   author = "Kenneth Moran"
   description = "Checks RSRC files for expected Strings"
   date = "9/17/2025"

strings:
   $companyName = "CompanyName" nocase
   $fileDesc = "FileDescription" nocase
   $FileVer = "FileVersion" nocase
   $IntName = "InternalName" nocase

condition:
pe.is_pe
//and for any section in pe.sections : (section.name == ".rsrc")
and not 4 of them
}



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


rule missingPE_Sections
/*
DLLs and Exes should normally have at least 6 sections, these being as follows:
.text, .rdata, .data, .pdata, .rsrc, and .reloc

If any of these sections are missing from EXEs or DLLs, that is highly suspicious
*/
{
meta:
   author = "Kenneth Moran"
   description = "Checks if expected sections are missing from EXEs/DLLs"
   date = "9/17/2025"


condition:
	pe.is_pe and (
	not (for any section in pe.sections : ( section.name == ".text" )) or
	not (for any section in pe.sections : ( section.name == ".rdata" )) or
	not (for any section in pe.sections : ( section.name == ".data" )) or
	not (for any section in pe.sections : ( section.name == ".pdata" )) or
	not (for any section in pe.sections : ( section.name == ".rsrc" )) or
	not (for any section in pe.sections : ( section.name == ".reloc" ))
	)
}




