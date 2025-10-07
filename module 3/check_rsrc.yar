import "pe"
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