import "pe"
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