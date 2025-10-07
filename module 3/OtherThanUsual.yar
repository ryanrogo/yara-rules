import "pe"
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