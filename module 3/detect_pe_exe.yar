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