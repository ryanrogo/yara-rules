rule detect_PSP {
  meta:
    description = "Detects PSP files by checking the magic number and trailer."
  strings:
    $header = { 7E 42 4B 00 }
  condition:
    $header at 0
}