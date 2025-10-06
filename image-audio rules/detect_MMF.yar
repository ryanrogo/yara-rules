rule detect_MMF {
  meta:
    description = "Detects MMF files by checking the magic number and trailer."
  strings:
    $header = { 4D 4D 4D 44 00 00 }
  condition:
    $header at 0
}