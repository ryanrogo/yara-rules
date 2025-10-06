rule detect_PNG {
  meta:
    description = "Detects PNG files by checking the magic number and trailer."
  strings:
    $header = { 89 50 4E 47 0D 0A 1A 0A }
    $trailer = { 49 45 4E 44 AE 42 60 82 }
  condition:
    $header at 0 and $trailer at (filesize - 8)
}