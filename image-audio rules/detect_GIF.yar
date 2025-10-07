rule detect_GIF {
  meta:
    description = "Detects GIF files by checking the magic number and trailer."
  strings:
    $header1 = { 47 49 46 38 37 61 }
    $header2 = { 47 49 46 38 39 61 }
    $trailer = { 00 3B }
  condition:
    any of ($header1, $header2) at 0 and $trailer at (filesize - 2)
}
