rule detect_GIF {
  meta:
    description = "Detects GIF files by checking the magic number and trailer."
  strings:
    $header = { 47 49 46 38 37 61 or 47 49 46 38 39 61 }
    $trailer = { 00 3B }
  condition:
    $header at 0 and $trailer at (filesize - 2)
}