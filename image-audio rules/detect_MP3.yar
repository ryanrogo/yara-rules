rule detect_MP3 {
  meta:
    description = "Detects MP3 files by checking the magic number and trailer."
  strings:
    $header = { 49 44 33 }
  condition:
    $header at 0
}