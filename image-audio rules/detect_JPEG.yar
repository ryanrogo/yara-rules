rule detect_JPEG {
  meta:
    description = "Detects JPEG files by checking the magic number and trailer."
  strings:
    $header = { FF D8 }
    $trailer = { FF D9 }
  condition:
    $header at 0 and $trailer at (filesize - 2)
}