rule detect_M4A {
  meta:
    description = "Detects M4A files by checking the magic number and trailer."
  strings:
    $header = { 66 74 79 70 4D 34 41 20 }
  condition:
    $header at 4
}