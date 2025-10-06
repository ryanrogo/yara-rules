rule detect_WMA {
  meta:
    description = "Detects WMA files by checking the magic number and trailer."
  strings:
    $header = { 30 26 B2 75 8E 66 CF 11 A6 D9 00 AA 00 62 CE 6C }
  condition:
    $header at 0
}