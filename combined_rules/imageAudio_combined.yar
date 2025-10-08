rule detect_MP3 {
  meta:
    description = "Detects MP3 files by checking the magic number and trailer."
  strings:
    $header = { 49 44 33 }
  condition:
    $header at 0
}

rule detect_AVIF {
  meta:
    description = "Detects AVIF files by checking the magic number and trailer."
  strings:
    $header = { 66 74 79 70 61 76 69 66 }
  condition:
    $header at 4
}

rule detect_FLAC {
  meta:
    description = "Detects FLAC files by checking the magic number and trailer."
  strings:
    $header = { 66 4C 61 43 00 00 00 22 }
  condition:
    $header at 0
}

rule detect_BMP {
  meta:
    description = "Detects BMP files by checking the magic number and trailer."
  strings:
    $header = { 42 4D }
  condition:
    $header at 0
}

rule detect_TIFF {
  meta:
    description = "Detects TIFF files by checking the magic number and trailer."
  strings:
    $header1 = { 49 20 49 }
	$header2 = { 49 49 2A 00 }
	$header3 = { 4D 4D 00 2A }
  condition:
    $header1 at 0 or $header2 at 0 or $header3 at 0
}

rule detect_PNG {
  meta:
    description = "Detects PNG files by checking the magic number and trailer."
  strings:
    $header = { 89 50 4E 47 0D 0A 1A 0A }
    $trailer = { 49 45 4E 44 AE 42 60 82 }
  condition:
    $header at 0 and $trailer at (filesize - 8)
}

rule detect_M4A {
  meta:
    description = "Detects M4A files by checking the magic number and trailer."
  strings:
    $header = { 66 74 79 70 4D 34 41 20 }
  condition:
    $header at 4
}

rule detect_MMF {
  meta:
    description = "Detects MMF files by checking the magic number and trailer."
  strings:
    $header = { 4D 4D 4D 44 00 00 }
  condition:
    $header at 0
}

rule detect_WEBP {
  meta:
    description = "Detects WEBP files by checking the magic number and trailer."
  strings:
    $header = { 52 49 46 46 ?? ?? ?? ?? 57 45 42 50 }
  condition:
    $header at 0
}

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

rule detect_AIFF {
  meta:
    description = "Detects AIFF files by checking the magic number and trailer."
  strings:
    $header = { 46 4F 52 4D 00 }
  condition:
    $header at 0
}

rule detect_PSD {
  meta:
    description = "Detects PSD files by checking the magic number and trailer."
  strings:
    $header = { 38 42 50 53 }
  condition:
    $header at 0
}

rule detect_OGG {
  meta:
    description = "Detects OGG files by checking the magic number and trailer."
  strings:
    $header = { 4F 67 67 53 00 02 00 00 00 00 00 00 00 00 }
  condition:
    $header at 0
}

rule detect_MSV {
  meta:
    description = "Detects MSV files by checking the magic number and trailer."
  strings:
    $header = { 4D 53 5F 56 4F 49 43 45 }
  condition:
    $header at 0
}

rule detect_PSP {
  meta:
    description = "Detects PSP files by checking the magic number and trailer."
  strings:
    $header = { 7E 42 4B 00 }
  condition:
    $header at 0
}

rule detect_EPS {
  meta:
    description = "Detects EPS files by checking the magic number and trailer."
  strings:
    $header = { C5 D0 D3 C6 }
  condition:
    $header at 0
}

rule detect_JPEG {
  meta:
    description = "Detects JPEG files by checking the magic number and trailer."
  strings:
    $header = { FF D8 }
    $trailer = { FF D9 }
  condition:
    $header at 0 and $trailer at (filesize - 2)
}

rule detect_WAV {
  meta:
    description = "Detects WAV files by checking the magic number and trailer."
  strings:
    $header = { 52 49 46 46 ?? ?? ?? ?? 57 41 56 45 66 6D 74 20 }
  condition:
    $header at 0
}

rule detect_RF64 {
  meta:
    description = "Detects RF64 files by checking the magic number and trailer."
  strings:
    $header = { 52 49 46 46 ?? ?? ?? ?? 43 44 44 41 66 6D 74 20 }
  condition:
    $header at 0
}

rule detect_WMA {
  meta:
    description = "Detects WMA files by checking the magic number and trailer."
  strings:
    $header = { 30 26 B2 75 8E 66 CF 11 A6 D9 00 AA 00 62 CE 6C }
  condition:
    $header at 0
}