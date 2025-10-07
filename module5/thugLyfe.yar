rule has_embedded_exe
{
    meta:
        description = "Checks if the DOS string occurs more than once, indicating an embedded PE file"
        author = "Ryan Rogowski"
    
    strings:
        $a = "This program cannot be run in DOS mode"
    
    condition:
        #a > 1
}

rule has_mean_string
{
    meta:
        description = "Check if a PE file contains a unique mean msg"
        author = "Ryan Rogowski"
    
    strings:
        $mean_msg = "I'm really mean. RAAAAH!"
    
    condition:
        $mean_msg
}

rule file_using_UPX
{
	meta:
		author = "Ryan Rogowski"
		description = "check if file is packed with UPX"
		date = "2025-09-15"
	strings:
		$upx0 = "UPX0"
		$upx1 = "UPX1"
		$upx2 = "UPX2"
	condition:
		$upx0 or $upx1 or $upx2

}

rule has_curl_cmd
{
    meta:
        description = "Check if a PE file contains a curl command to download the second stage payload (setup.exe)"
        author = "Ryan Rogowski"
    
    strings:
        $curl_cmd = {44 6F 77 6E 6C 6F 61 64 69 6E 67 2E 2E 2E 0A 00 63 75 72 6C 20 2D 6B 20 2D 6F 20 73 65 74 75 70 2E 65 78 65 20 68 74 74 70 73 3A 2F 2F 31 36 35 2E 37 33 2E 32 34 34 2E 31 31 2F 69 6E 73 74 61 6C 6C 65 72 73 2F 73 65 74 75 70 2E 65 78 65 00 44 6F 77 6E 6C 6F 61 64 69 6E 67 20 75 70 64 61 74 65 2E 2E 2E 0A 00 75 70 64 61 74 65 2D 74 6F 6F 6C 2E 65 78 65}
    
    condition:
        $curl_cmd
}

rule has_staller_curl_cmd
{
    meta:
        description = "Check if a PE file contains a curl command to download the second stage payload (.staller domain)"
        author = "Ryan Rogowski"
    
    strings:
        $curl_staller_cmd = {63 75 72 6C 20 2D 6B 02 6F 20 73 65 74 75 70 2E 65 78 65 20 68 FF F6 DB FF 74 74 70 73 3A 2F 2F 74 68 75 25 6C 79 66 65 2F 2E 73 74 61 6C 6C 65 72}
    
    condition:
        $curl_staller_cmd
}
