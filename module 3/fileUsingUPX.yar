rule fileUsingUPX
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