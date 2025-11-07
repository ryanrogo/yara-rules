rule cronJobs
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for calls that write to crontab related files, as could be scheduled persistence"
		date = "11/07/2025"
		version = "1.0"
	strings:
		$location = "/var/spool/cron/crontabs/"
		$location2 = "/var/spool"
		$name = "crontab"
		$action = "fopen("
		
	condition:
		$any of ($location, $location2, $name) or $action and any of ($location, $location2, $name)
}