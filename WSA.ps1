###############################################################################
# This script will assess several security aspects of websites. It will use
# the SSLLabs, SecurityHeaders.io and Mozilla SSL Observatory API's to
# automatically retrieve the grading for a list of websites.
#
# Written by Eelco Huininga 2017-2018
###############################################################################

# Global user configurable variables
$InputFile					= "Hosts.txt"
$ResultsFile				= "WSA-results-" + (Get-Date -UFormat %Y%m%d) + ".csv"
$altNamesFile				= "WSA-debug.UnknownHostsFound-" + (Get-Date -UFormat %Y%m%d) + ".csv"
$HeadersDebugFile			= "WSA-debug.Headers-" + (Get-Date -UFormat %Y%m%d) + ".csv"
$Delimiter					= "`t"
$MaxRequests				= 30
$TimeOut					= 10
$UseProxy					= $true

# Global system variables
$SSLLabsAPIUrl				= "https://api.ssllabs.com/api/v2/analyze"
$SecurityHeadersAPIUrl		= "https://securityheaders.com/"
$MozillaObservatoryAPIUrl	= "https://http-observatory.security.mozilla.org/api/v1/analyze"
$RIPEWhoisAPIUrl			= "https://stat.ripe.net/data/whois/data.json"
$RIPEPrefixAPIUrl			= "https://stat.ripe.net/data/prefix-overview/data.json"
$RIPEDNSAPIUrl				= "https://stat.ripe.net/data/dns-chain/data.json"
$WhoIsUrl					= "http://dotnul.com/api/whois/"
$WhoisCache					= New-Object System.Data.DataTable
$WhoisCache.Columns.Add("Domain", [string]) | Out-Null
$WhoisCache.Columns.Add("Whois", [string]) | Out-Null
$RipeCache					= New-Object System.Data.DataTable
$RipeCache.Columns.Add("IPAddress", [string]) | Out-Null
$RipeCache.Columns.Add("ASNHolder", [string]) | Out-Null


###############################################################################
# Function definitions
###############################################################################
# Show help and usage
###############################################################################

function print_help() {
	Write-Host ("This script will assess several security aspects of websites. It will use the SSLLabs, SecurityHeaders.io and Mozilla SSL Observatory API's to automatically retrieve the grading for a list of websites.")
	Write-Host ("")
	Write-Host ("Written by Eelco Huininga 2017-2018")
	Write-Host ("")
	Write-Host ("Usage:")
	Write-Host ("	$0 [ options ]")
	Write-Host ("")
	Write-Host ("Options:")
	Write-Host ("	-h,		--help								 Print this help message")
	Write-Host ("	-d <url>,  --domain <url>						 Specify target domain")
	Write-Host ("	-i <file>, --input <file>						 Specify file with target domains (default: Hosts.txt)")
}

###############################################################################
# Get WHOIS record for domain name
###############################################################################

function whois($site) {
	# Get domain part from URL
	$site = $site.split('.')[-2..-1] -join '.'

	# Check if we've already got a WHOIS result for this site
	$Result = ($WhoisCache | Where-Object Domain -eq "$site").Whois
	if ($Result -eq $null) {
		Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $site + " - Performing WHOIS lookup..." + (" " * ([Console]::WindowWidth - [Console]::CursorLeft))+ "`r")
		try {
			$WHOISResult = Invoke-WebRequest `
				-ErrorAction Ignore `
				-Uri ($WhoIsUrl + $site)
		} catch [System.Net.Webexception] {
			return ('ERROR' + $_.Exception.Response.StatusCode.Value__ + $_.Exception.Response.StatusDescription)
		}

		# Convert the JSON response
		$WHOISResult = ConvertFrom-Json -InputObject $WHOISResult.Content

		$Result = "Error"
		if ($WHOISREsult.error -ne "false") {
			if ($WHOISREsult.whois -eq $null) {
				$Result = "N/A"
			} else {
				# Return first line in WHOIS result after line containing "Registrar:"
				$i = 0
				$WHOISResult.whois -Split("<br />") | ForEach-Object {
					if ($_.Trim() -ilike "Registrar:*") {
						$Result = ($_.Trim() -ireplace [regex]::Escape("Registrar:"), "").Trim()
						if ($Result -eq "") {
							$Result = (($WHOISResult.whois -Split("<br />") | Select-Object -Index ($i + 1)).Trim())
						}
						if ($Result -eq "") {
							$Result = "Error"
						} else {
							$WhoisCache.Rows.Add($site, $Result) | Out-Null
						}
					}
					$i++
				}
			}
		}
	} else {
		Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $site + " - WHOIS found in cache" + (" " * ([Console]::WindowWidth - [Console]::CursorLeft))+ "`r")
	}

	return $Result
}

###############################################################################
# Get the RIPE ASN prefix for an IP address
###############################################################################

function getPrefix($ipAddress) {
	# Check if we've already got a WHOIS result for this site
	$Result = ($RipeCache | Where-Object IPAddress -eq "$ipAddress").ASNHolder
	if ($Result -eq $null) {
		Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $CurrentHost + " - Retrieving RIPE prefix for " + $ipAddress + (" " * ([Console]::WindowWidth - [Console]::CursorLeft))+ "`r")
		try {
			$PrefixResult = Invoke-RestMethod `
				-Uri ($RIPEPrefixAPIUrl + '?resource=' + $ipAddress)
		} catch [System.Net.Webexception] {
			return ('ERROR' + $_.Exception.Response.StatusCode.Value__ + $_.Exception.Response.StatusDescription)
		}

		if ($PrefixResult.data.asns.holder) {
			$RipeCache.Rows.Add($ipAddress, $PrefixResult.data.asns.holder) | Out-Null
			return ($PrefixResult.data.asns.holder)
		} else {
			return ("N/A")
		}
	} else {
		Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $CurrentHost + " - RIPE prefix for "+ $ipAddress + " found in cache " + (" " * ([Console]::WindowWidth - [Console]::CursorLeft))+ "`r")
	}

	return $Result
}

###############################################################################
# Get the securityheaders.io rating
###############################################################################

function securityheaders($site) {
	Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $site + " - Getting securityheaders.io grading..." + (" " * ([Console]::WindowWidth - [Console]::CursorLeft))+ "`r")

	# Initiate the SecurityHeaders.io scan
	try {
		$Result = Invoke-WebRequest `
			-MaximumRedirection 0 `
			-ErrorAction Ignore `
			-Uri ($SecurityHeadersAPIUrl + '?q=' + $site + '&hide=on')
	} catch [System.Net.Webexception] {
		return ('ERROR' + $_.Exception.Response.StatusCode.Value__ + $_.Exception.Response.StatusDescription)
	}

	# Convert the JSON response
	$ResultColour = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Result.Headers.'X-Score'))
	$ResultColour = ConvertFrom-Json -InputObject $ResultColour
	# Colour can be default, grey, red, orange, yellow, green

	if ($Result.Headers.'X-Grade') {
		return ($Result.Headers.'X-Grade')
	} else {
		return ("N/A")
	}
}

###############################################################################
# Get the Mozilla HTTP Observatory rating
# https://github.com/mozilla/http-observatory/blob/master/httpobs/docs/api.md
###############################################################################

function mozillaObservatory($site) {
	Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $site + " - Getting Mozilla HTTP Observatory grading..." + (" " * ([Console]::WindowWidth - [Console]::CursorLeft))+ "`r")

	# Initiate the Mozilla HTTP Observatory scan by making a POST request
	try {
		$Result = Invoke-WebRequest `
			-MaximumRedirection 0 `
			-ErrorAction Ignore `
			-Method POST `
			-Uri ($MozillaObservatoryAPIUrl + '?host=' + $site + '&hidden=true')
	} catch [System.Net.Webexception] {
		return ('ERROR' + $_.Exception.Response.StatusCode.Value__ + $_.Exception.Response.StatusDescription)
	}

	# Convert the JSON response
	$Result = ConvertFrom-Json -InputObject $Result.Content

	# Ugly hack to prevent looping
	$j = 0

	Do {
		If ($Result.error) {
			return ($Result.error)
		}

		# Display a message if the scan hasn't finished yet
		if ($Result.state -ne "FINISHED") {
			Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $site + " - Getting Mozilla HTTP Observatory grading (pausing for 5 seconds)..." + (" " * ([Console]::WindowWidth - [Console]::CursorLeft))+ "`r")
			Start-Sleep -s 5

			# Get the result from Mozilla HTTP Observatory by making a GET request
			$Result = Invoke-WebRequest `
				-MaximumRedirection 0 `
				-ErrorAction Ignore `
				-Method GET `
				-Uri ($MozillaObservatoryAPIUrl + '?host=' + $site + '&hidden=true')

			# Convert the JSON response
			$Result = ConvertFrom-Json -InputObject $Result.Content
		}
		$j++
#	} While (($Result.state -ne "FINISHED") -and ($Result.state -ne "ABORTED") -and ($j -le $MaxRequests))
	} While ((($Result.state -eq "PENDING") -or ($Result.state -eq "PENDING")) -and ($j -le $MaxRequests))

	# Return the resulting grade if the scan finished successfully
	if ($Result.state -eq "FINISHED") {
		return ($Result.grade)
	}

	if ($j -eq $MaxRequests) {
		return ("No result within " + $MaxRequests + " requests")
	}

	# Return an error message if the scan didn't finish successfully
	return ($Result.state)
}

###############################################################################
# Get the DNS records for a site
###############################################################################

function getDNSRecords($site) {
	try {
		$DNSResult = Invoke-RestMethod `
			-Uri ($RIPEDNSAPIUrl + '?resource=' + $site)
	} catch [System.Net.Webexception] {
		return ('ERROR' + $_.Exception.Response.StatusCode.Value__ + $_.Exception.Response.StatusDescription)
	}

	return ($DNSResult)
}

###############################################################################
# Analyze the contents of the website
###############################################################################

function analyzeWebsite($site) {
	Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $site + " - Analyzing cookies and HTTP headers..." + (" " * ([Console]::WindowWidth - [Console]::CursorLeft))+ "`r")

	try {
		$Result = Invoke-WebRequest `
			-MaximumRedirection 0 `
			-ErrorAction Ignore `
			-Uri $site `
			-TimeoutSec $TimeOut `
			-SessionVariable mysession
	} catch [System.Net.Webexception] {
		if ($_.CategoryInfo.Category -eq "InvalidOperation") {
			if ($_.Exception.Response.StatusCode.Value__ -eq $null) {
				return ("site down")
			} else {
				return ("Can't scan website: " + $_.Exception.Response.StatusCode.Value__ + " " + $_.Exception.Response.StatusDescription)
			}
		} else {
			return ('Unknown error')
		}
	}

	# Write headers to debug header file
	$Hdr = ''
	ForEach ($Hdr in $Result.Headers.Keys) {
		'"' + $site + '"' + $Delimiter + `
		'"' + $Hdr + '"' + $Delimiter + `
		'"' + $Result.Headers.$Hdr + '"' `
			| Out-File -Append $HeadersDebugFile
	}

	$ReturnString = ''

	# Analyze the cookies
	foreach ($Cookie in $mysession.Cookies.GetCookies($site)) {
		if (($Cookie.Secure -ne "True") -Or ($Cookie.HttpOnly -ne "True")) {
			$ReturnString = $ReturnString + "Set the "
			# Cookie should have the Secure attribute set
			if ($Cookie.Secure -ne "True") {
				$ReturnString = $ReturnString + "Secure"
			}
			if (($Cookie.Secure -ne "True") -And ($Cookie.HttpOnly -ne "True")) {
				$ReturnString = $ReturnString + " and the "
			}
			# Cookie should have the HttpOnly attribute set
			if ($Cookie.HttpOnly -ne "True") {
				$ReturnString = $ReturnString + "HttpOnly"
			}
			$ReturnString = $ReturnString + " attribute(s) for cookie with name " + $Cookie.Name + "`n"
		}

		# Cookie should not be valid for all subdomains
		if ($Cookie.Domain.StartsWith(".")) {
			$ReturnString = $ReturnString + "Set a specific domain for cookie with name " + $Cookie.Name + "(" + $Cookie.Domain + ")`n"
		}
	}

	# Check if 'Location' header redirects to a secure https:// site
	if (($Result.Headers.'Location' -ne $null) -and (!($Result.Headers.'Location' -clike "https://*"))) {
		$ReturnString += "Insecure redirection found: '" + $Result.Headers.'Location' + "'`n"
	}

	# Check if 'Server' header is empty
	if ($Result.Headers.'Server' -ne $null) {
		$ReturnString += "Server header should be empty instead of '" + $Result.Headers.'Server' + "'`n"
	}

	# Check if 'X-Served-Via' header is empty
	if ($Result.Headers.'X-Served-Via' -ne $null) {
		$ReturnString += "X-Served-Via should be empty instead of '" + $Result.Headers.'X-Served-Via' + "'`n"
	}

	# Check if 'X-Served-By' header is empty
	if ($Result.Headers.'X-Served-By' -ne $null) {
		$ReturnString += "X-Served-By should be empty instead of '" + $Result.Headers.'X-Served-By' + "'`n"
	}

	# Check if 'X-Powered-By' header is empty
	if ($Result.Headers.'X-Powered-By' -ne $null) {
		$ReturnString += "X-Powered-By should be empty instead of '" + $Result.Headers.'X-Powered-By' + "'`n"
	}

	# Check if 'X-App-Server' header is empty
	if ($Result.Headers.'X-App-Server' -ne $null) {
		$ReturnString += "X-App-Server should be empty instead of '" + $Result.Headers.'X-App-Server' + "'`n"
	}

	# Check if 'X-AspNet-Version' header is empty
	if ($Result.Headers.'X-AspNet-Version' -ne $null) {
		$ReturnString += "X-AspNet-Version should be empty instead of '" + $Result.Headers.'X-AspNet-Version' + "'`n"
	}

	# Check if 'X-AspNetMvc-Version' header is empty
	if ($Result.Headers.'X-AspNetMvc-Version' -ne $null) {
		$ReturnString += "X-AspNetMvc-Version should be empty instead of '" + $Result.Headers.'X-AspNetMvc-Version' + "'`n"
	}

	# Check if 'X-MS-Server-Fqdn' header is empty
	if ($Result.Headers.'X-MS-Server-Fqdn' -ne $null) {
		$ReturnString += "X-MS-Server-Fqdn should be empty instead of '" + $Result.Headers.'X-MS-Server-Fqdn' + "'`n"
	}

	# Check if 'Content-Security-Policy' header is empty
	if ($Result.Headers.'Content-Security-Policy' -eq "") {
		$ReturnString += "Set 'Content-Security-Policy'`n"
	}

	# Check if 'X-Frame-Options' header is set correctly
	if ($Result.Headers.'X-Frame-Options' -ne "SAMEORIGIN") {
		$ReturnString += "Set 'X-Frame-Options' to 'SAMEORIGIN'`n"
	}

	# Check if 'X-XSS-Protection' header is set correctly
	if ($Result.Headers.'X-XSS-Protection' -ne "1; mode=block") {
		$ReturnString += "Set 'X-XSS-Protection' to '1; mode=block'`n"
	}

	# Check if 'X-Content-Type-Options' header is set correctly
	if ($Result.Headers.'X-Content-Type-Options' -ne "nosniff") {
		$ReturnString += "'Set X-Content-Type-Options' to 'nosniff'`n"
	}

	# Check if 'Referrer-Policy' header is set
	if ($Result.Headers.'Referrer-Policy' -eq $null) {
		$ReturnString += "Set 'Referrer-Policy'`n"
	}

	# Check if 'Public-Key-Pins' header is set
	if ($Result.Headers.'Public-Key-Pins' -eq $null) {
		$ReturnString += "Set 'Public-Key-Pins'`n"
	}

	# Check if 'Strict-Transport-Security' header is set correctly
	$HSTSmaxage = $false
	$HSTSinclsubdom = $false
	$HSTSpreload = $false
	if ($Result.Headers.'Strict-Transport-Security' -ne $null) {
		foreach ($item in $Result.Headers.'Strict-Transport-Security'.Split(";").Trim() ) {
			if ($item -clike "max-age*") {
				$HSTSmaxage = $true
				$item2 = $item.Split("=").Trim()
				if ($item2[1] -le 10368000) {
					$ReturnString = "Set 'Strict-Transport-Security' max-age to at least 10368000`n"
				}
			}
			if ($item -eq "includeSubdomains") {
				$HSTSinclsubdom = $true
			}
			if ($item -eq "preload") {
				$HSTSpreload = $true
			}
		}
		if (!$HSTSmaxage) {
			$ReturnString += "Set 'Strict-Transport-Security' max-age to at least 10368000`n"
		}
		if (!$HSTSinclsubdom) {
			$ReturnString += "Set 'Strict-Transport-Security' with 'includeSubdomains' value`n"
		}
		if (!$HSTSpreload) {
			$ReturnString += "Set 'Strict-Transport-Security' with 'preload' value`n"
		}
	}

	# Check if no insecure (https://) links are on this website
	ForEach ($link in $Result.Links) {
		if ($link.href -clike "http://*") {
			$ReturnString += "Insecure link found: " + $link.href + "`n"
		}
	}

	if ($ReturnString -ne "") {
		return ($ReturnString)
	} else {
		return ("None!")
	}
	return ("Error")
}

###############################################################################
# Perform a reverse DNS lookup
###############################################################################

function reverseDNSLookup($site) {
		try {
			$DnsRecords = Resolve-DnsName `
				$site `
				-Type A_AAAA `
				-DnsOnly
		} catch [System.Net.Webexception] {
			if ($_.CategoryInfo.Category -eq "ResourceUnavailable") {
				$DnsRecords = "No DNS record"
			} else {
				Write-Host("Resolve-DnsName returned an error while trying to resolve " + $site + " --> " + $_.CategoryInfo)
			}
		}
}

###############################################################################
# Initiate the scans so we can retrieve the result later on
###############################################################################

function initiateScans() {
	$i = 0
	foreach ($CurrentHost in $Hosts) {
		$wait = 1
		Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $CurrentHost + " - SSLLabs: Initiating scan..." + (" " * ([Console]::WindowWidth - [Console]::CursorLeft))+ "`r")
		try {
			$TmpResult = Invoke-RestMethod `
				-Uri ($SSLLabsAPIUrl + '?host=' + $CurrentHost + '&all=done&hideResults=true&ignoreMismatch=on')
		} catch [System.Net.Webexception] {
			if ($_.Exception.Response.StatusCode.Value__ -eq "429") {
				$wait = 15
			} else {
				if ($_.CategoryInfo.Category -eq "InvalidOperation") {
					Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $CurrentHost + " - SSLLabs: site is temporarily down, retrying..." + (" " * ([Console]::WindowWidth - [Console]::CursorLeft))+ "`r")
				} else {
					Write-Host ('`nSSLLabs returned an error: ' + $_.Exception.Response.StatusCode.Value__ + $_.Exception.Response.StatusDescription)
				}
			}
		}
		if ($TmpResult.newAssessmentCoolOff -ne $null) {
			Write-Host("TmpResult.newAssessmentCoolOff = " + $TmpResult.newAssessmentCoolOff)
		}
		Start-Sleep -s $wait
		$i++
	}
}



###############################################################################
#
# Main code
#
###############################################################################

# Read command line parameters
#[CmdletBinding()]
#param(
#	[alias("d")] [string] $domain,
#	[alias("i")] [string] $input,
#	[alias("h")] [switch] $help
#)

# Set proxy
if ($UseProxy) {
	(New-Object System.Net.WebClient).Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
}

# Add TLSv1.1 and TLSv1.2 to the available TLS protocols for Invoke-WebRequest() and Invoke-RestMethod()
try {
	if ([Net.ServicePointManager]::SecurityProtocol -clike '*Tls11*') {
		[Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls11
	}
} catch {
	Write-Host("Notice: TLSv1.1 not available")
}
try {
	if ([Net.ServicePointManager]::SecurityProtocol -clike '*Tls12*') {
		[Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls12
	}
} catch {
	Write-Host("Notice: TLSv1.2 not available")
}
#try {
#	if ([Net.ServicePointManager]::SecurityProtocol -clike '*Tls13*') {
#		[Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls13
#	}
#} catch {
#	Write-Host("Notice: TLSv1.3 not available")
#}

# Read hosts from input file
$Hosts = Get-Content ($InputFile)

# Prepare header of the output file
'"Protocol"' + $Delimiter + `
'"Hostname"' + $Delimiter + `
'"IP address"' + $Delimiter + `
'"Reverse DNS"' + $Delimiter + `
'"SSLLabs"' + $Delimiter + `
'"SecurityHeaders"' + $Delimiter + `
'"SSL Observatory"' + $Delimiter + `
'"Hosting provider"' + $Delimiter + `
'"WHOIS"' + $Delimiter + `
'"Certificate Issuer"' + $Delimiter + `
'"Valid until"' + $Delimiter + `
'"Recommendations"' `
	| Out-File $ResultsFile

# Prepare header of the HTTP headers debug file
'"URL"' + $Delimiter + `
'"HTTP header"' + $Delimiter + `
'"Value"' `
	| Out-File $HeadersDebugFile

# Prepare header of the HTTP headers debug file
'"URL"' + $Delimiter + `
'"Newly discovered host"' `
	| Out-File $altNamesFile

# Now get the results for all domains
$i = 0
$StartTime = (Get-Date)

# To save time, send requests to SSLLabs for scanning the hostnames, but don't retrieve the results yet
#initiateScans

foreach ($CurrentHost in $Hosts) {
	$SSLResult = ""
	$ScanReady = $false
	Write-Progress `
		-Activity "Getting SSLLabs results" `
		-status "Host: $CurrentHost" `
		-percentComplete  ($i++ / $Hosts.count*100)

	Do {
#		foreach ($HTTPPrefix in "http","https") {
#		$ScreenWidth = (get-host).UI.RawUI.WindowSize.Width

   		# Perform a reverse DNS lookup for the hostname
#		$rdns = reverseDNSLookup

		Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $CurrentHost + " - SSLLabs: Sending request..." + (" " * ([Console]::WindowWidth - [Console]::CursorLeft))+ "`r")
		try {
			$SSLResult = Invoke-RestMethod `
				-Uri ($SSLLabsAPIUrl + '?host=' + $CurrentHost + '&all=done&hideResults=true&ignoreMismatch=on')
		} catch [System.Net.Webexception] {
			if ($_.CategoryInfo.Category -eq "InvalidOperation") {
				Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $CurrentHost + " - SSLLabs: site is temporarily down, retrying..." + (" " * ([Console]::WindowWidth - [Console]::CursorLeft))+ "`r")
			} else {
				Write-Host ('`nSSLLabs returned an error: ' + $_.Exception.Response.StatusCode.Value__ + $_.Exception.Response.StatusDescription)
			}
		}

		switch ($SSLResult.status) {
			# Status = resolving DNS names
			"DNS" {
				Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $CurrentHost + " - SSLLabs: Resolving DNS names, please wait..." + (" " * ([Console]::WindowWidth - [Console]::CursorLeft))+ "`r")

				# Wait 5 seconds before next try
				Start-Sleep -s 5
				break
			}

			# Status = SSL Labs scan in progress, please wait...
			"IN_PROGRESS" {
				$EndpointsDone = 1

				# Find the endpoint with the longest wait time
				$SecondsToWait = 2

				foreach ($endpoint in $SSLResult.endpoints) {
					if ($endpoint.statusMessage -eq "Ready") {
						$EndpointsDone++
					}
					if ($endpoint.statusMessage -eq "In progress") {
						$CurrentEndpoint = $endpoint.ipAddress
					}
					if ($SecondsToWait -le $endpoint.eta) {
						$SecondsToWait = $endpoint.eta
					}
				}

				# Retry in 15 seconds if ETA is unknown
				if ($SecondsToWait -eq -1) {
					$SecondsToWait = 15
				}

				# Retry in 30 seconds if ETA is longer than 30 seconds
				if ($SecondsToWait -gt 30) {
					$SecondsToWait = 30
				}
				Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $CurrentHost + " - SSLLabs endpoint " + $EndpointsDone + "/" + $SSLResult.endpoints.Count + " (" + $CurrentEndpoint + "): pausing for " + $SecondsToWait + " seconds..." + (" " * ([Console]::WindowWidth - [Console]::CursorLeft))+ "`r")

				# Ease down requests on the SSLLabs API
				Start-Sleep -s $SecondsToWait

				break
			}

			# Status = SSL Labs scan could not finish correctly
			"ERROR" {
				$ScanReady = $true
				Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $CurrentHost + " - SSLLabs: Scan error (" + $SSLResult.statusMessage + ")" + (" " * ([Console]::WindowWidth - [Console]::CursorLeft))+ "`r")

				# Get WHOIS information for domain
				$whoisResult = whois($CurrentHost)

				# Get grading from securityheaders.io
				$SecurityHeadersGrade = securityheaders($CurrentHost)

				# Get grading from Mozilla HTTP Observatory
				$MozillaObservatoryResult = mozillaObservatory($CurrentHost)

				# Analyze the headers
				$WebsiteSuggestions = analyzeWebsite("https://" + $CurrentHost)

				# Check if no DNS record was found
				if ($SSLResult.statusMessage -eq 'Unable to resolve domain name') {
					# Write results to output file
					'"N/A"' + $Delimiter + `
					'"' + $CurrentHost + '"' + $Delimiter + `
					'"No DNS record"' + $Delimiter + `
					'"N/A"' + $Delimiter + `
					'"N/A"' + $Delimiter + `
					'"' + $SecurityHeadersGrade + '"' + $Delimiter + `
					'"' + $MozillaObservatoryResult + '"' + $Delimiter + `
					'"N/A"' + $Delimiter + `
					'"' + $whoisResult + '"' + $Delimiter + `
					'"N/A"' + $Delimiter + `
					'"N/A"' + $Delimiter + `
					'"' + $WebsiteSuggestions + '"' `
						| Out-File -Append $ResultsFile
				} else {
					# Write results to output file
					'"N/A"' + $Delimiter + `
					'"' + $CurrentHost + '"' + $Delimiter + `
					'"N/A"' + $Delimiter + `
					'"N/A"' + $Delimiter + `
					'"' + $SSLResult.statusMessage + '"' + $Delimiter + `
					'"' + $SecurityHeadersGrade + '"' + $Delimiter + `
					'"' + $MozillaObservatoryResult + '"' + $Delimiter + `
					'"N/A"' + $Delimiter + `
					'"' + $whoisResult + '"' + $Delimiter + `
					'"N/A"' + $Delimiter + `
					'"N/A"' + $Delimiter + `
					'"' + $WebsiteSuggestions + '"' `
						| Out-File -Append $ResultsFile
				}

				Write-Host ("[" + $i + "/" + $Hosts.count + "] " + $CurrentHost + " - Done" + (" " * ([Console]::WindowWidth - [Console]::CursorLeft)))
				break
			}

			# Status = SSL Labs scan finished
			"READY" {
				$ScanReady = $true
				Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $CurrentHost + " - SSLLabs: scan ready" + (" " * ([Console]::WindowWidth - [Console]::CursorLeft))+ "`r")

				# Get WHOIS information for domain
				$whoisResult = whois($CurrentHost)

				# Get grading from securityheaders.io
				$SecurityHeadersGrade = securityheaders("https://" + $CurrentHost)

				# Get grading from Mozilla HTTP Observatory
				$MozillaObservatoryResult = mozillaObservatory($CurrentHost)
				
				# Analyze the headers
				$WebsiteSuggestions = analyzeWebsite("https://" + $CurrentHost)
				
				# Iterate through all the endpoints
				foreach ($endpoint in $SSLResult.endpoints) {
					$Suggestions = ""
					# Get RIPE ASN prefix for the IP address (hosting provider info)
					$PrefixResult = getPrefix ($endpoint.ipAddress)

					# Check if the certificate is of an Extended Validation-type
					if ($endpoint.details.cert.validationType -eq "E") {
						$CertificateType = "EV"
					} else {
						$CertificateType = "-"
					}

					# Check if the SSLLabs test returned any warnings
					if ($endpoint.hasWarnings -eq "true") {
						$Suggestions = $Suggestions + "Fix all warnings from the SSL Labs test`n"
					}

					if ($endpoint.statusMessage -eq "Ready") {
						# Get the certificate's keysize, validation dates and issuer
						$CertificateKeySize = $endpoint.details.key.strength
						$CertificateDateBefore = ((Get-Date("1/1/1970")).addSeconds([int64]$endpoint.details.cert.notBefore / 1000).ToLocalTime()).ToString("yyyy-MM-dd HH:mm")
						$CertificateDateAfter = ((Get-Date("1/1/1970")).addSeconds([int64]$endpoint.details.cert.notAfter / 1000).ToLocalTime()).ToString("yyyy-MM-dd HH:mm")
						$CertificateIssuer = $endpoint.details.cert.issuerLabel

						if ($endpoint.grade -ne $endpoint.gradeTrustIgnored) {
							$SSLLabsGrade = $endpoint.grade + ' (' + $endpoint.gradeTrustIgnored + ')'
						} else {
							$SSLLabsGrade = $endpoint.grade
						}
						'"https"' + $Delimiter + `
						'"' + $CurrentHost + '"' + $Delimiter + `
						'"' + $endpoint.ipAddress + '"' + $Delimiter + `
						'"' + $endpoint.serverName + '"' + $Delimiter + `
						'"' + $SSLLabsGrade + '"' + $Delimiter + `
						'"' + $SecurityHeadersGrade + '"' + $Delimiter + `
						'"' + $MozillaObservatoryResult + '"' + $Delimiter + `
						'"' + $PrefixResult + '"' + $Delimiter + `
						'"' + $whoisResult + '"' + $Delimiter + `
						'"' + $CertificateIssuer + '"' + $Delimiter + `
						'"' + $CertificateDateAfter + '"' + $Delimiter + `
						'"' + $Suggestions + $WebsiteSuggestions + '"' `
							| Out-File -Append $ResultsFile
					} else {
						'"https"' + $Delimiter + `
						'"' + $CurrentHost + '"' + $Delimiter + `
						'"' + $endpoint.ipAddress + '"' + $Delimiter + `
						'"' + $endpoint.serverName + '"'  + $Delimiter + `
						'"' + $endpoint.statusMessage + '"' + $Delimiter + `
						'"' + $SecurityHeadersGrade + '"' + $Delimiter + `
						'"' + $MozillaObservatoryResult + '"' + $Delimiter + `
						'"' + $PrefixResult + '"' + $Delimiter + `
						'"' + $whoisResult + '"' + $Delimiter + `
						'"N/A"' + $Delimiter + `
						'"N/A"' + $Delimiter + `
						'"' + $Suggestions + $WebsiteSuggestions + '"' `
							| Out-File -Append $ResultsFile
					}

					# Check for any unknown hostnames in the certificate's altname
					foreach ($altName in $endpoints.details.cert.altNames) {
						if (!$Hosts.Contains($altName)) {
							'"' + $CurrentHost + '"' + $Delimiter + `
							'"' + $altName +'"' `
								| Out-File -Append $altNamesFile
						}
					}
				}
				Write-Host ("[" + $i + "/" + $Hosts.count + "] " + $CurrentHost + " - Done" + (" " * ([Console]::WindowWidth - [Console]::CursorLeft)))
				break
			}

			default {
				Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $CurrentHost + " - SSLLabs: Unknown status: " + $SSLResult.status + (" " * ([Console]::WindowWidth - [Console]::CursorLeft))+ "`r")
				break
			}
		}

		# Ease down requests on the SSLLabs API
		Start-Sleep -s 1
	} While ($ScanReady -eq $false)
}
Write-Progress "Done" "Done" -completed
Write-Host("Total time: " + ([timespan]::fromseconds(((Get-Date) - $StartTime).totalseconds).ToString("hh\:mm\:ss")))