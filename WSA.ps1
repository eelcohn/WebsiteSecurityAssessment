# -----------------------------------------------------------------------------
# This script will assess several security aspects of websites. It will use
# the SSLLabs, SecurityHeaders.io and Mozilla SSL Observatory API's to
# automatically retrieve the grading for a list of websites.
#
# Written by Eelco Huininga 2017-2020
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Global user configurable variables
# -----------------------------------------------------------------------------
$Protocols				= @("http", "https")
$InputFile				= "Hosts.txt"
$ResultsFile				= "WSA-results-" + (Get-Date -UFormat %Y%m%d) + ".csv"
$altNamesFile				= "WSA-debug.UnknownHostsFound-" + (Get-Date -UFormat %Y%m%d) + ".csv"
$HeadersDebugFile			= "WSA-debug.Headers-" + (Get-Date -UFormat %Y%m%d) + ".csv"
$Delimiter				= "`t"
$MaxRequests				= 30
$TimeOut				= 5
$DnsServer				= ""
$PreferredNamedGroup			= "x25519"
$UseProxy				= $True
$UseCommonPrefixes			= $True

# -----------------------------------------------------------------------------
# Global system variables
# -----------------------------------------------------------------------------
$WSAVersion				= "v20200316"
$CommonPrefixes				= @("www")
$SSLLabsAPIUrl				= "https://api.ssllabs.com/api/v3/analyze"
$SecurityHeadersAPIUrl			= "https://securityheaders.com/"
$MozillaObservatoryAPIUrl		= "https://http-observatory.security.mozilla.org/api/v1/analyze"
$RIPEWhoisAPIUrl			= "https://stat.ripe.net/data/whois/data.json"
$RIPEPrefixAPIUrl			= "https://stat.ripe.net/data/prefix-overview/data.json"
$RIPEDNSAPIUrl				= "https://stat.ripe.net/data/dns-chain/data.json"
$WhoIsUrl				= "https://dotnul.com/api/whois/"
$WhoisCache = New-Object System.Data.DataTable
$WhoisCache.Columns.Add("Domain", [string]) | Out-Null
$WhoisCache.Columns.Add("Whois", [string]) | Out-Null
$RipeCache = New-Object System.Data.DataTable
$RipeCache.Columns.Add("IPAddress", [string]) | Out-Null
$RipeCache.Columns.Add("ASNHolder", [string]) | Out-Null
$ObservatoryCache = New-Object System.Data.DataTable
$ObservatoryCache.Columns.Add("Domain", [string]) | Out-Null
$ObservatoryCache.Columns.Add("Rating", [string]) | Out-Null
$ReverseDnsCache = New-Object System.Data.DataTable
$ReverseDnsCache.Columns.Add("IPAddress", [string]) | Out-Null
$ReverseDnsCache.Columns.Add("Hostname", [string]) | Out-Null
$GoodHTTPHeaders = @(
	"Accept-Ranges",
	"Access-Control-Allow-Origin",
	"Access-Control-Allow-Methods",
	"Access-Control-Allow-Headers",
	"Cache-Control",
	"Connection",
	"Content-Language",
	"Content-Length",
	"Content-Security-Policy",
	"Content-Security-Policy-Report-Only",
	"Content-Type",
	"Date",
	"Expect-CT",
	"Expect-Staple",
	"Expires",
	"ETag",
	"Feature-Policy",
	"Keep-Alive",
	"Last-Modified",
	"Link",
	"Location",
	"P3p",
	"Public-Key-Pins",
	"Public-Key-Pins-Report-Only",
	"Pragma",
	"Referrer-Policy",
	"Set-Cookie",
	"Strict-Transport-Security"
	"Transfer-Encoding",
	"Vary",
	"X-Content-Security-Policy",
	"X-Content-Type-Options",
	"X-Download-Options",
	"X-Frame-Options",
	"X-Permitted-Cross-Domain-Policies",
	"X-Robots-Tag",
	"X-XSS-Protection")
$BadHTTPHeaders = @(
	"MicrosoftSharePointTeamServices",
	"Server",
	"Via",
	"X-AH-Environment",
	"X-App-Server",
	"X-AspNet-Version",
	"X-AspNetMvc-Version",
	"X-Backend-Server",
	"X-Debug-Token",
	"X-Debug-Token-Link",
	"X-Drupal-Cache",
	"X-Drupal-Cache-Contexts",
	"X-Drupal-Cache-Tags",
	"X-Drupal-Dynamic-Cache",
	"X-Engine",
	"X-FEServer",
	"X-Generator",
	"X-KoobooCMS-Version",
	"X-MS-Server-Fqdn",
	"X-Mod-Pagespeed",
	"X-Oracle-DMS-ECID",
	"X-Oracle-DMS-RID",
	"X-OWA-Version",
	"X-Powered-By",
	"X-Powered-By-Plesk",
	"X-Redirect-By",
	"X-Served-By",
	"X-Served-Via",
	"X-Server-Powered-By",
	"X-SharePointHealthScore",
	"X-Varnish",
	"X-Varnish-Cache",
	"X-Varnish-Cache-Hits",
	"X-Varnish-Cacheable",
	"X-Varnish-Host")



# -----------------------------------------------------------------------------
#
# Function definitions
#
# -----------------------------------------------------------------------------
# Show help and usage
# -----------------------------------------------------------------------------

function print_help() {
	Write-Host ("This script will assess several security aspects of websites. It will use the SSLLabs, SecurityHeaders.io and Mozilla SSL Observatory API's to automatically retrieve the grading for a list of websites.")
	Write-Host ("")
	Write-Host ("Written by Eelco Huininga 2017-2019")
	Write-Host ("")
	Write-Host ("Usage:")
	Write-Host ("	$0 [ options ]")
	Write-Host ("")
	Write-Host ("Options:")
	Write-Host ("	-h,        --help							 Print this help message")
	Write-Host ("	-d <url>,  --domain <url>						 Specify target domain")
	Write-Host ("	-i <file>, --input <file>						 Specify file with target domains (default: Hosts.txt)")
}

# -----------------------------------------------------------------------------
# Show detailed error info
# -----------------------------------------------------------------------------

function showError($Title, $ExceptionStack) {
	Write-Host($Title)
	Write-Host('  ErrorCode: 0x{0:X8}' -f $ExceptionStack.Exception.ErrorCode)
	Write-Host('  CategoryInfo: ' + $ExceptionStack.CategoryInfo)
	Write-Host('  FullyQualifiedErrorId: ' + $ExceptionStack.FullyQualifiedErrorId)
	Write-Host('  StatusCode: ' + $ExceptionStack.Exception.Response.StatusCode.Value__)
	Write-Host('  StatusDescription: ' + $ExceptionStack.Exception.Response.StatusDescription)
}

# -----------------------------------------------------------------------------
# Expand IPv6 address
# -----------------------------------------------------------------------------
function expandIPv6($Address) {
	# Expand :: to zero's
	if ($Address.Contains("::")) {
		$blocks = $Address -split ":"
		$count = $blocks.Count
		$replace = 8 - $count + 1
		for ($i=0; $i -le $count-1; $i++) {
			if ($blocks[$i] -eq "") {
				$blocks[$i] = ("0:" * $replace).TrimEnd(":")
			}
		}
#		$Address = $blocks -join ":"
	}

	# Add zero's to blocks < 0x1000
#	$blocks = $Address -split ":"
#	for ($i=0; $i -le $blocks.Count-1; $i++) {
#		if ($blocks[$i].length -ne 4) {
#			$blocks[$i] = $blocks[$i].Padleft(4,"0")
#		}
#	}
	Return ($blocks -join ":")
}

# -----------------------------------------------------------------------------
# Get WHOIS record for domain name
# -----------------------------------------------------------------------------

function whois($site) {
	# Get domain part from URL
	$site = $site.split('.')[-2..-1] -join '.'

	# Check if we've already got a WHOIS result for this site
	$Result = ($WhoisCache | Where-Object Domain -eq "$site").Whois
	if ($Result -eq $null) {
		Write-Host ("[" + $i + "/" + $TotalHosts + "] " + $HTTPPrefix + "://" + $CurrentHost + " - Performing WHOIS lookup for "+ $site + "...")
		try {
			$WHOISResult = Invoke-WebRequest `
				-ErrorAction Ignore `
				-Uri ($WhoIsUrl + $site)
		} catch [System.Net.Webexception] {
			showError('Whois(): Invoke-WebRequest returned an error while processing ' + $site, $_)
			return ('ERROR' + $_.Exception.Response.StatusCode.Value__ + $_.Exception.Response.StatusDescription)
		}

		# Convert the JSON response
		$WHOISResult = ConvertFrom-Json -InputObject $WHOISResult.Content

		$Result = "Unable to get WHOIS data"
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
							$Result = "Unable to get WHOIS data"
						} else {
							$WhoisCache.Rows.Add($site, $Result) | Out-Null
						}
					}
					$i++
				}
			}
		}
	} else {
		Write-Host ("[" + $i + "/" + $TotalHosts + "] " + $HTTPPrefix + "://" + $CurrentHost + " - Performing WHOIS lookup for "+ $site + ": cached")
	}

	return $Result
}

# -----------------------------------------------------------------------------
# Get the RIPE ASN prefix for an IP address
# -----------------------------------------------------------------------------

function getPrefix($ipAddress) {
	# Check if a RIPE prefix for this IP address is available in the cache
	$Result = ($RipeCache | Where-Object IPAddress -eq "$ipAddress").ASNHolder

	if ($Result -eq $null) {
		Write-Host ("[" + $i + "/" + $TotalHosts + "] " + $HTTPPrefix + "://" + $CurrentHost + " - Retrieving RIPE prefix for " + $ipAddress)
		try {
			$PrefixResult = Invoke-RestMethod `
				-Uri ($RIPEPrefixAPIUrl + '?resource=' + $ipAddress)
		} catch [System.Net.Webexception] {
			showError('getPrefix(): Invoke-WebRequest returned an error while processing ' + $site, $_)
			return ('ERROR' + $_.Exception.Response.StatusCode.Value__ + $_.Exception.Response.StatusDescription)
		}

		[Net.IPAddress]$network, $netmask = ($PrefixResult.data.resource -split "/")
		[Net.IPAddress]$netmask = [uint32]"0xffffffff" -shl (31 - $netmask)

		if ($PrefixResult.data.asns.holder) {
			$RipeCache.Rows.Add($ipAddress, $PrefixResult.data.asns.holder) | Out-Null
			return ($PrefixResult.data.asns.holder)
		} else {
			return ("N/A")
		}
	} else {
		Write-Host ("[" + $i + "/" + $TotalHosts + "] " + $HTTPPrefix + "://" + $CurrentHost + " - Retrieving RIPE prefix for "+ $ipAddress + ": cached ")
	}

	return $Result
}

# -----------------------------------------------------------------------------
# Get the securityheaders.io rating
# -----------------------------------------------------------------------------

function securityheaders($site) {
	Write-Host ("[" + $i + "/" + $TotalHosts + "] " + $site + " - Getting securityheaders.io grading...")

	# Initiate the SecurityHeaders.io scan
	try {
		$Result = Invoke-WebRequest `
			-MaximumRedirection 0 `
			-ErrorAction Ignore `
			-Uri ($SecurityHeadersAPIUrl + '?q=' + $site + '&hide=on&followRedirects=off')
	} catch [System.Net.Webexception] {
		showError('securityheaders(): Invoke-WebRequest returned an error while processing ' + $site, $_)
		return ('ERROR' + $_.Exception.Response.StatusCode.Value__ + $_.Exception.Response.StatusDescription)
	}

	# Convert the JSON response
	$ResultColour = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Result.Headers.'X-Score'))

	# Colour can be default, grey, red, orange, yellow, green
	$ResultColour = ConvertFrom-Json -InputObject $ResultColour

	if ($Result.Headers.'X-Grade') {
		return ($Result.Headers.'X-Grade')
	} else {
		return ("N/A")
	}
}

# -----------------------------------------------------------------------------
# Get the Mozilla HTTP Observatory rating
# https://github.com/mozilla/http-observatory/blob/master/httpobs/docs/api.md
# -----------------------------------------------------------------------------

function mozillaObservatory($site) {
	# Check if the observatory's rating is available in the cache
	$Result = ($ObservatoryCache | Where-Object Domain -eq "$Domain").Rating

	if ($Result -eq $null) {
		Write-Host ("[" + $i + "/" + $TotalHosts + "] " + $HTTPPrefix + "://" + $site + " - Getting Mozilla HTTP Observatory grading...")

		# Initiate the Mozilla HTTP Observatory scan by making a POST request
		try {
			$Result = Invoke-WebRequest `
				-MaximumRedirection 0 `
				-ErrorAction Ignore `
				-Method POST `
				-Uri ($MozillaObservatoryAPIUrl + '?host=' + $site + '&hidden=true')
		} catch [System.Net.Webexception] {
			showError('mozillaObservatory(): Invoke-WebRequest returned an error while processing ' + $site, $_)
			return ('ERROR' + $_.Exception.Response.StatusCode.Value__ + $_.Exception.Response.StatusDescription)
		}

		# Convert the JSON response
		$Result = ConvertFrom-Json -InputObject $Result.Content

		# Ugly hack to prevent looping
		$j = 1
		$ObservatoryWait = 8

		Do {
			If ($Result.error) {
				If ($Result.error -eq "site down") {
					$ObservatoryCache.Rows.Add($site, "N/A") | Out-Null
					return ("N/A")
				} else {
					return ($Result.error)
				}
			}

			# Display a message if the scan hasn't finished yet
			if ($Result.state -ne "FINISHED") {
				Write-Host ("[" + $i + "/" + $TotalHosts + "] " + $HTTPPrefix + "://" + $site + " - Getting Mozilla HTTP Observatory grading: attempt " + $j + " of " + $MaxRequests + " (pausing for " + $ObservatoryWait + " seconds)...")
				Start-Sleep -s $ObservatoryWait

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
		} While ((($Result.state -eq "PENDING") -or ($Result.state -eq "RUNNING")) -and ($j -le $MaxRequests))

		# Return the resulting grade if the scan finished successfully
		if ($Result.state -eq "FINISHED") {
			$ObservatoryCache.Rows.Add($site, $Result.grade) | Out-Null
			return ($Result.grade)
		}

		if ($j -eq $MaxRequests) {
			return ("No result within " + $MaxRequests + " requests")
		}

		# Return an error message if the scan didn't finish successfully
		return ($Result.state)
	} else {
		Write-Host ("[" + $i + "/" + $TotalHosts + "] " + $HTTPPrefix + "://" + $CurrentHost + " - Getting Mozilla HTTP Observatory grading: cached ")
	}

	return $Result
}

# -----------------------------------------------------------------------------
# Get the DNS records for a site
# -----------------------------------------------------------------------------

function DNSLookup($site) {
	Write-Host -NoNewLine ("[" + $i + "/" + $TotalHosts + "] " + $HTTPPrefix + "://" + $site + " - Performing DNS lookup...")

	try {
		if ($DnsServer -ne "") {
			$DnsRecords = Resolve-DnsName `
				-Name $site `
				-Type A_AAAA `
				-Server $DnsServer `
				-DnsOnly `
				-ErrorAction Stop
		} else {
			$DnsRecords = Resolve-DnsName `
				-Name $site `
				-Type A_AAAA `
				-DnsOnly `
				-ErrorAction Stop
		}
	} catch [Exception] {
		switch ($_.CategoryInfo.Category) {
			# No DNS record was found
			"ResourceUnavailable" {
				Write-Host (" unavailable")
				return ("N/A")
			}

			# The operation timed out
			"OperationTimeout" {
				Write-Host (" timed out")
				return ("Timeout")
			}

			# All other errors
			default {
				showError('DNSLookup(): Resolve-DnsName returned an error while processing ' + $site, $_)
				return ("Error")
			}
		}
	}

	$Result = ($DnsRecords.IP6Address + $DnsRecords.IP4Address) | ?{$_ -ne $Null}

	if ($Result -ne $null) {
		Write-Host (" found " + $Result.Count + " entries")
		return ($Result)
	} else {
		Write-Host (" nothing found")
		return "N/A"
	}
}

# -----------------------------------------------------------------------------
# Get the reverse DNS record for an IP addresslookup
# -----------------------------------------------------------------------------

function reverseDNSLookup($IPAddress) {
	# Check if reverse DNS for this IP address is available in the cache
	$Result = ($ReverseDNSCache | Where-Object IPAddress -eq "$IPAddress").Hostname

	if ($Result -eq $null) {
		Write-Host ("[" + $i + "/" + $TotalHosts + "] " + $HTTPPrefix + "://" + $CurrentHost + " - Performing reverse DNS lookup for " + $IPAddress + "...")

		try {
			$ReverseDnsRecords = Resolve-DnsName `
				-Name $IPAddress `
				-Type A_AAAA `
				-DnsOnly `
				-ErrorAction Stop
			$Result = ($ReverseDnsRecords | Where-Object Type -eq "PTR").NameHost
		} catch [Exception] {
			switch ($_.CategoryInfo.Category) {
				# No reverse DNS record was found
				"ResourceUnavailable" {
					$Result = "N/A"
				}

				# The operation timed out
				"OperationTimeout" {
					$Result = "Timeout"
				}

				# All other errors
				default {
					showError('reverseDNSLookup(): Resolve-DnsName returned an error while processing ' + $site, $_)
					$Result = "Unable to perform reverse DNS"
				}
			}
		}

		$ReverseDNSCache.Rows.Add($IPAddress, $Result) | Out-Null
	} else {
		Write-Host ("[" + $i + "/" + $TotalHosts + "] " + $HTTPPrefix + "://" + $CurrentHost + " - Performing reverse DNS lookup for " + $IPAddress + ": cached")
	}

	return $Result
}

# -----------------------------------------------------------------------------
# Load the contents of the website
# -----------------------------------------------------------------------------

function loadWebsite($site) {
	Write-Host ("[" + $i + "/" + $TotalHosts + "] " + $HTTPPrefix + "://" + $site + " - Loading website content...")

	try {
		$Result = Invoke-WebRequest `
			-MaximumRedirection 0 `
			-ErrorAction Ignore `
			-Headers @{"X-Client"="WebsiteSecurityAssessment " + $WSAversion} `
			-SkipCertificateCheck `
			-Uri $site `
			-TimeoutSec $TimeOut
# SkipCertificateCheck is only available on PowerShell 6.0.0 and above
#			-SkipCertificateCheck `
	} catch [System.Net.Webexception] {
		if ($_.Exception.HResult -eq 0x80131509) {
			return ("N/A")
		} else {
			return ("Can't scan website: " + $_.Exception.Response.StatusCode.Value__ + " " + $_.Exception.Response.StatusDescription)
		}
	}

	result $Result
}

# -----------------------------------------------------------------------------
# Analyze the contents of the website
# -----------------------------------------------------------------------------

function analyzeWebsite($site) {
	Write-Host ("[" + $i + "/" + $TotalHosts + "] " + $site + " - Analyzing cookies and HTTP headers...")

	try {
		$Result = Invoke-WebRequest `
			-MaximumRedirection 0 `
			-ErrorAction Ignore `
			-Headers @{"X-Client"="WebsiteSecurityAssessment " + $WSAversion} `
			-SkipCertificateCheck `
			-Uri $site `
			-TimeoutSec $TimeOut
# SkipCertificateCheck is only available on PowerShell 6.0.0 and above
#			-SkipCertificateCheck `
	} catch [System.Net.Webexception] {
		# Continue on 404 Not Found errors
		if ($_.Exception.HResult -ne 0x80131509) {
			return ("Can't scan website: " + $_.Exception.Response.StatusCode.Value__ + " " + $_.Exception.Response.StatusDescription)
		}
	}

	# Write headers to debug header file
	$Hdr = ''
	ForEach ($Hdr in $Result.Headers.Keys) {
	$HeaderRating = "Unknown"
		if ($BadHTTPHeaders -Contains $Hdr) {
			$HeaderRating = "Bad"
		} elseif ($GoodHTTPHeaders -Contains $Hdr) {
			$HeaderRating = "Good"
		}
		'"' + $site + '"' + $Delimiter + `
		'"' + $Hdr + '"' + $Delimiter + `
		'"' + $Result.Headers.$Hdr + '"' + $Delimiter + `
		'"' + $HeaderRating + '"' `
			| Out-File -Append $HeadersDebugFile
	}

	$ReturnString = ''

	# Analyze the cookies
	foreach ($Cookie in $Result.BaseResponse.Cookies) {
		if (($Cookie.Secure -ne "True") -Or ($Cookie.HttpOnly -ne "True")) {
			$ReturnString += "Set the "
			# Cookie should have the Secure attribute set
			if ($Cookie.Secure -ne "True") {
				$ReturnString += "Secure"
			}
			if (($Cookie.Secure -ne "True") -And ($Cookie.HttpOnly -ne "True")) {
				$ReturnString += " and the "
			}
			# Cookie should have the HttpOnly attribute set
			if ($Cookie.HttpOnly -ne "True") {
				$ReturnString += "HttpOnly"
			}
			$ReturnString += " attribute(s) for cookie with name " + $Cookie.Name + "`n"
		}

		# Cookie should not be valid for all subdomains
		if ($Cookie.Domain.StartsWith(".")) {
			$ReturnString += "Set a specific domain for cookie with name " + $Cookie.Name + "(" + $Cookie.Domain + ")`n"
		}
	}

	# Check if any of the HTTP headers disclose unnecessary information
	foreach ($BadHeader in $BadHTTPHeaders) {
		if ($Result.Headers.$BadHeader -ne $null) {
			$ReturnString += "Information disclosure in HTTP header " + $BadHeader + ": '" + $Result.Headers.$BadHeader + "'`n"
		}
	}

	# Check if 'Location' header redirects to a secure https:// site
	if (($Result.Headers.'Location' -ne $null) -and (!($Result.Headers.'Location' -clike "https://*"))) {
		$ReturnString += "Insecure redirection found: '" + $Result.Headers.'Location' + "'`n"
	}

	# Check if 'Content-Security-Policy' header is empty
	if ($Result.Headers.'Content-Security-Policy' -eq $null) {
		$ReturnString += "Set HTTP header 'Content-Security-Policy'`n"
	}

	# Check if 'X-Frame-Options' header is set correctly
	if ($Result.Headers.'X-Frame-Options' -ne "SAMEORIGIN") {
		$ReturnString += "Set HTTP header 'X-Frame-Options' to 'SAMEORIGIN'`n"
		if (($Result.Headers.'X-Frame-Options' -ne $Null) -and ($Result.Headers.'X-Frame-Options' -ne "DENY") -and ($Result.Headers.'X-Frame-Options' -ne "ALLOW-FROM")) {
			$ReturnString += "Note: 'X-Frame-Options' has an invalid value of '" + $Result.Headers.'X-Frame-Options' + "'`n"
		}
	}

	# Check if 'X-XSS-Protection' header is set correctly
	if ($Result.Headers.'X-XSS-Protection' -ne "1; mode=block") {
		$ReturnString += "Set HTTP header 'X-XSS-Protection' to '1; mode=block'`n"
	}

	# Check if 'X-Content-Type-Options' header is set correctly
	if ($Result.Headers.'X-Content-Type-Options' -ne "nosniff") {
		$ReturnString += "Set HTTP header 'X-Content-Type-Options' to 'nosniff'`n"
	}

	# Check if 'X-Permitted-Cross-Domain-Policies' header is set correctly
	if ($Result.Headers.'X-Permitted-Cross-Domain-Policies' -ne "none") {
		$ReturnString += "Set HTTP header 'X-Permitted-Cross-Domain-Policies' to 'none'`n"
	}

	# Check if 'Referrer-Policy' header is set
	if ($Result.Headers.'Referrer-Policy' -eq $null) {
		$ReturnString += "Set HTTP header 'Referrer-Policy'`n"
	}

	# Check if 'Access-Control-Allow-Origin' is strict enough
	if ($Result.Headers.'Access-Control-Allow-Origin' -eq "*") {
		$ReturnString += "Set HTTP header 'Access-Control-Allow-Origin' to a more strict value`n"
	}

	# Check if 'Public-Key-Pins' header is set
	if ($HTTPPrefix -eq "https") {
		if ($Result.Headers.'Public-Key-Pins' -eq $null) {
			$ReturnString += "Set HTTP header 'Public-Key-Pins'`n"
		}
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
				# Qualsys advises a minimun value for max-age of 120 days
				if ($item2[1] -le 10368000) {
					$ReturnString = "Set HTTP header 'Strict-Transport-Security' max-age to at least 10368000`n"
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
			$ReturnString += "Set HTTP header 'Strict-Transport-Security' max-age to at least 10368000`n"
		}
		if (!$HSTSinclsubdom) {
			$ReturnString += "Set HTTP header 'Strict-Transport-Security' with 'includeSubdomains' value`n"
		}
		if (!$HSTSpreload) {
			$ReturnString += "Set HTTP header 'Strict-Transport-Security' with 'preload' value`n"
		}
	}

	# Check if no insecure (https://) links are on this website
	ForEach ($link in $Result.Links) {
		if ($link.href -clike "http://*") {
			$ReturnString += "Insecure link found: " + $link.href + "`n"
		}
	}

	# Find the value of <meta generator=""> tag in the website (if any). This will show the software the website is running on.
	if ($Result.ParsedHtml -ne $null) {
		$MetaGenerator = ($Result.ParsedHtml.IHTMLDocument3_getElementsByTagName('meta') | Where {$_.name -eq 'generator'}).content
		if ($MetaGenerator -ne $null) {
			$ReturnString += "Information disclosure found in metatag '<meta generator>: " + $MetaGenerator + "`n"
		}
	}

	return ($ReturnString)
}

# -----------------------------------------------------------------------------
# Analyze available HTTP methods
# -----------------------------------------------------------------------------

function analyzeHTTPMethods($site) {
	Write-Host ("[" + $i + "/" + $TotalHosts + "] " + $site + " - Analyzing HTTP methods...")

	$BadHTTPMethods = @(
#		"DELETE",
#		"MERGE",
		"OPTIONS",
#		"PATCH",
#		"PUT",
		"TRACE")
#		"CONNECT",
#		"DEBUG",
#		"TRACK",

	$ReturnString = ''

	# Check if any insecure HTTP methods are available
	foreach ($BadMethod in $BadHTTPMethods) {
		try {
			$Result = Invoke-WebRequest `
				-MaximumRedirection 0 `
				-ErrorAction Ignore `
				-Headers @{"X-Client"="WebsiteSecurityAssessment " + $WSAversion} `
				-SkipCertificateCheck `
				-Uri $site `
				-Method $BadMethod `
				-TimeoutSec $TimeOut
# SkipCertificateCheck is only available on PowerShell 6.0.0 and above
#				-SkipCertificateCheck `
# CustomMethod is available from PowerShell 6.0.0 and above
#				-CustomMethod $BadMethod `
		} catch [System.Net.Webexception] {
			if ($_.CategoryInfo.Category -ne "InvalidOperation") {
				# The webserver should return HTTP error code 405: Method not allowed or 501: Not Implemented
				if (($_.Exception.Response.StatusCode.Value__ -ne "405") -and ($_.Exception.Response.StatusCode.Value__ -ne "501")) {
					$ReturnString += "Dangerous HTTP method " + $BadMethod + " found`n"
				}
			}
		}
	}

	return ($ReturnString)
}

# -----------------------------------------------------------------------------
# Initiate the scans so we can retrieve the result later on
# -----------------------------------------------------------------------------

function initiateScans() {
	$i = 0
	foreach ($CurrentHost in $Hosts) {
		$wait = 1
		Write-Host ("[" + $i + "/" + $TotalHosts + "] https://" + $CurrentHost + " - SSLLabs: Initiating scan...")
		try {
			$TmpResult = Invoke-RestMethod `
				-Uri ($SSLLabsAPIUrl + '?host=' + $CurrentHost + '&all=done&hideResults=true&ignoreMismatch=on')
		} catch [System.Net.Webexception] {
			if ($_.Exception.Response.StatusCode.Value__ -eq "405") {
				$wait = 15
			} else {
				if ($_.CategoryInfo.Category -eq "InvalidOperation") {
					Write-Host ("[" + $i + "/" + $TotalHosts + "] https://" + $CurrentHost + " - SSLLabs: site is temporarily down, retrying...")
					$wait = 5
				} else {
					showError('initiateScans(): Invoke-WebRequest returned an error while processing ' + $site, $_)
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



# -----------------------------------------------------------------------------
#
# Main code
#
# -----------------------------------------------------------------------------

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

# Add TLSv1.1, TLSv1.2 and TLSv1.3 to the available TLS protocols for Invoke-WebRequest() and Invoke-RestMethod()
try {
	if ([Net.ServicePointManager]::SecurityProtocol -NotLike '*Tls11*') {
		[Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls11
	}
} catch {
	Write-Host("Notice: TLSv1.1 not available")
}
try {
	if ([Net.ServicePointManager]::SecurityProtocol -NotLike '*Tls12*') {
		[Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls12
	}
} catch {
	Write-Host("Notice: TLSv1.2 not available")
}
try {
	if ([Net.ServicePointManager]::SecurityProtocol -NotLike '*Tls13*') {
		[Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls13
	}
} catch {
	Write-Host("Notice: TLSv1.3 not available")
}

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
'"ISP"' + $Delimiter + `
'"WHOIS"' + $Delimiter + `
'"Certificate Issuer"' + $Delimiter + `
'"Valid until"' + $Delimiter + `
'"Recommendations"' `
	| Out-File $ResultsFile

# Prepare header of the HTTP headers debug file
'"URL"' + $Delimiter + `
'"HTTP header"' + $Delimiter + `
'"Value"' + $Delimiter + `
'"Rating"' `
	| Out-File $HeadersDebugFile

# Prepare header of the HTTP headers debug file
'"URL"' + $Delimiter + `
'"Newly discovered host"' `
	| Out-File $altNamesFile

# Reset counter which shows the user where we are in the list of domains
$i = 0

# Get the start time so we can calculate how long the script has run
$StartTime = (Get-Date).ToFileTime()
$ETA = $null

# To save time, send requests to SSLLabs for scanning the hostnames, but don't retrieve the results yet
#initiateScans

# Calculate the total number of hosts to scan
if ($UseCommonPrefixes -eq $true) {
	$TotalHosts = ((1 + $CommonPrefixes.count) * $Hosts.count)
} else {
	$TotalHosts = $Hosts.count
}

# Now get the results for all domains
ForEach ($Domain in $Hosts) {
	$CurrentHosts = @()
	$CurrentHosts += $Domain

	if ($UseCommonPrefixes -eq $true) {
		ForEach ($Prefix in $CommonPrefixes) {
			$CurrentHosts += ($Prefix + "." + $Domain)
		}
	}

	ForEach($CurrentHost in $CurrentHosts) {
		$SSLResult = ""
		Write-Progress `
			-Activity ("WebsiteSecurityAssessment " + $WSAversion + $ETA) `
			-status "Current host: $CurrentHost" `
			-percentComplete ($i++ / $TotalHosts*100)

		foreach ($HTTPPrefix in $Protocols) {
			switch ($HTTPPrefix) {
				# Check the hostname via HTTP
				"http" {
					# Perform a DNS lookup for the hostname
					$DNSResults = DNSLookup($CurrentHost)

					# Get WHOIS information for domain
					$whoisResult = whois($CurrentHost)

					if ($DNSResults -ne "N/A") {
						# Get grading from securityheaders.io
						$SecurityHeadersGrade = securityheaders("http://" + $CurrentHost)

						# Get grading from Mozilla HTTP Observatory
						$MozillaObservatoryResult = mozillaObservatory($CurrentHost)

						# Analyze the website content
						$Suggestions = analyzeWebsite("http://" + $CurrentHost)

						# Analyze the HTTP methods
						$Suggestions += analyzeHTTPMethods("http://" + $CurrentHost)

						if ($Suggestions -ne "") {
							$Suggestions = $Suggestions.TrimEnd("`n")
						} else {
							$Suggestions = "None!"
						}
						ForEach ($endpoint in $DNSResults) {
							# Expand IPv6 address
							if ($endpoint.Contains(":")) {
								$IPAddress = expandIPv6($endpoint)
							} else {
								$IPAddress = $endpoint
							}

							# Get RIPE ASN prefix for the IP address (hosting provider info)
							$PrefixResult = getPrefix($IPAddress)

							# Perform reverse DNS lookup for the IP address
							$rDNS = reverseDNSLookup($IPAddress)

							# Write results to output file
							'"http"' + $Delimiter + `
							'"' + $CurrentHost + '"' + $Delimiter + `
							'"' + $IPAddress + '"' + $Delimiter + `
							'"' + $rDNS + '"' + $Delimiter + `
							'"N/A"' + $Delimiter + `
							'"' + $SecurityHeadersGrade + '"' + $Delimiter + `
							'"' + $MozillaObservatoryResult + '"' + $Delimiter + `
							'"' + $PrefixResult + '"' + $Delimiter + `
							'"' + $whoisResult + '"' + $Delimiter + `
							'"N/A"' + $Delimiter + `
							'"N/A"' + $Delimiter + `
							'"' + $Suggestions + '"' `
								| Out-File -Append $ResultsFile
						}
					} else {
							# Write results to output file
							'"http"' + $Delimiter + `
							'"' + $CurrentHost + '"' + $Delimiter + `
							'"No DNS record"' + $Delimiter + `
							'"N/A"' + $Delimiter + `
							'"N/A"' + $Delimiter + `
							'"N/A"' + $Delimiter + `
							'"N/A"' + $Delimiter + `
							'"N/A"' + $Delimiter + `
							'"' + $whoisResult + '"' + $Delimiter + `
							'"N/A"' + $Delimiter + `
							'"N/A"' + $Delimiter + `
							'"N/A"' `
								| Out-File -Append $ResultsFile
					}

					break
				}

				# Check the hostname via HTTPS
				"https" {
					# Reset the 'SSLLabs scan is ready'-flag
					$ScanReady = $false

					# Create a Do-While loop for retrieving the SSLLabs result
					Write-Host ("[" + $i + "/" + $TotalHosts + "] https://" + $CurrentHost + " - SSLLabs: Sending request...")
					Do {
						try {
							$SSLResult = Invoke-RestMethod `
								-Uri ($SSLLabsAPIUrl + '?host=' + $CurrentHost + '&all=done&hideResults=true&ignoreMismatch=on')
						} catch [System.Net.Webexception] {
							if ($_.CategoryInfo.Category -eq "InvalidOperation") {
								Write-Host ("[" + $i + "/" + $TotalHosts + "] https://" + $CurrentHost + " - SSLLabs: site is temporarily down, retrying...")
								Start-Sleep -s 5
							} else {
								showError('main(): Invoke-WebRequest returned an error while processing ' + $CurrentHost, $_)
							}
						}

						switch ($SSLResult.status) {
							# Status = resolving DNS names
							"DNS" {
								Write-Host ("[" + $i + "/" + $TotalHosts + "] https://" + $CurrentHost + " - SSLLabs: Resolving DNS names, please wait...")

								# Wait 5 seconds before next try
								Start-Sleep -s 5
								break
							}

							# Status = SSL Labs scan in progress, please wait...
							"IN_PROGRESS" {
								# Reset number-of-endpoints-done counter so we can show to the user which endpoint is currently being processed
								$EndpointsDone = 1

								# Default to a 2 second wait time
								$SecondsToWait = 2

								foreach ($endpoint in $SSLResult.endpoints) {
									# Find the number of endpoints which have already been processed
									if ($endpoint.statusMessage -eq "Ready") {
										$EndpointsDone++
									}

									# Find the IP address of the current endpoint being processed
									if ($endpoint.statusMessage -eq "In progress") {
											$CurrentEndpoint = $endpoint.ipAddress
											$CurrentDetails = $endpoint.statusDetailsMessage
									}

									# Find the endpoint with the longest wait time
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
								Write-Host ("[" + $i + "/" + $TotalHosts + "] https://" + $CurrentHost + " - SSLLabs [" + $EndpointsDone + "/" + $SSLResult.endpoints.Count + "] " + $CurrentDetails + " for endpoint " + $CurrentEndpoint + " (pausing for " + $SecondsToWait + " seconds)")

								# Ease down requests on the SSLLabs API
								Start-Sleep -s $SecondsToWait

								break
							}

							# Status = SSL Labs scan could not finish correctly
							"ERROR" {
								$ScanReady = $true
								Write-Host ("[" + $i + "/" + $TotalHosts + "] https://" + $CurrentHost + " - SSLLabs: Scan error (" + $SSLResult.statusMessage + ")")

								# Get WHOIS information for domain
								$whoisResult = whois($CurrentHost)

								# Check if no DNS record was found
								if ($SSLResult.statusMessage -eq 'Unable to resolve domain name') {
									# Write results to output file
									'"https"' + $Delimiter + `
									'"' + $CurrentHost + '"' + $Delimiter + `
									'"No DNS record"' + $Delimiter + `
									'"N/A"' + $Delimiter + `
									'"N/A"' + $Delimiter + `
									'"N/A"' + $Delimiter + `
									'"N/A"' + $Delimiter + `
									'"N/A"' + $Delimiter + `
									'"' + $whoisResult + '"' + $Delimiter + `
									'"N/A"' + $Delimiter + `
									'"N/A"' + $Delimiter + `
									'"N/A"' `
										| Out-File -Append $ResultsFile
								} else {
									# Get grading from securityheaders.io
									$SecurityHeadersGrade = securityheaders("https://" + $CurrentHost)

									# Get grading from Mozilla HTTP Observatory
									$MozillaObservatoryResult = mozillaObservatory($CurrentHost)

									# Analyze the headers
									$Suggestions = analyzeWebsite("https://" + $CurrentHost)

									# Analyze the HTTP methods
									$Suggestions += analyzeHTTPMethods("https://" + $CurrentHost)

									if ($Suggestions -ne "") {
										$Suggestions = $Suggestions.TrimEnd("`n")
									} else {
										$Suggestions = "None!"
									}

									# Write results to output file
									'"https"' + $Delimiter + `
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

								Write-Host ("[" + $i + "/" + $TotalHosts + "] https://" + $CurrentHost + " - Done")
								break
							}

							# Status = SSL Labs scan finished
							"READY" {
								$ScanReady = $true
								Write-Host ("[" + $i + "/" + $TotalHosts + "] https://" + $CurrentHost + " - SSLLabs: scan ready")

								# Get WHOIS information for domain
								$whoisResult = whois($CurrentHost)

								# Get grading from securityheaders.io
								$SecurityHeadersGrade = securityheaders("https://" + $CurrentHost)

								# Get grading from Mozilla HTTP Observatory
								$MozillaObservatoryResult = mozillaObservatory($CurrentHost)

								# Analyze the website content
								$WebsiteSuggestions = analyzeWebsite("https://" + $CurrentHost)

								# Analyze the HTTP methods
								$WebsiteSuggestions += analyzeHTTPMethods("https://" + $CurrentHost)

								# Get the certificate's keysize, validation dates and issuer
								$CertificateKeySize = $SSLResult.certs[0].keyStrength
								$CertificateDateBefore = ((Get-Date("1/1/1970")).addSeconds([int64]$SSLResult.certs[0].notBefore / 1000).ToLocalTime()).ToString("yyyy-MM-dd")
								$CertificateDateAfter = ((Get-Date("1/1/1970")).addSeconds([int64]$SSLResult.certs[0].notAfter / 1000).ToLocalTime()).ToString("yyyy-MM-dd")
								$CertificateIssuer = $SSLResult.certs[0].issuerSubject -replace '^CN=|,.*$'

								# Iterate through all the endpoints
								foreach ($endpoint in $SSLResult.endpoints) {
									$Suggestions = ""

									# Get RIPE ASN prefix for the IP address (hosting provider info)
									$PrefixResult = getPrefix($endpoint.ipAddress)

									# Perform reverse DNS lookup for the IP address
									$rDNS = reverseDNSLookup($endpoint.ipAddress)

									# Check if the SSLLabs test returned any warnings
									if ($endpoint.hasWarnings -eq "true") {
										$Suggestions += "Fix all warnings from the SSL Labs test`n"
									}

									switch ($endpoint.statusMessage) {
										"Ready" {
											# Check for a DNS CAA record
											if ($SSLResult.certs[0].dnsCaa) {
												if ($SSLResult.certs[0].dnsCaa = $false) {
													$Suggestions += "Add a DNS CAA record`n"
												}
											} else {
												$Suggestions += "Add a DNS CAA record`n"
											}

											# Check if the certificate is of an Extended Validation-type
											if ($endpoint.details.cert.validationType -eq "E") {
												$CertificateType = "EV"
											} else {
												$CertificateType = "-"
											}

											# Check for warnings on common DH primes
											if ($endpoint.details.dhUsesKnownPrimes) {
												if ($endpoint.details.dhUsesKnownPrimes -ne "0") {
													$Suggestions += "Replace common DH primes with custom DH primes`n"
												}
											}
											if ($endpoint.details.dhYsReuse -eq "true") {
												$Suggestions += "Replace DH public server primes with custom primes`n"
											}
											if ($endpoint.details.ecdhParameterReuse -eq "true") {
												$Suggestions += "Replace ECDH public server primes with custom primes`n"
											}

											# Check if the preferred named group is available
											$PreferredNamedGroupFound = $False
											foreach ($namedGroup in $endpoint.details.namedGroups.list) {
												if ($namedGroup.name -eq $PreferredNamedGroup) {
													$PreferredNamedGroupFound = $True
												}
											}
											if ($PreferredNamedGroupFound -eq $False) {
												$Suggestions += "Add the named group " + $PreferredNamedGroup + " and make it first preferred`n"
											} else {
												if ($endpoint.details.namedGroups.list[0].name -ne $PreferredNamedGroup) {
													$Suggestions += "Make the named group " + $PreferredNamedGroup + " first preferred`n"
												}
											}

											# Check if domain is on HSTS preload list
											if ($endpoint.details.hstsPolicy.preload -ne "true") {
												$Suggestions += "Add this domain to the HSTS preload list`n"
											}

											# Check for OCSP stapling
											if ($endpoint.details.ocspStapling -ne "true") {
												$Suggestions += "Enable OCSP stapling`n"
											}

											# Remove any trailing linefeeds
											$Suggestions += $WebsiteSuggestions
											if ($Suggestions -ne "") {
												$Suggestions = $Suggestions.TrimEnd("`n")
											} else {
												$Suggestions = "None!"
											}

											# Also show the grade if trust issues are ignored
											if ($endpoint.grade -ne $endpoint.gradeTrustIgnored) {
												$SSLLabsGrade = $endpoint.grade + ' (' + $endpoint.gradeTrustIgnored + ')'
											} else {
												$SSLLabsGrade = $endpoint.grade
											}

											'"https"' + $Delimiter + `
											'"' + $CurrentHost + '"' + $Delimiter + `
											'"' + $endpoint.ipAddress + '"' + $Delimiter + `
											'"' + $rDNS + '"' + $Delimiter + `
											'"' + $SSLLabsGrade + '"' + $Delimiter + `
											'"' + $SecurityHeadersGrade + '"' + $Delimiter + `
											'"' + $MozillaObservatoryResult + '"' + $Delimiter + `
											'"' + $PrefixResult + '"' + $Delimiter + `
											'"' + $whoisResult + '"' + $Delimiter + `
											'"' + $CertificateIssuer + '"' + $Delimiter + `
											'"' + $CertificateDateAfter + '"' + $Delimiter + `
											'"' + $Suggestions + '"' `
												| Out-File -Append $ResultsFile

											break
										}

										"Unable to connect to the server" {
											$Suggestions = ($Suggestions + $WebsiteSuggestions).TrimEnd("`n")

											'"https"' + $Delimiter + `
											'"' + $CurrentHost + '"' + $Delimiter + `
											'"' + $endpoint.ipAddress + '"' + $Delimiter + `
											'"' + $rDNS + '"' + $Delimiter + `
											'"N/A"' + $Delimiter + `
											'"' + $SecurityHeadersGrade + '"' + $Delimiter + `
											'"' + $MozillaObservatoryResult + '"' + $Delimiter + `
											'"' + $PrefixResult + '"' + $Delimiter + `
											'"' + $whoisResult + '"' + $Delimiter + `
											'"N/A"' + $Delimiter + `
											'"N/A"' + $Delimiter + `
											'"' + $Suggestions + '"' `
												| Out-File -Append $ResultsFile

											break
										}

										"No secure protocols supported" {
											$Suggestions = ("Enable HTTPS`n" + $Suggestions + $WebsiteSuggestions).TrimEnd("`n")

											'"https"' + $Delimiter + `
											'"' + $CurrentHost + '"' + $Delimiter + `
											'"' + $endpoint.ipAddress + '"' + $Delimiter + `
											'"' + $rDNS + '"' + $Delimiter + `
											'"N/A"' + $Delimiter + `
											'"' + $SecurityHeadersGrade + '"' + $Delimiter + `
											'"' + $MozillaObservatoryResult + '"' + $Delimiter + `
											'"' + $PrefixResult + '"' + $Delimiter + `
											'"' + $whoisResult + '"' + $Delimiter + `
											'"N/A"' + $Delimiter + `
											'"N/A"' + $Delimiter + `
											'"' + $Suggestions + '"' `
												| Out-File -Append $ResultsFile

											break
										}

										default {
											$Suggestions += $WebsiteSuggestions
											if ($Suggestions -ne "") {
												$Suggestions = $Suggestions.TrimEnd("`n")
											} else {
												$Suggestions = "None!"
											}

											'"https"' + $Delimiter + `
											'"' + $CurrentHost + '"' + $Delimiter + `
											'"' + $endpoint.ipAddress + '"' + $Delimiter + `
											'"' + $rDNS + '"' + $Delimiter + `
											'"' + $endpoint.statusMessage + '"' + $Delimiter + `
											'"' + $SecurityHeadersGrade + '"' + $Delimiter + `
											'"' + $MozillaObservatoryResult + '"' + $Delimiter + `
											'"' + $PrefixResult + '"' + $Delimiter + `
											'"' + $whoisResult + '"' + $Delimiter + `
											'"N/A"' + $Delimiter + `
											'"N/A"' + $Delimiter + `
											'"' + $Suggestions + '"' `
												| Out-File -Append $ResultsFile

											break
										}
									}

									# Check for any unknown hostnames in the certificate's altname
									foreach ($altName in $SSLResult.certs[0].altNames) {
										# Prevent reporting of hostnames starting with *. or common prefixes
										if (!$Hosts.Contains($altName) `
											-and (($altName.split('.')[0] -eq '*') -and ($CurrentHost -ne ($altName.split('.')[1..99] -join '.')))) {
											'"' + $CurrentHost + '"' + $Delimiter + `
											'"' + $altName +'"' `
												| Out-File -Append $altNamesFile
										}
									}
								}
								Write-Host ("[" + $i + "/" + $TotalHosts + "] https://" + $CurrentHost + " - Done")
								break
							}

							default {
								Write-Host ("[" + $i + "/" + $TotalHosts + "] https://" + $CurrentHost + " - SSLLabs: Unknown status: " + $SSLResult.status)

								break
							}
						}
					} While ($ScanReady -eq $false)
				}

				default {
					break
				}
			}
		}
		$TotalTime = ((Get-Date).ToFileTime() - $StartTime)
		$ETA = " (ETA: " + [DateTime]::FromFileTime((Get-Date).ToFileTime() + (($TotalTime / $i) * ($TotalHosts - $i))) + ")"
	}
}
Write-Progress "Done" "Done" -completed
Write-Host("Total time: " + [DateTime]::FromFileTime($TotalTime).ToString("hh\:mm\:ss"))
