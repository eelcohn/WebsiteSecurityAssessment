###############################################################################
# This script will assess several security aspects of websites. It will use
# the SSLLabs, SecurityHeaders.io and Mozilla SSL Observatory API's to
# automatically retrieve the grading for a list of websites.
#
# Written by Eelco Huininga 2017-2018
###############################################################################

# Global variables
$SSLLabsAPIUrl            = "https://api.ssllabs.com/api/v2/analyze"
$SecurityHeadersAPIUrl    = "https://securityheaders.io/"
$MozillaObservatoryAPIUrl = "https://http-observatory.security.mozilla.org/api/v1/analyze"
$RIPEWhoisAPIUrl          = "https://stat.ripe.net/data/whois/data.json"
$RIPEPrefixAPIUrl         = "https://stat.ripe.net/data/prefix-overview/data.json"
$RIPEDNSAPIUrl            = "https://stat.ripe.net/data/dns-chain/data.json"
$WhoIsUrl                 = "http://www.webservicex.net/whois.asmx/GetWhoIS"
$InputFile                = "Hosts.txt"
$ResultsFile              = "WSAresults-" + (Get-Date -UFormat %Y%m%d) + ".csv"
$altNamesFile             = "WSAdebug.altNames-" + (Get-Date -UFormat %Y%m%d) + ".txt"
$HeadersDebugFile         = "WSAdebug.Headers-" + (Get-Date -UFormat %Y%m%d) + ".txt"
$CookiesDebugFile         = "WSAdebug.Cookies-" + (Get-Date -UFormat %Y%m%d) + ".txt"
$Delimiter                = "`t"



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
	Write-Host ("    $0 [ options ]")
	Write-Host ("")
	Write-Host ("Options:")
	Write-Host ("    -h,        --help                                 Print this help message")
	Write-Host ("    -d url,    --domain url                           Specify target domain")
	Write-Host ("    -i file,   --input file                           Specify file with target domains (default: Hosts.txt)")
}

###############################################################################
# Get WHOIS record for domain name
###############################################################################

function whois($site) {
    Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $SSLLabsHost + " - Performing WHOIS lookup...                                             `r")

    # Get domain part from URL
    $site = $site.split('.')[-2..-1] -join '.'

    $WHOISResult = Invoke-WebRequest `
        -ErrorAction Ignore `
        -Uri ($WhoIsUrl + "?HostName=" + $site)

    if ($WHOISREsult -eq "") {
        return ("N/A")
    }

    # Return first line in WHOIS result after line containing "Registrar:"
    $i = 0
    $WHOISResult.Content.Split("`n") | ForEach-Object {
        if ($_.StartsWith("Registrar:")) {
            return ($WHOISResult.Content.Split("`n")[$i + 1].Trim())
        }
        $i++
    }
    return $null
}

###############################################################################
# Get the RIPE ASN prefix for an IP address
###############################################################################

function getPrefix($ipAddress) {
    Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $SSLLabsHost + " - Retrieving RIPE prefix for " + $endpoints.ipAddress + "                                `r")

    $PrefixResult = Invoke-RestMethod `
        -Uri ($RIPEPrefixAPIUrl + '?resource=' + $endpoints.ipAddress)

    If ($PrefixResult.data.asns.holder) {
        return ($PrefixResult.data.asns.holder)
    } else {
        return ("N/A")
    }
}

###############################################################################
# Get the securityheaders.io rating
###############################################################################

function securityheaders($site) {
    Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $site + " - Getting securityheaders.io grading...                           `r")

    $Result = Invoke-WebRequest `
        -MaximumRedirection 0 `
        -ErrorAction Ignore `
        -Uri ($SecurityHeadersAPIUrl + '?q=https%3A%2F%2F' + $site + '&hide=on')

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
    Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $SSLLabsHost + " - Getting Mozilla HTTP Observatory grading...                            `r")

    # Initiate the Mozilla HTTP Observatory scan by making a POST request
    $Result = Invoke-WebRequest `
        -MaximumRedirection 0 `
        -ErrorAction Ignore `
        -Method POST `
        -Uri ($MozillaObservatoryAPIUrl + '?host=' + $site + '&hidden=true')

    # Convert the JSON response
    $Result = ConvertFrom-Json -InputObject $Result.Content

    # Ugly hack to prevent looping
    $j = 0

    Do {
        If ($Result.error) {
            return ($Result.error)
        }

        # Display a message if the scan hasn't finished yet
        If ($Result.state -ne "FINISHED") {
            Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $SSLLabsHost + " - Getting Mozilla HTTP Observatory grading (pausing for 5 seconds)...    `r")
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
    } While (($Result.state -ne "FINISHED") -and ($Result.state -ne "ABORTED") -and ($j -le 20))

    # Return the resulting grade if the scan finished successfully
    if ($Result.state -eq "FINISHED") {
        return ($Result.grade)
    }

    if ($j -eq 50) {
        return ("No result within 20 requests")
    }

    # Return an error message if the scan didn't finish successfully
    return ($Result.state)
}

###############################################################################
# Get the DNS records for a site
###############################################################################

function getDNSRecords($site) {
    $DNSResult = Invoke-RestMethod `
        -Uri ($RIPEDNSAPIUrl + '?resource=' + $SSLLabsHost)

    return ($DNSResult)
}

###############################################################################
# Analyze the cookies for a site
###############################################################################

function analyzeCookies($site) {
    Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $site + " - Analyzing cookies...                                                   `r")

    try {
        $CookieResult = Invoke-WebRequest `
            -ErrorAction Ignore `
            -Uri $site `
            -SessionVariable mysession
    } catch [System.Net.Webexception] {
        return ("N/A")
    }

    $ReturnString = ''

    foreach ($Cookie in $mysession.Cookies.GetCookies("https://" + $site)) {
        $Cookie | Out-File -Append $CookiesDebugFile
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

    if ($ReturnString) {
        return ($ReturnString.Remove($Result.Length))
    } else {
        return ("None!")
    }
}

###############################################################################
# Analyze the headers for a site
###############################################################################

function analyzeHeaders($site) {
    Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $site + " - Analyzing headers...                                                  `r")

    try {
        $Result = Invoke-WebRequest `
            -ErrorAction Ignore `
            -Uri $site `
            -SessionVariable mysession
    } catch [System.Net.Webexception] {
        return ("N/A")
    }

    $Result.Headers | Out-File -Append $HeadersDebugFile

    $ReturnString = ''

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
        $ReturnString += "Content-Security-Policy should be set`n"
    }

    # Check if 'X-Frame-Options' header is set correctly
    if ($Result.Headers.'X-Frame-Options' -ne "SAMEORIGIN") {
        $ReturnString += "X-Frame-Options should be set to 'SAMEORIGIN'`n"
    }

    # Check if 'X-XSS-Protection' header is set correctly
    if ($Result.Headers.'X-XSS-Protection' -ne "1; mode=block") {
        $ReturnString += "X-XSS-Protection should be set to '1; mode=block'`n"
    }

    # Check if 'X-Content-Type-Options' header is set correctly
    if ($Result.Headers.'X-Content-Type-Options' -ne "nosniff") {
        $ReturnString += "X-Content-Type-Options should be set to 'nosniff'`n"
    }

    # Check if 'Referrer-Policy' header is set
    if ($Result.Headers.'Referrer-Policy' -eq $null) {
        $ReturnString += "Referrer-Policy should be set`n"
    }

    # Check if 'Public-Key-Pins' header is set
    if ($Result.Headers.'Public-Key-Pins' -eq $null) {
        $ReturnString += "Public-Key-Pins should be set`n"
    }

    if ($ReturnString) {
        return ($ReturnString.Remove($Result.Length))
    } else {
        return ("None!")
    }
}



###############################################################################
#
# Main code
#
###############################################################################


# Set proxy
(New-Object System.Net.WebClient).Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

# Read hosts from input file
$Hosts = Get-Content ($InputFile)

# Prepare header of the output file
'"Hostname"' + $Delimiter + `
'"IP address"' + $Delimiter + `
'"Server name"' + $Delimiter + `
'"Hosting provider"' + $Delimiter + `
'"WHOIS"' + $Delimiter + `
'"SSLLabs Rating"' + $Delimiter + `
'"securityheaders.io grade"' + $Delimiter + `
'"Mozilla SSL Observatory grade"' + $Delimiter + `
'"Recommendations"' + $Delimiter + `
'"Cookie Recommendations"' `
    | Out-File $ResultsFile

# Now get the results for all domains
$i = 0
foreach ($SSLLabsHost in $Hosts) {
    $ScanReady = $false
    Write-Progress `
        -Activity “Getting SSLLabs results” `
        -status “Host: $SSLLabsHost” `
        -percentComplete  ($i++ / $Hosts.count*100)

    Do {
        $ScreenWidth = (get-host).UI.RawUI.WindowSize.Width

        $SSLResult = Invoke-RestMethod `
            -Uri ($SSLLabsAPIUrl + '?host=' + $SSLLabsHost + '&all=done&hideResults=true&ignoreMismatch=on')

        switch ($SSLResult.status) {
            # Status = resolving DNS names
            "DNS" {
                Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $SSLLabsHost + " - SSLLabs: Resolving DNS names, please wait...                          `r")

                # Wait 5 seconds before next try
                Start-Sleep -s 5
                break
            }

            # Status = SSL Labs scan in progress, please wait...
            "IN_PROGRESS" {
                # Ease down requests on the SSLLabs API
                $SecondsToWait = $SSLResult.endpoints.eta

                # Retry in 15 seconds if ETA is unknown
                if ($SecondsToWait -eq -1) {
                    $SecondsToWait = 15
                }

                # Retry in 60 seconds if ETA is longer than 60 seconds
                if ($SecondsToWait -gt 60) {
                    $SecondsToWait = 60
                }
                Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $SSLLabsHost + " - SSLLabs: scan in progress, pausing for " + $SecondsToWait + " seconds...            `r")
                Start-Sleep -s $SecondsToWait
                break
            }

            # Status = SSL Labs scan could not finish correctly
            "ERROR" {
                $ScanReady = $true
                Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $SSLLabsHost + " - SSLLabs: Scan error (" + $SSLResult.statusMessage + ")                         `r")

                # Get grading from securityheaders.io
                $SecurityHeadersGrade = securityheaders($SSLLabsHost)

                # Get grading from Mozilla HTTP Observatory
                $MozillaObservatoryResult = mozillaObservatory($SSLLabsHost)

                # Check if no DNS record was found
                if ($SSLResult.statusMessage -eq 'Unable to resolve domain name') {
                    # Write results to output file
                    '"' + $SSLLabsHost + '"' + $Delimiter + `
                    '"No DNS record"' + $Delimiter + `
                    '"N/A"' + $Delimiter + `
                    '"N/A"' + $Delimiter + `
                    '"N/A"' + $Delimiter + `
                    '"N/A"' + $Delimiter + `
                    '"' + $SecurityHeadersGrade + '"' + $Delimiter + `
                    '"' + $MozillaObservatoryResult + '"' + $Delimiter + `
                    '"N/A"' + $Delimiter + `
                    '"N/A"' | Out-File -Append $ResultsFile
                } else {
                    # Get WHOIS information for domain
                    $whoisResult = whois($SSLLabsHost)

                    # Write results to output file
                    '"' + $SSLLabsHost + '"' + $Delimiter + `
                    '"N/A"' + $Delimiter + `
                    '"N/A"' + $Delimiter + `
                    '"N/A"' + $Delimiter + `
                    '"' + $whoisResult + '"' + $Delimiter + `
                    '"' + $SSLResult.statusMessage + '"' + $Delimiter + `
                    '"' + $SecurityHeadersGrade + '"' + $Delimiter + `
                    '"' + $MozillaObservatoryResult + '"' + $Delimiter + `
                    '"N/A"' + $Delimiter + `
                    '"N/A"' | Out-File -Append $ResultsFile
                }

                Write-Host ("[" + $i + "/" + $Hosts.count + "] " + $SSLLabsHost + " - Done                                                                  ")
                break
            }

            # Status = SSL Labs scan finished
            "READY" {
                $ScanReady = $true
                Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $SSLLabsHost + " - SSLLabs: scan ready                                             `r")

                # Get WHOIS information for domain
                $whoisResult = whois($SSLLabsHost)

                # Get grading from securityheaders.io
                $SecurityHeadersGrade = securityheaders($SSLLabsHost)

                # Get grading from Mozilla HTTP Observatory
                $MozillaObservatoryResult = mozillaObservatory($SSLLabsHost)

                # Analyze the cookies
                $CookieSuggestions = analyzeCookies($SSLLabsHost)

                # Analyze the headers
                $HeaderSuggestions = analyzeHeaders($SSLLabsHost)
                
                # Iterate through all the endpoints
                foreach ($endpoints in $SSLResult.endpoints) {
                    $Suggestions = ""
                    # Get RIPE ASN prefix for the IP address (hosting provider info)
                    $PrefixResult = getPrefix ($endpoints.ipAddress)

                    # Check if the certificate is of an Extended Validation-type
                    if ($endpoints.details.cert.validationType -eq "E") {
                        $CertificateType = "EV"
                    } else {
                        $CertificateType = "-"
                    }

                    # Check if the SSLLabs test returned any warnings
                    if ($endpoints.hasWarnings -eq "true") {
                        $Suggestions = $Suggestions + "Fix all warnings from the SSL Labs test`n"
                    }

                    # Check if the server signature is empty
                    if ($endpoints.details.serverSignature) {
                        $Suggestions = $Suggestions + "HTTP header 'Server' isn't empty (" + $endpoints.details.serverSignature + ")`n"
                    }

                    if ($endpoints.statusMessage -eq "Ready") {
                        if ($endpoints.grade -ne $endpoints.gradeTrustIgnored) {
                            $SSLLabsGrade = $endpoints.grade + ' (' + $endpoints.gradeTrustIgnored + ')'
                        } else {
                            $SSLLabsGrade = $endpoints.grade
                        }
                        '"' + $SSLLabsHost + '"' + $Delimiter + `
                        '"' + $endpoints.ipAddress + '"' + $Delimiter + `
                        '"' + $endpoints.serverName + '"' + $Delimiter + `
                        '"' + $PrefixResult + '"' + $Delimiter + `
                        '"' + $whoisResult + '"' + $Delimiter + `
                        '"' + $SSLLabsGrade + '"' + $Delimiter + `
                        '"' + $SecurityHeadersGrade + '"' + $Delimiter + `
                        '"' + $MozillaObservatoryResult + '"' + $Delimiter + `
                        '"' + $Suggestions + $HeaderSuggestions + '"' + $Delimiter + `
                        '"' + $CookieSuggestions + '"' | Out-File -Append $ResultsFile
                    } else {
                        '"' + $SSLLabsHost + '"' + $Delimiter + `
                        '"' + $endpoints.ipAddress + '"' + $Delimiter + `
                        '"' + $endpoints.serverName + '"'  + $Delimiter + `
                        '"' + $PrefixResult + '"' + $Delimiter + `
                        '"' + $whoisResult + '"' + $Delimiter + `
                        '"' + $endpoints.statusMessage + '"' + $Delimiter + `
                        '"' + $SecurityHeadersGrade + '"' + $Delimiter + `
                        '"' + $MozillaObservatoryResult + '"' + $Delimiter + `
                        '"' + $Suggestions + '"' + $Delimiter + `
                        '"' + $CookieSuggestions + '"' | Out-File -Append $ResultsFile
                    }

                    # Check for any unknown hostnames in the certificate's altname
                    foreach ($altName in $endpoints.details.cert.altNames) {
                        if (!$Hosts.Contains($altName)) {
                            Write-Host ("`nUnknown host found: " + $altName)
                            $altName | Out-File -Append $altNamesFile
                        }
                    }
                }
                Write-Host ("[" + $i + "/" + $Hosts.count + "] " + $SSLLabsHost + " - Done                                                                   ")
                break
            }

            default {
                Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $SSLLabsHost + " - SSLLabs: Unknown status: " + $SSLResult.status + "                             `r")
                break
            }
        }

        # Ease down requests on the SSLLabs API
        Start-Sleep -s 1
    } While ($ScanReady -eq $false)
}
Write-Progress "Done" "Done" -completed
