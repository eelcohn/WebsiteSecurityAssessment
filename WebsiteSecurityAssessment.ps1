###############################################################################
# This script will assess several security aspects of websites. It will use
# the SSLLabs and SecurityHeaders.io API's to automatically retrieve the
# grading for a list of websites.
#
# Written by Eelco Huininga 2017
###############################################################################

# Global variables
$SSLLabsAPIUrl         = "https://api.ssllabs.com/api/v2/analyze"
$SecurityHeadersAPIUrl = "https://securityheaders.io/"
$RIPEWhoisAPIUrl       = "https://stat.ripe.net/data/whois/data.json"
$RIPEPrefixAPIUrl      = "https://stat.ripe.net/data/prefix-overview/data.json"
$RIPEDNSAPIUrl         = "https://stat.ripe.net/data/dns-chain/data.json"
$WhoIsUrl              = "http://www.webservicex.net/whois.asmx/GetWhoIS"
$ProxyUrl              = ""
$InputFile             = "Hosts.txt"
$ResultsFile           = "SSLLabs-" + (Get-Date -UFormat %Y%m%d) + ".csv"
$altNamesFile          = "SSLLabs.altNames.txt"
$Delimiter             = "`t"



###############################################################################
# Function definitions
###############################################################################
# Get WHOIS record for domain name
###############################################################################

function whois($site) {
    $WHOISResult = Invoke-WebRequest `
        -Proxy $ProxyUrl `
        -ProxyUseDefaultCredentials `
        -Uri ($WhoIsUrl + '?HostName=' + $site)

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
    $PrefixResult = Invoke-RestMethod `
        -Proxy $ProxyUrl `
        -ProxyUseDefaultCredentials `
        -Uri ($RIPEPrefixAPIUrl + '?resource=' + $endpoints.ipAddress)
    return ($PrefixResult.data.asns.holder)
}

###############################################################################
# Get the securityheaders.io rating
###############################################################################

function securityheaders($site) {
    $Result = Invoke-WebRequest `
        -Proxy $ProxyUrl `
        -ProxyUseDefaultCredentials `
        -MaximumRedirection 0 `
        -ErrorAction Ignore `
        -Uri ($SecurityHeadersAPIUrl + '?q=' + $site + '&hide=on')
    return ($Result.Headers.'X-Grade')
}

###############################################################################
# Get the DNS records for a site
###############################################################################

function getDNSRecords($site) {
    $DNSResult = Invoke-RestMethod `
        -Proxy $ProxyUrl `
        -ProxyUseDefaultCredentials `
        -Uri ($RIPEDNSAPIUrl + '?resource=' + $SSLLabsHost)
    return ($DNSResult)
}



###############################################################################
#
# Main code
#
###############################################################################

# Read hosts from input file
$Hosts = Get-Content ($InputFile)

# Prepare header of the output file
'"Hostname"' + $Delimiter + `
'"Rating"' + $Delimiter + `
'"Rating if trust ignored"' + $Delimiter + `
'"securityheaders.io Grade"' + $Delimiter + `
'"Has warnings"' + $Delimiter + `
'"SNI"' + $Delimiter + `
'"Server name"' + $Delimiter + `
'"Server signature"' + $Delimiter + `
'"IP address"' + $Delimiter + `
'"Hosting provider"' + $Delimiter + `
'"WHOIS"' | Out-File $ResultsFile

# Now get the results for all domains
$i = 0
foreach ($SSLLabsHost in $Hosts) {
    $ScanReady = $false
    Write-Progress `
        -Activity “Getting SSLLabs results” `
        -status “Host: $SSLLabsHost” `
        -percentComplete  ($i++ / $Hosts.count*100)

    Do {
        $SSLResult = Invoke-RestMethod `
            -Proxy $ProxyUrl `
            -ProxyUseDefaultCredentials `
            -Uri ($SSLLabsAPIUrl + '?host=' + $SSLLabsHost + '&all=done&hideResults=true&ignoreMismatch=on')

        switch ($SSLResult.status) {
            # Status = resolving DNS names
            "DNS" {
                Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $SSLLabsHost + " - SSLLabs: Resolving DNS names, please wait...                                   `r")

                # Wait 5 seconds before next try
                Start-Sleep -s 5
                break
            }

            # Status = SSL Labs scan could not finish correctly
            "ERROR" {
                $ScanReady = $true
                Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $SSLLabsHost + " - SSLLabs: Scan error (" + $SSLResult.statusMessage + ")                         `r")

                # Get WHOIS information for domain
                Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $SSLLabsHost + " - WHOIS lookup                                                                   `r")
                $whoisResult = whois($SSLLabsHost)

                # Write results to output file
                '"' + $SSLLabsHost + '"' + $Delimiter + `
                '"' + $SSLResult.statusMessage + '"' + $Delimiter + `
                '"N/A"' + $Delimiter + `
                '"' + $SecurityHeadersGrade + '"' + $Delimiter + `
                '"N/A"' + $Delimiter + `
                '"N/A"' + $Delimiter + `
                '"N/A"' + $Delimiter + `
                '"N/A"' + $Delimiter + `
                '"N/A"' + $Delimiter + `
                '"N/A"' + $Delimiter + `
                '"' + $whoisResult + '"' | Out-File -Append $ResultsFile

                Write-Host ("[" + $i + "/" + $Hosts.count + "] " + $SSLLabsHost + " - Done                                                                  ")
                break
            }

            # Status = SSL Labs scan finished
            "READY" {
                $ScanReady = $true
                Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $SSLLabsHost + " - SSLLabs: scan ready                                             `r")

                # Get WHOIS information for domain
                Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $SSLLabsHost + " - WHOIS lookup                                                    `r")
                $whoisResult = whois($SSLLabsHost)

                # Get grading from securityheaders.io
                Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $SSLLabsHost + " - Getting securityheaders.io grading...                                  `r")
                $SecurityHeadersGrade = securityheaders('https%3A%2F%2F' + $SSLLabsHost)

                # Iterate through all the endpoints
                foreach ($endpoints in $SSLResult.endpoints) {
                    # Get RIPE ASN prefix for the IP address (hosting provider info)
                    Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $SSLLabsHost + " - Retrieving RIPE prefix for " + $endpoints.ipAddress + "                                `r")
                    $PrefixResult = getPrefix ($endpoints.ipAddress)

                    if ($endpoints.statusMessage -eq "Ready") {
                        '"' + $SSLLabsHost + '"' + $Delimiter + `
                        '"' + $endpoints.grade + '"' + $Delimiter + `
                        '"' + $endpoints.gradeTrustIgnored + '"' + $Delimiter + `
                        '"' + $SecurityHeadersGrade + '"' + $Delimiter + `
                        '"' + $endpoints.hasWarnings + '"' + $Delimiter + `
                        '"' + $endpoints.sniRequired + '"' + $Delimiter + `
                        '"' + $endpoints.serverName + '"' + $Delimiter + `
                        '"' + $endpoints.details.serverSignature + '"' + $Delimiter + `
                        '"' + $endpoints.ipAddress + '"' + $Delimiter + `
                        '"' + $PrefixResult + '"' + $Delimiter + `
                        '"' + $whoisResult + '"' | Out-File -Append $ResultsFile

                        foreach ($altName in $endpoints.details.cert.altNames) {
#                            if (get-content($InputFile) -contains $altName) {
                                $endpoints.details.cert.altNames | Out-File -Append $altNamesFile
#                            }
                        }
                    } else {
                        '"' + $SSLLabsHost + '"' + $Delimiter + `
                        '"' + $endpoints.statusMessage + '"' + $Delimiter + `
                        '"N/A"' + $Delimiter + `
                        '"' + $SecurityHeadersGrade + '"' + $Delimiter + `
                        '"' + $endpoints.hasWarnings + '"' + $Delimiter + `
                        '"' + $endpoints.sniRequired + '"' + $Delimiter + `
                        '"' + $endpoints.serverName + '"' + $Delimiter + `
                        '"' + $endpoints.details.serverSignature + '"' + $Delimiter + `
                        '"' + $endpoints.ipAddress + '"' + $Delimiter + `
                        '"' + $PrefixResult + '"' + $Delimiter + `
                        '"' + $whoisResult + '"' | Out-File -Append $ResultsFile
                    }
                }
                Write-Host ("[" + $i + "/" + $Hosts.count + "] " + $SSLLabsHost + " - Done                                                                   ")
                break
            }

            # Status = SSL Labs scan in progress, please wait...
            "IN_PROGRESS" {
                # Wait before next try
                $SecondsToWait = $SSLResult.endpoints.eta

                # Retry in 15 seconds if ETA is unknown
                if ($SecondsToWait -eq -1) {
                    $SecondsToWait = 15
                }

                # Retry in 150 seconds if ETA is longer than 150 seconds
                if ($SecondsToWait -gt 150) {
                    $SecondsToWait = 150
                }
                Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $SSLLabsHost + " - SSLLabs: scan in progress, pausing for " + $SecondsToWait + " seconds...                                  `r")
                Start-Sleep -s $SecondsToWait
                break
            }

            default {
                Write-Host -NoNewLine ("[" + $i + "/" + $Hosts.count + "] " + $SSLLabsHost + " - SSLLabs: Unknown status: " + $SSLResult.status + "                             `r")
                break
            }
        }

        # Wait between each request
        Start-Sleep -s 1
    } While ($ScanReady -eq $false)
}
Write-Progress "Done" "Done" -completed
