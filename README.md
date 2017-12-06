# WebsiteSecurityAssessment
This PowerShell script will automatically assess the SSLLabs, SecurityHeaders.io and Mozilla SSL Observatory gradings for multiple websites. I've created this script for medium- and large-scale company's who own hundreds of website which need to be periodically assessed for some basic security measures.

The script will read all the sites from the Hosts.txt file. Add your websites to the Hosts.txt file, place the Hosts.txt file in the same path as the script, and run the script. The script will output it's findings to a CSV file, which you can import into Microsoft Excel or LibreOffice Calc.

The CSV file has the following columns:
* Hostname: this is the hostname (or URL) read from the Hosts.txt file
* IP address: this is the IP address (or addresses) associated with the hostname
* Server name: this is the reverse-DNS lookup on the IP address associated with the hostname
* Hosting provider: the registrar associated with the IP address. This can help you identify where the website is hosted.
* WHOIS: the registrar associated with the hostname (or domain name). This can help you identify where the domain name is registered.
* SSLLabs rating: the SSLLabs rating for the specified hostname. If there's a trust issue, it will also report the rating if the trust issue is ignored, e.g. T (B)
* securityheaders.io rating: the securityheaders.io rating for the specified hostname
* Mozilla SSL Observatory rating: the Mozilla SSL Observatory rating for the specified hostname
* Recommendations: Any additional recommendations found for the specified hostname
* Cookie recommendations: Any recommendations for any cookies found on the website. This script will scan all cookies for the HttpOnly-flag and the Secure-flag. If it finds a cookie which has no HttpOnly- or Secure-flag, it will report it.

