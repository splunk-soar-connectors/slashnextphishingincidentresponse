[comment]: # "Auto-generated SOAR connector documentation"
# SlashNext Phishing Incident Response

Publisher: SlashNext  
Connector Version: 1\.1\.1  
Product Vendor: SlashNext  
Product Name: SlashNextPhishingIR  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.8\.24304  

This integration supports the investigative type of actions to fully automate the analysis of suspicious URLs by integrating with SlashNext Phishing Incident Response

[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2019-2020 SlashNext Inc. (www.slashnext.com)"
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
  
The **SlashNext Phishing Incident Response** Integration app allows Phantom users to fully automate
the analysis of suspicious URLs in phishing emails, network logs, and more. Playbooks that require
URL or Domain analysis can automatically analyze them with the **SlashNext SEER™** threat detection
cloud to get definitive, binary verdicts (malicious or benign) along with IOCs, screenshots, and
more. For example, IR teams responsible for abuse inbox management can extract links or domains out
of suspicious emails and automatically analyze them with the **SlashNext SEER™** threat detection
cloud to get definitive, binary verdicts (malicious or benign) along with IOCs, screenshots, and
more. Automating URL analysis can save IR teams hundreds of hours versus manually triaging these
emails or checking URLs and domains against less accurate phishing databases and domain reputation
services.  
SlashNext threat detection uses browsers in a purpose-built cloud to dynamically inspect page
contents and site behavior in real-time. This method enables SlashNext to follow URL re-directs and
multi-stage attacks to more thoroughly analyze the final page(s) and made a much more accurate,
binary determination with near-zero false positives. It also detects all six major categories of
phishing and social engineering sites. These include credential stealing, rogue software/malware
sites, scareware, phishing exploits (sites hosting weaponized documents, etc.), and social
engineering scams (fake deals, giveaways, etc.).  
Use cases include abuse inbox management where SOC teams can automate URL analysis in phishing
emails to save hundreds of hours versus more manual methods. Playbooks that mine and analyze network
logs can also leverage SlashNext URL analysis on demand.  
SlashNext not only provides accurate, binary verdicts (rather than threat scores), it provides IOC
metadata and screenshots of detected phishing pages. These enable easier classification and
reporting. Screenshots can be used as an aid in on-going employee phishing awareness training and
testing.  
The SlashNext Phishing Incident Response integration app uses an API key to authenticate with the
SlashNext cloud. If you don't have a valid API key, contact the SlashNext team:
support@slashnext.com


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a SlashNextPhishingIR asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api\_key** |  required  | password | SlashNext API Key \(The system uses this API key to authenticate with SlashNext Cloud\. If you don't have a valid API key, please reach us at support\@slashnext\.com\)
**api\_base\_url** |  optional  | string | SlashNext API Base URL \(Input only if specifically provided by SlashNext\)

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity and authentication using the supplied configuration  
[api quota](#action-api-quota) - Find information about your API quota, like current usage, quota left, etc  
[host reputation](#action-host-reputation) - Search in SlashNext Cloud database and retrieve the reputation of a host  
[host urls](#action-host-urls) - Search in SlashNext Cloud database and retrieve a list of all URLs associated with the specified host  
[host report](#action-host-report) - Search in SlashNext Cloud database and retrieve a detailed report for a host and associated URL  
[url scan](#action-url-scan) - Perform a real\-time URL reputation scan with SlashNext cloud\-based SEER Engine  
[url scansync](#action-url-scansync) - Perform a real\-time URL scan with SlashNext cloud\-based SEER Engine in a blocking mode  
[scan report](#action-scan-report) - Retrieve URL scan results against a previous Scan request  
[download screenshot](#action-download-screenshot) - Download webpage screenshot against a previous URL Scan request  
[download html](#action-download-html) - Download webpage HTML against a previous URL Scan request  
[download text](#action-download-text) - Download webpage text against a previous URL Scan request  

## action: 'test connectivity'
Validate the asset configuration for connectivity and authentication using the supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'api quota'
Find information about your API quota, like current usage, quota left, etc

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.errorMsg | string | 
action\_result\.data\.\*\.errorNo | numeric | 
action\_result\.data\.\*\.quotaDetails\.licensedQuota | string | 
action\_result\.data\.\*\.quotaDetails\.remainingQuota | string | 
action\_result\.data\.\*\.quotaDetails\.expiryDate | string | 
action\_result\.data\.\*\.quotaDetails\.isExpired | boolean | 
action\_result\.data\.\*\.quotaDetails\.note | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.State | string | 
action\_result\.summary\.Quota | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'host reputation'
Search in SlashNext Cloud database and retrieve the reputation of a host

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**host** |  required  | Host can either be a domain name or an IPv4 address | string |  `domain`  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.host | string |  `domain`  `ip` 
action\_result\.data\.\*\.errorMsg | string | 
action\_result\.data\.\*\.errorNo | numeric | 
action\_result\.data\.\*\.threatData\.firstSeen | string | 
action\_result\.data\.\*\.threatData\.lastSeen | string | 
action\_result\.data\.\*\.threatData\.threatName | string | 
action\_result\.data\.\*\.threatData\.threatStatus | string | 
action\_result\.data\.\*\.threatData\.threatType | string | 
action\_result\.data\.\*\.threatData\.verdict | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.State | string | 
action\_result\.summary\.Verdict | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'host urls'
Search in SlashNext Cloud database and retrieve a list of all URLs associated with the specified host

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**host** |  required  | Host can either be a domain name or IPv4 address | string |  `domain`  `ip` 
**limit** |  optional  | Maximum number of URL records to fetch\. This is an optional parameter with a default value of 10 | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.host | string |  `domain`  `ip` 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.errorMsg | string | 
action\_result\.data\.\*\.errorNo | numeric | 
action\_result\.data\.\*\.normalizeData\.normalizeMessage | string | 
action\_result\.data\.\*\.normalizeData\.normalizeStatus | numeric | 
action\_result\.data\.\*\.urlDataList\.\*\.finalUrl | string |  `url` 
action\_result\.data\.\*\.urlDataList\.\*\.landingUrl\.scanId | string |  `snx scan id` 
action\_result\.data\.\*\.urlDataList\.\*\.landingUrl\.threatData\.firstSeen | string | 
action\_result\.data\.\*\.urlDataList\.\*\.landingUrl\.threatData\.lastSeen | string | 
action\_result\.data\.\*\.urlDataList\.\*\.landingUrl\.threatData\.threatName | string | 
action\_result\.data\.\*\.urlDataList\.\*\.landingUrl\.threatData\.threatStatus | string | 
action\_result\.data\.\*\.urlDataList\.\*\.landingUrl\.threatData\.threatType | string | 
action\_result\.data\.\*\.urlDataList\.\*\.landingUrl\.threatData\.verdict | string | 
action\_result\.data\.\*\.urlDataList\.\*\.landingUrl\.url | string |  `url` 
action\_result\.data\.\*\.urlDataList\.\*\.scanId | string |  `snx scan id` 
action\_result\.data\.\*\.urlDataList\.\*\.threatData\.firstSeen | string | 
action\_result\.data\.\*\.urlDataList\.\*\.threatData\.lastSeen | string | 
action\_result\.data\.\*\.urlDataList\.\*\.threatData\.threatName | string | 
action\_result\.data\.\*\.urlDataList\.\*\.threatData\.threatStatus | string | 
action\_result\.data\.\*\.urlDataList\.\*\.threatData\.threatType | string | 
action\_result\.data\.\*\.urlDataList\.\*\.threatData\.verdict | string | 
action\_result\.data\.\*\.urlDataList\.\*\.url | string |  `url` 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.State | string | 
action\_result\.summary\.URLs Found | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'host report'
Search in SlashNext Cloud database and retrieve a detailed report for a host and associated URL

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**host** |  required  | Host can either be a domain name or IPv4 address | string |  `domain`  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.host | string |  `domain`  `ip` 
action\_result\.data\.\*\.errorMsg | string | 
action\_result\.data\.\*\.errorNo | numeric | 
action\_result\.data\.\*\.htmlData\.htmlBase64 | string | 
action\_result\.data\.\*\.htmlData\.htmlContenType | string | 
action\_result\.data\.\*\.htmlData\.htmlName | string | 
action\_result\.data\.\*\.normalizeData\.normalizeMessage | string | 
action\_result\.data\.\*\.normalizeData\.normalizeStatus | numeric | 
action\_result\.data\.\*\.scData\.scBase64 | string | 
action\_result\.data\.\*\.scData\.scContentType | string | 
action\_result\.data\.\*\.scData\.scName | string | 
action\_result\.data\.\*\.textData\.textBase64 | string | 
action\_result\.data\.\*\.textData\.textName | string | 
action\_result\.data\.\*\.threatData\.firstSeen | string | 
action\_result\.data\.\*\.threatData\.lastSeen | string | 
action\_result\.data\.\*\.threatData\.threatName | string | 
action\_result\.data\.\*\.threatData\.threatStatus | string | 
action\_result\.data\.\*\.threatData\.threatType | string | 
action\_result\.data\.\*\.threatData\.verdict | string | 
action\_result\.data\.\*\.urlData\.finalUrl | string |  `url` 
action\_result\.data\.\*\.urlData\.landingUrl\.scanId | string |  `snx scan id` 
action\_result\.data\.\*\.urlData\.landingUrl\.threatData\.firstSeen | string | 
action\_result\.data\.\*\.urlData\.landingUrl\.threatData\.lastSeen | string | 
action\_result\.data\.\*\.urlData\.landingUrl\.threatData\.threatName | string | 
action\_result\.data\.\*\.urlData\.landingUrl\.threatData\.threatStatus | string | 
action\_result\.data\.\*\.urlData\.landingUrl\.threatData\.threatType | string | 
action\_result\.data\.\*\.urlData\.landingUrl\.threatData\.verdict | string | 
action\_result\.data\.\*\.urlData\.landingUrl\.url | string |  `url` 
action\_result\.data\.\*\.urlData\.scanId | string |  `snx scan id` 
action\_result\.data\.\*\.urlData\.threatData\.firstSeen | string | 
action\_result\.data\.\*\.urlData\.threatData\.lastSeen | string | 
action\_result\.data\.\*\.urlData\.threatData\.threatName | string | 
action\_result\.data\.\*\.urlData\.threatData\.threatStatus | string | 
action\_result\.data\.\*\.urlData\.threatData\.threatType | string | 
action\_result\.data\.\*\.urlData\.threatData\.verdict | string | 
action\_result\.data\.\*\.urlData\.url | string |  `url` 
action\_result\.data\.\*\.urlDataList\.\*\.finalUrl | string |  `url` 
action\_result\.data\.\*\.urlDataList\.\*\.landingUrl\.scanId | string |  `snx scan id` 
action\_result\.data\.\*\.urlDataList\.\*\.landingUrl\.threatData\.firstSeen | string | 
action\_result\.data\.\*\.urlDataList\.\*\.landingUrl\.threatData\.lastSeen | string | 
action\_result\.data\.\*\.urlDataList\.\*\.landingUrl\.threatData\.threatName | string | 
action\_result\.data\.\*\.urlDataList\.\*\.landingUrl\.threatData\.threatStatus | string | 
action\_result\.data\.\*\.urlDataList\.\*\.landingUrl\.threatData\.threatType | string | 
action\_result\.data\.\*\.urlDataList\.\*\.landingUrl\.threatData\.verdict | string | 
action\_result\.data\.\*\.urlDataList\.\*\.landingUrl\.url | string |  `url` 
action\_result\.data\.\*\.urlDataList\.\*\.scanId | string |  `snx scan id` 
action\_result\.data\.\*\.urlDataList\.\*\.threatData\.firstSeen | string | 
action\_result\.data\.\*\.urlDataList\.\*\.threatData\.lastSeen | string | 
action\_result\.data\.\*\.urlDataList\.\*\.threatData\.threatName | string | 
action\_result\.data\.\*\.urlDataList\.\*\.threatData\.threatStatus | string | 
action\_result\.data\.\*\.urlDataList\.\*\.threatData\.threatType | string | 
action\_result\.data\.\*\.urlDataList\.\*\.threatData\.verdict | string | 
action\_result\.data\.\*\.urlDataList\.\*\.url | string |  `url` 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.State | string | 
action\_result\.summary\.Verdict | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'url scan'
Perform a real\-time URL reputation scan with SlashNext cloud\-based SEER Engine

Type: **investigate**  
Read only: **True**

Perform a real\-time URL reputation scan with SlashNext cloud\-based SEER Engine\. If the specified URL already exists in the cloud database, scan results will get returned immediately\. If not, this action will submit a URL scan request and return with a 'check back later' message along with a unique Scan ID\. Users can check the results of this scan with the 'scan report' action after 30 seconds or later using the returned Scan ID\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | The URL that needs to be scanned | string |  `url` 
**extended\_info** |  optional  | If extented\_info is checked, the system along with URL reputation also downloads forensics data like screenshot, HTML, and rendered text | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.extended\_info | boolean | 
action\_result\.parameter\.url | string |  `url` 
action\_result\.data\.\*\.errorMsg | string | 
action\_result\.data\.\*\.errorNo | numeric | 
action\_result\.data\.\*\.htmlData\.htmlBase64 | string | 
action\_result\.data\.\*\.htmlData\.htmlContenType | string | 
action\_result\.data\.\*\.htmlData\.htmlName | string | 
action\_result\.data\.\*\.normalizeData\.normalizeMessage | string | 
action\_result\.data\.\*\.normalizeData\.normalizeStatus | numeric | 
action\_result\.data\.\*\.scData\.scBase64 | string | 
action\_result\.data\.\*\.scData\.scContentType | string | 
action\_result\.data\.\*\.scData\.scName | string | 
action\_result\.data\.\*\.swlData\.swlMessage | string | 
action\_result\.data\.\*\.swlData\.swlStatus | numeric | 
action\_result\.data\.\*\.textData\.textBase64 | string | 
action\_result\.data\.\*\.textData\.textName | string | 
action\_result\.data\.\*\.urlData\.finalUrl | string |  `url` 
action\_result\.data\.\*\.urlData\.landingUrl\.scanId | string |  `snx scan id` 
action\_result\.data\.\*\.urlData\.landingUrl\.threatData\.firstSeen | string | 
action\_result\.data\.\*\.urlData\.landingUrl\.threatData\.lastSeen | string | 
action\_result\.data\.\*\.urlData\.landingUrl\.threatData\.threatName | string | 
action\_result\.data\.\*\.urlData\.landingUrl\.threatData\.threatStatus | string | 
action\_result\.data\.\*\.urlData\.landingUrl\.threatData\.threatType | string | 
action\_result\.data\.\*\.urlData\.landingUrl\.threatData\.verdict | string | 
action\_result\.data\.\*\.urlData\.landingUrl\.url | string |  `url` 
action\_result\.data\.\*\.urlData\.scanId | string |  `snx scan id` 
action\_result\.data\.\*\.urlData\.threatData\.firstSeen | string | 
action\_result\.data\.\*\.urlData\.threatData\.lastSeen | string | 
action\_result\.data\.\*\.urlData\.threatData\.threatName | string | 
action\_result\.data\.\*\.urlData\.threatData\.threatStatus | string | 
action\_result\.data\.\*\.urlData\.threatData\.threatType | string | 
action\_result\.data\.\*\.urlData\.threatData\.verdict | string | 
action\_result\.data\.\*\.urlData\.url | string |  `url` 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.State | string | 
action\_result\.summary\.Verdict | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'url scansync'
Perform a real\-time URL scan with SlashNext cloud\-based SEER Engine in a blocking mode

Type: **investigate**  
Read only: **True**

Perform a real\-time URL scan with SlashNext cloud\-based SEER Engine in a blocking mode\. If the specified URL already exists in the cloud database, the scan result will get returned immediately\. If not, this action will submit a URL scan request and wait for the scan to finish\. The scan may take up to 30 seconds to finish\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | The URL that needs to be scanned | string |  `url` 
**extended\_info** |  optional  | If extented\_info is checked, the system along with URL reputation also downloads forensics data like screenshot, HTML, and rendered text | boolean | 
**timeout** |  optional  | A timeout value in seconds\. If the system is unable to complete a scan within the specified timeout, a timeout error will be returned\. Users may try again with a different timeout\. If no timeout value is specified, a default value of 60 seconds will be used | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.extended\_info | boolean | 
action\_result\.parameter\.timeout | numeric | 
action\_result\.parameter\.url | string |  `url` 
action\_result\.data\.\*\.errorMsg | string | 
action\_result\.data\.\*\.errorNo | numeric | 
action\_result\.data\.\*\.htmlData\.htmlBase64 | string | 
action\_result\.data\.\*\.htmlData\.htmlContenType | string | 
action\_result\.data\.\*\.htmlData\.htmlName | string | 
action\_result\.data\.\*\.normalizeData\.normalizeMessage | string | 
action\_result\.data\.\*\.normalizeData\.normalizeStatus | numeric | 
action\_result\.data\.\*\.scData\.scBase64 | string | 
action\_result\.data\.\*\.scData\.scContentType | string | 
action\_result\.data\.\*\.scData\.scName | string | 
action\_result\.data\.\*\.swlData\.swlMessage | string | 
action\_result\.data\.\*\.swlData\.swlStatus | numeric | 
action\_result\.data\.\*\.textData\.textBase64 | string | 
action\_result\.data\.\*\.textData\.textName | string | 
action\_result\.data\.\*\.urlData\.finalUrl | string |  `url` 
action\_result\.data\.\*\.urlData\.landingUrl\.scanId | string |  `snx scan id` 
action\_result\.data\.\*\.urlData\.landingUrl\.threatData\.firstSeen | string | 
action\_result\.data\.\*\.urlData\.landingUrl\.threatData\.lastSeen | string | 
action\_result\.data\.\*\.urlData\.landingUrl\.threatData\.threatName | string | 
action\_result\.data\.\*\.urlData\.landingUrl\.threatData\.threatStatus | string | 
action\_result\.data\.\*\.urlData\.landingUrl\.threatData\.threatType | string | 
action\_result\.data\.\*\.urlData\.landingUrl\.threatData\.verdict | string | 
action\_result\.data\.\*\.urlData\.landingUrl\.url | string |  `url` 
action\_result\.data\.\*\.urlData\.scanId | string |  `snx scan id` 
action\_result\.data\.\*\.urlData\.threatData\.firstSeen | string | 
action\_result\.data\.\*\.urlData\.threatData\.lastSeen | string | 
action\_result\.data\.\*\.urlData\.threatData\.threatName | string | 
action\_result\.data\.\*\.urlData\.threatData\.threatStatus | string | 
action\_result\.data\.\*\.urlData\.threatData\.threatType | string | 
action\_result\.data\.\*\.urlData\.threatData\.verdict | string | 
action\_result\.data\.\*\.urlData\.url | string |  `url` 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.State | string | 
action\_result\.summary\.Verdict | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'scan report'
Retrieve URL scan results against a previous Scan request

Type: **investigate**  
Read only: **True**

Retrieve URL scan results against a previous Scan request\. If the scan is finished, the result will be returned immediately; otherwise, a 'check back later' message will be returned\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**scanid** |  required  | Scan ID returned by an earlier call to 'url scan' or 'url scansync' action | string |  `snx scan id` 
**extended\_info** |  optional  | If extented\_info is checked, the system along with URL reputation also downloads forensics data like screenshot, HTML, and rendered text | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.extended\_info | boolean | 
action\_result\.parameter\.scanid | string |  `snx scan id` 
action\_result\.data\.\*\.errorMsg | string | 
action\_result\.data\.\*\.errorNo | numeric | 
action\_result\.data\.\*\.htmlData\.htmlBase64 | string | 
action\_result\.data\.\*\.htmlData\.htmlContenType | string | 
action\_result\.data\.\*\.htmlData\.htmlName | string | 
action\_result\.data\.\*\.normalizeData\.normalizeMessage | string | 
action\_result\.data\.\*\.normalizeData\.normalizeStatus | numeric | 
action\_result\.data\.\*\.scData\.scBase64 | string | 
action\_result\.data\.\*\.scData\.scContentType | string | 
action\_result\.data\.\*\.scData\.scName | string | 
action\_result\.data\.\*\.swlData\.swlMessage | string | 
action\_result\.data\.\*\.swlData\.swlStatus | numeric | 
action\_result\.data\.\*\.textData\.textBase64 | string | 
action\_result\.data\.\*\.textData\.textName | string | 
action\_result\.data\.\*\.urlData\.finalUrl | string |  `url` 
action\_result\.data\.\*\.urlData\.landingUrl\.scanId | string |  `snx scan id` 
action\_result\.data\.\*\.urlData\.landingUrl\.threatData\.firstSeen | string | 
action\_result\.data\.\*\.urlData\.landingUrl\.threatData\.lastSeen | string | 
action\_result\.data\.\*\.urlData\.landingUrl\.threatData\.threatName | string | 
action\_result\.data\.\*\.urlData\.landingUrl\.threatData\.threatStatus | string | 
action\_result\.data\.\*\.urlData\.landingUrl\.threatData\.threatType | string | 
action\_result\.data\.\*\.urlData\.landingUrl\.threatData\.verdict | string | 
action\_result\.data\.\*\.urlData\.landingUrl\.url | string |  `url` 
action\_result\.data\.\*\.urlData\.scanId | string |  `snx scan id` 
action\_result\.data\.\*\.urlData\.threatData\.firstSeen | string | 
action\_result\.data\.\*\.urlData\.threatData\.lastSeen | string | 
action\_result\.data\.\*\.urlData\.threatData\.threatName | string | 
action\_result\.data\.\*\.urlData\.threatData\.threatStatus | string | 
action\_result\.data\.\*\.urlData\.threatData\.threatType | string | 
action\_result\.data\.\*\.urlData\.threatData\.verdict | string | 
action\_result\.data\.\*\.urlData\.url | string |  `url` 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.State | string | 
action\_result\.summary\.Verdict | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'download screenshot'
Download webpage screenshot against a previous URL Scan request

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**scanid** |  required  | Scan ID returned by an earlier call to 'url scan' or 'url scansync' action | string |  `snx scan id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.scanid | string |  `snx scan id` 
action\_result\.data\.\*\.errorMsg | string | 
action\_result\.data\.\*\.errorNo | numeric | 
action\_result\.data\.\*\.scData\.scBase64 | string | 
action\_result\.data\.\*\.scData\.scContentType | string | 
action\_result\.data\.\*\.scData\.scName | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.State | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'download html'
Download webpage HTML against a previous URL Scan request

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**scanid** |  required  | Scan ID returned by an earlier call to 'url scan' or 'url scansync' action | string |  `snx scan id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.scanid | string |  `snx scan id` 
action\_result\.data\.\*\.errorMsg | string | 
action\_result\.data\.\*\.errorNo | numeric | 
action\_result\.data\.\*\.htmlData\.htmlBase64 | string | 
action\_result\.data\.\*\.htmlData\.htmlContenType | string | 
action\_result\.data\.\*\.htmlData\.htmlName | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.State | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'download text'
Download webpage text against a previous URL Scan request

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**scanid** |  required  | Scan ID returned by an earlier call to 'url scan' or 'url scansync' action | string |  `snx scan id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.scanid | string |  `snx scan id` 
action\_result\.data\.\*\.errorMsg | string | 
action\_result\.data\.\*\.errorNo | numeric | 
action\_result\.data\.\*\.textData\.textBase64 | string | 
action\_result\.data\.\*\.textData\.textName | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.State | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 