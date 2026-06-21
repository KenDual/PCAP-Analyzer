# local.zeek — loaded after Zeek's defaults for offline pcap analysis.
#
# json-logs makes every *.log emit newline-delimited JSON, which the parser
# reads uniformly. hash-all-files adds md5/sha1/sha256 to files.log so you get
# hashes you can drop straight into VirusTotal during malware triage.

@load policy/tuning/json-logs.zeek
@load policy/frameworks/files/hash-all-files
@load policy/protocols/conn/known-services
@load policy/protocols/ssl/validate-certs

# Keep Zeek quiet about packet loss / checksums on offline captures.
redef ignore_checksums = T;
