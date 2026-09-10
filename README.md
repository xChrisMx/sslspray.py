# sslspray.py
sslspray.py — masscan + nmap sweep that finds which internal web servers still accept SSLv2/SSLv3/TLS 1.0/1.1, flags weak (C/D/F-graded) cipher suites, and audits certs (self-signed, expired, weak signature algo). Outputs a CSV + Excel report with an Overview dashboard, risk-ranked findings, and formula-injection-safe output.
