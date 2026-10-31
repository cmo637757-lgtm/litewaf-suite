# Member C Test Cases

This document lists independent test samples for the LiteWAF-NGX testing and reporting work. Attack samples are expected to be blocked with HTTP 403. Normal samples are expected to pass with HTTP 200.

## Attack Samples

| id | Request path or condition | Sample type | Expected status | Test purpose |
| --- | --- | --- | --- | --- |
| A001 | `/search?q=1%27%20OR%20%271%27=%271` | attack | 403 | Detect basic SQL injection tautology. |
| A002 | `/item?id=1%20UNION%20SELECT%20user,password%20FROM%20users` | attack | 403 | Detect SQL UNION extraction attempt. |
| A003 | `/login?user=admin%27--` | attack | 403 | Detect SQL comment-based bypass. |
| A004 | `/api/order?id=1%3Bdrop%20table%20orders` | attack | 403 | Detect stacked SQL command attempt. |
| A005 | `/product?id=1%20AND%20SLEEP(5)` | attack | 403 | Detect time-based SQL injection pattern. |
| A006 | `/comment?msg=%3Cscript%3Ealert(1)%3C%2Fscript%3E` | attack | 403 | Detect reflected XSS script tag. |
| A007 | `/profile?name=%3Cimg%20src=x%20onerror=alert(1)%3E` | attack | 403 | Detect event-handler XSS payload. |
| A008 | `/search?q=%3Csvg%20onload=alert(1)%3E` | attack | 403 | Detect SVG onload XSS payload. |
| A009 | `/redirect?next=javascript:alert(1)` | attack | 403 | Detect JavaScript URL injection. |
| A010 | `/post?title=%3Ciframe%20src=http://evil.example%3E` | attack | 403 | Detect iframe injection attempt. |
| A011 | `/../../etc/passwd` | attack | 403 | Detect Unix directory traversal. |
| A012 | `/download?file=..%2F..%2F..%2Fetc%2Fshadow` | attack | 403 | Detect encoded traversal sequence. |
| A013 | `/download?file=..%5C..%5Cwindows%5Cwin.ini` | attack | 403 | Detect Windows-style traversal sequence. |
| A014 | `/static/%2e%2e/%2e%2e/etc/passwd` | attack | 403 | Detect dot-encoded traversal. |
| A015 | `/cgi-bin/test.cgi` with User-Agent `Nikto/2.5.0` | attack | 403 | Detect scanner User-Agent. |
| A016 | `/` with User-Agent `sqlmap/1.8` | attack | 403 | Detect automated SQL injection scanner. |
| A017 | `/wp-admin/` with User-Agent `Mozilla/5.0` | attack | 403 | Detect common admin probing path. |
| A018 | `/.env` | attack | 403 | Detect sensitive configuration file probing. |
| A019 | `/shell.php?cmd=id` | attack | 403 | Detect command execution probe. |
| A020 | `/login`, request 21 from same client within dynamic window | attack | 403 | Verify dynamic blocking after threshold is exceeded. |
| A021 | `/login`, request 25 from same client within dynamic window | attack | 403 | Verify blocked client remains denied during block period. |

## Normal Samples

| id | Request path or condition | Sample type | Expected status | Test purpose |
| --- | --- | --- | --- | --- |
| N001 | `/` | normal | 200 | Verify homepage request is allowed. |
| N002 | `/index.html` | normal | 200 | Verify static HTML request is allowed. |
| N003 | `/about` | normal | 200 | Verify ordinary page request is allowed. |
| N004 | `/contact` | normal | 200 | Verify common form page is allowed. |
| N005 | `/login` | normal | 200 | Verify normal login page request is allowed before threshold. |
| N006 | `/search?q=nginx` | normal | 200 | Verify ordinary search query is allowed. |
| N007 | `/product?id=1001` | normal | 200 | Verify numeric query parameter is allowed. |
| N008 | `/api/status` | normal | 200 | Verify simple API endpoint is allowed. |
| N009 | `/assets/app.css` | normal | 200 | Verify CSS asset request is allowed. |
| N010 | `/assets/app.js` | normal | 200 | Verify JavaScript asset request is allowed. |
| N011 | `/images/logo.png` | normal | 200 | Verify image asset request is allowed. |
| N012 | `/docs/readme.txt` | normal | 200 | Verify normal text file request is allowed. |
| N013 | `/profile?name=alice` | normal | 200 | Verify plain text parameter is allowed. |
| N014 | `/comment?msg=hello-world` | normal | 200 | Verify simple comment content is allowed. |
| N015 | `/cart?item=book&qty=1` | normal | 200 | Verify multiple benign parameters are allowed. |
| N016 | `/download?file=manual.pdf` | normal | 200 | Verify normal download parameter is allowed. |
| N017 | `/health` | normal | 200 | Verify health check request is allowed. |
| N018 | `/api/users?page=1&size=10` | normal | 200 | Verify pagination parameters are allowed. |
| N019 | `/news/2026/course-design` | normal | 200 | Verify friendly URL path is allowed. |
| N020 | `/login`, request 1 from same client within dynamic window | normal | 200 | Verify dynamic counter does not block immediately. |
| N021 | `/login`, request 20 from same client within dynamic window | normal | 200 | Verify requests at the threshold are still allowed. |
