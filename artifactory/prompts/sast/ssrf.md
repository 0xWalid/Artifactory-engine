# SAST Guided Questions: Server-Side Request Forgery (SSRF)

**Usage:** For a `sast` SSRF hit, at **low temperature** make the model *describe
the data flow* via the questions below before ruling TP/FP. Prove survivors at
runtime against the in-scope host before `confirmed`.

## Describe-the-flow questions (answer each, cite line numbers)
1. Which outbound-request API is the sink (`requests`/`http`/`fetch`, `curl`,
   URL opener, webhook, image/PDF fetcher, XML parser with external entities)?
2. Where does the destination URL/host originate and is it **user-controllable**
   (full URL, host, path, or just a query param)?
3. Is the destination validated by **allow-list of hosts/schemes**, a
   **deny-list**, or nothing? Name the check.
4. Does validation happen **before** resolution but the request follow
   **redirects** / re-resolve DNS (TOCTOU) afterwards?
5. Can the input reach internal ranges (169.254.169.254, 127.0.0.0/8, RFC1918,
   `localhost`, `file://`, `gopher://`) — or is scheme/host constrained?
6. What does a successful internal fetch **return to the caller** (response body,
   status, timing) — i.e. is it blind or does it exfiltrate?

## Ruling
- **False Positive** if destination is strictly allow-listed (scheme + host) with
  no redirect/DNS-rebinding gap, or the URL is not user-controllable.
- **Keep (candidate)** otherwise → PoC targets an **in-scope** collaborator/marker
  only (never a real cloud metadata endpoint unless authorised); log with evidence.
