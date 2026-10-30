# Security Policy

## Reporting a vulnerability

Please do not report security vulnerabilities in public issues, discussions or pull requests.

1. Use GitHub's private reporting: open the **Security** tab of this repository and choose **Report a vulnerability**. Only the maintainers can see the report.
2. If there is no such button, email **security@oaax.org** with the same details.
3. Include the oaax-manager version (`oaax-manager --version`), the steps to reproduce, and the impact you expect.

## What is in scope

oaax-manager downloads archives and extracts them on the user's machine. Reports are especially welcome about:

- the download verification (sha256 pinning, size limits),
- the archive extraction rules (path traversal, links, special files),
- the shipped `index.json`.
