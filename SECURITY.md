# Security Policy

## Reporting a vulnerability

Please do not report security vulnerabilities in public issues, discussions or pull requests.

Use GitHub's private reporting: open the **Security** tab of this repository and choose **Report a vulnerability**. Only the maintainers can see the report.
If there is no such button, open an issue that only asks for a private contact channel (no details) and a maintainer will reply.

Include the oaax-manager version (`oaax-manager --version`), the steps to reproduce, and the impact you expect.

## What is in scope

oaax-manager downloads archives and extracts them on the user's machine. Reports about the download verification (sha256 pinning, size limits),
the archive extraction rules (path traversal, links, special files) or the shipped `index.json` are especially welcome.
