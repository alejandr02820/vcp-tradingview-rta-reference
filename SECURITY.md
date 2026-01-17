# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| < 1.1   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly:

1. **DO NOT** create a public GitHub issue
2. Email security@veritaschain.org with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Any suggested fixes (optional)

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Target**: Within 30 days (depending on severity)

## Security Best Practices

When deploying this implementation:

1. **Key Management**
   - Store Ed25519 private keys securely
   - Use hardware security modules (HSM) in production
   - Rotate keys periodically

2. **Network Security**
   - Always use HTTPS/TLS for webhook endpoints
   - Implement webhook signature verification
   - Use firewall rules to restrict access

3. **Data Protection**
   - Anonymize sensitive data in logs
   - Implement proper access controls
   - Follow data retention policies

## Contact

- **Security Team:** security@veritaschain.org
- **PGP Key:** Available upon request

---

**VeritasChain Standards Organization (VSO)**
