# SAST Test Project

This directory contains a vulnerable Flask application designed specifically for testing the SAST (Static Application Security Testing) tool.

## ⚠️ WARNING

**This application contains intentional security vulnerabilities for testing purposes. DO NOT USE IN PRODUCTION!**

## Purpose

This vulnerable application is designed to test the SAST tool's ability to detect various types of security vulnerabilities including:

- SQL Injection
- Command Injection
- Path Traversal
- Cross-Site Scripting (XSS)
- Insecure Deserialization
- Hardcoded Credentials
- Weak Cryptography
- Information Disclosure
- And many more...

## Vulnerabilities Included

### 1. SQL Injection
- Direct string interpolation in SQL queries
- No parameterized queries

### 2. Command Injection
- `subprocess.check_output()` with `shell=True`
- Direct command execution from user input

### 3. Path Traversal
- Direct file access without path validation
- No sanitization of file paths

### 4. Cross-Site Scripting (XSS)
- Direct output of user input without HTML escaping
- Template injection vulnerabilities

### 5. Insecure Deserialization
- `pickle.loads()` with untrusted data
- No validation of serialized data

### 6. Hardcoded Credentials
- Database passwords in source code
- API keys and secret keys hardcoded

### 7. Weak Cryptography
- MD5 hashing for passwords
- Base64 encoding used as encryption
- Insecure random number generation

### 8. Information Disclosure
- Debug information exposure
- Environment variables disclosure
- Sensitive configuration exposure

## Installation

```bash
# Install dependencies
pip install -r requirements.txt
```

## Running the Application

```bash
# Start the vulnerable application
python vulnerable_app.py
```

The application will start on `http://localhost:5000`

## Testing Endpoints

### SQL Injection
- `POST /login` - Login with SQL injection payload

### Command Injection
- `GET /execute?cmd=<command>` - Execute system commands

### Path Traversal
- `GET /file?file=<path>` - Read arbitrary files

### Code Injection
- `GET /eval?code=<python_code>` - Execute Python code

### Template Injection
- `GET /template?template=<template>` - Server-side template injection

### File Upload
- `POST /upload` - Upload files without validation

### XSS
- `GET /xss?input=<script>` - Cross-site scripting

### Information Disclosure
- `GET /debug` - Expose sensitive information

### Weak Cryptography
- `GET /weak_crypto?password=<password>` - Weak password encoding

## SAST Testing

To test the SAST tool with this application:

1. **Create a ZIP file**:
   ```bash
   zip -r vulnerable-app.zip .
   ```

2. **Upload to SAST tool**:
   - Use the SAST upload interface
   - Upload the `vulnerable-app.zip` file
   - Configure scan settings
   - Run the scan

3. **Expected Results**:
   The SAST tool should detect multiple vulnerabilities including:
   - SQL injection in `/login` endpoint
   - Command injection in `/execute` endpoint
   - Path traversal in `/file` endpoint
   - XSS in `/xss` endpoint
   - Hardcoded credentials throughout the code
   - Weak cryptography functions
   - Insecure deserialization
   - Information disclosure

## Security Tools Tested

This application is designed to test the following SAST tools:

- **Bandit** - Python security linter
- **Semgrep** - Multi-language static analysis
- **Pylint** - Python code analysis
- **ESLint** - JavaScript/TypeScript linting (if JS files added)

## Expected Vulnerability Count

When scanned with a comprehensive SAST tool, this application should trigger approximately:

- 15-25 security vulnerabilities
- 5-10 code quality issues
- 3-5 best practice violations

## Cleanup

After testing, make sure to:

1. Stop the application
2. Remove any uploaded files
3. Clean up temporary files
4. Reset any test data

## Contributing

To add more vulnerabilities for testing:

1. Add new endpoints with intentional vulnerabilities
2. Document the vulnerability type
3. Update this README
4. Test with the SAST tool

## License

This test application is provided for educational and testing purposes only. 