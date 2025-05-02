# Git Secrets Regular expression (REGEX)
This repository contains a set of regex patterns that can be used to configure git secrets within a local repository. The patterns can be copy-pasted directly into the terminal. The patterns cover the common set of credentials encountered across enterprise workloads.

# Important Notes:

- These patterns may need adjustment based on your specific environment and coding practices.
- False positives can occur, so test your rules before implementing them widely.
- Consider combining with allowlisting patterns for test/example credentials.
- These patterns focus on string literals but won't catch all variations or obfuscated credentials.

# Pre-requisites
1. git installed
2. git initialised for a local repository
3. git-secrets installed
4. git-secrets installed for a local repository

# REGEX patterns
To configure git-secrets pre-commit hook scanning against any of the following credential types, simply copy-paste the example git secrets commands.

## Generic Patterns

### 1. Passwords
```bash
git secrets --add '.*(PASSWORD|PWD|pwd|Password|password|passwd|PASSWD)\s*=\s*.+'
```
### 2. API keys
```bash
git secrets --add '.*(api_key|API_key|API_KEY|KEY|access_key|ACCESS_KEY|Access_Key|Access_key)\s*=\s*.+'
```

## AWS Credentials

### AWS Session Token/STS Security Token
```bash
git secrets --add '(?i)aws(.{0,20})?session(.{0,20})?token(.{0,20})?['"][A-Za-z0-9/+=]{16,}['"]'
```

## Azure Credentials

### Azure Storage Account Key
```bash
git secrets --add '(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88};EndpointSuffix=core\.windows\.net'
```

### Azure SAS Token
```bash
git secrets --add '(?i)sv=[\w%-]+&s[ispt]=[\w%-]+&sig=[A-Za-z0-9%/+]{42,}=?&se=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z'
```

### Azure AD Client Secret/Application Password
```bash
git secrets --add '(?i)(client|app)(.{0,20})?secret(.{0,20})?['"][a-zA-Z0-9_\-~!@#$%^&*()+=:;,.?]{16,}['"]'
```

### Azure Connection String
```bash
git secrets --add '(?i)AccountEndpoint=https://[^;]+\.documents\.azure\.com.*AccountKey=[A-Za-z0-9+/=]{88};'
```

### Azure Key Vault Secret
```bash
git secrets --add '(?i)https://[a-zA-Z0-9-]+\.vault\.azure\.net(.{0,20})?(secrets|keys|certificates)/[a-zA-Z0-9-]+/[a-zA-Z0-9]+'
```

## Database Credentials

### Generic Database Password Pattern
```bash
git secrets --add '(?i)(db|database|sql)(.{0,20})?(password|pwd)(.{0,20})?['\"][^'\"]{8,}['\"]'
```

### PostgreSQL Connection String
```bash
git secrets --add '(?i)(postgres|pg)(ql)?:\/\/[a-zA-Z0-9_]+:[^@]+@[a-zA-Z0-9._-]+:[0-9]+\/[a-zA-Z0-9_]+'
```

### MySQL Connection String
```bash
git secrets --add '(?i)mysql:\/\/[a-zA-Z0-9_]+:[^@]+@[a-zA-Z0-9._-]+:[0-9]+\/[a-zA-Z0-9_]+'
```

### SQL Server Connection String
```bash
git secrets --add '(?i)Server=.*;(User ID|uid)=.*;(Password|pwd)=.*;'
```

### MongoDB Connection URI
```bash
git secrets --add '(?i)mongodb(\+srv)?:\/\/[^:]+:[^@]+@[a-zA-Z0-9._-]+'
```

### Redis Connection String
```bash
git secrets --add '(?i)redis:\/\/([^:]+:[^@]+@)?[a-zA-Z0-9_.-]+:[0-9]+'
```

### DynamoDB Credentials in Code
```bash
git secrets --add '(?i)new\s+AWS.DynamoDB\({(.|\n)*?accessKeyId(.|\n)*?['"][A-Z0-9]{20}['"](.|\n)*?secretAccessKey(.|\n)*?['"][a-zA-Z0-9/+=]{40}['"]'
```

### CosmosDB Connection String
```bash
git secrets --add '(?i)AccountEndpoint=https://[^;]+\.documents\.azure\.com.*AccountKey=[A-Za-z0-9+/=]{88};'
```

## API Authentication

### OAuth Token
```bash
git secrets --add '(?i)(oauth|access)(.{0,20})?token(.{0,20})?['"][a-zA-Z0-9_\-.~+/=]{30,}['"]'
```

### JWT Token
```bash
git secrets --add '(?i)ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'
```

### Generic API Key Pattern
```bash
git secrets --add '(?i)api(.{0,20})?key(.{0,20})?['"][a-zA-Z0-9_\-]{16,}['"]'
```

### Authentication Bearer Token
```bash
git secrets --add '(?i)bearer\s+[a-zA-Z0-9_\-\.=]+'
```

### GraphQL API Token
```bash
git secrets --add '(?i)graphql(.{0,20})?token(.{0,20})?['"][a-zA-Z0-9_\-]{16,}['"]'
```

## Common Service Credentials

### Docker Registry Credentials
```bash
git secrets --add '(?i)docker(.{0,20})?(login|auth)(.{0,20})?['"][a-zA-Z0-9_\-]+['"](.{0,20})?['"][a-zA-Z0-9_\-~!@#$%^&*()+=]{8,}['"]'
```

### NPM Token
```bash
git secrets --add '(?i)npm_[a-zA-Z0-9]{36}'
```

### SSH Private Key
```bash
git secrets --add '-----BEGIN ((EC|RSA|DSA|OPENSSH) )?PRIVATE KEY( BLOCK)?-----'
```

### Service Account Credentials (Generic)
```bash
git secrets --add '(?i)(service|account)(.{0,20})?(key|secret|token|password)(.{0,20})?['"][a-zA-Z0-9_\-\.=]{16,}['"]'
```

### GitHub/GitLab PAT (Personal Access Token)
```bash
git secrets --add '(?i)(github|gitlab)(.{0,20})?(access|api)?(.{0,20})?token(.{0,20})?['"]([a-zA-Z0-9_]{16,}|ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})['"]'
```

### CI/CD Pipeline Secret Variables
```bash
git secrets --add '(?i)(travis|circle|github|gitlab)(.{0,20})?(ci|cd)(.{0,20})?(token|key|secret|password)(.{0,20})?['\"][a-zA-Z0-9_\-]{16,}['\"]'
```