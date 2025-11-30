# Design Document

## Overview

The License Compliance Scanner (LCS) is a FastAPI-based backend system that provides automated license detection through rule-based pattern matching. The system follows a layered architecture with clear separation between API endpoints, business logic, data access, and rule processing. Users authenticate via JWT tokens, submit license text for analysis, and receive structured compliance reports.

The system is designed for simplicity and maintainability, using SQLite for data persistence, declarative JSON rules for license detection, and a straightforward REST API interface.

## Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     API Layer (FastAPI)                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ Auth Routes  │  │ Scan Routes  │  │Report Routes │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────┐
│                    Service Layer                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ Auth Service │  │ Scan Service │  │License Engine│  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────┐
│                 Data Access Layer                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │User Repository│ │Scan Repository│ │ Rule Loader  │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┴───────────────────┐
        │                                       │
┌───────────────┐                      ┌────────────────┐
│SQLite Database│                      │ rules.json     │
│(SQLModel/ORM) │                      │(License Rules) │
└───────────────┘                      └────────────────┘
```

### Technology Stack

- **Web Framework**: FastAPI (async support, automatic OpenAPI docs, Pydantic validation)
- **Authentication**: PyJWT for token generation and validation
- **ORM**: SQLModel (combines SQLAlchemy and Pydantic for type-safe database operations)
- **Database**: SQLite (simple, file-based, zero-configuration)
- **Password Hashing**: passlib with bcrypt
- **Validation**: Pydantic models (built into FastAPI)

## Components and Interfaces

### 1. API Layer (FastAPI Routes)

#### Authentication Endpoints
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login (returns JWT)

#### Scan Endpoints
- `POST /api/scans` - Submit license data for scanning (requires auth)
- `GET /api/scans/{scan_id}` - Retrieve specific scan results (requires auth)
- `GET /api/scans` - List user's scan history with pagination (requires auth)

#### Report Endpoints
- `GET /api/reports/{scan_id}` - Generate compliance report for a scan (requires auth)

### 2. Service Layer

#### AuthService
```python
class AuthService:
    def register_user(username: str, password: str) -> User
    def authenticate_user(username: str, password: str) -> User | None
    def create_access_token(user_id: int) -> str
    def verify_token(token: str) -> int | None  # Returns user_id
    def hash_password(password: str) -> str
    def verify_password(plain: str, hashed: str) -> bool
```

#### ScanService
```python
class ScanService:
    def create_scan(user_id: int, license_text: str) -> Scan
    def execute_scan(scan_id: int) -> ScanResult
    def get_scan_results(scan_id: int, user_id: int) -> ScanResult
    def get_user_scans(user_id: int, skip: int, limit: int) -> List[Scan]
```

#### LicenseEngine
```python
class LicenseEngine:
    def __init__(rules_path: str)
    def load_rules() -> List[LicenseRule]
    def detect_licenses(text: str) -> List[LicenseMatch]
    def calculate_confidence(match: Match, rule: LicenseRule) -> float
```

#### ReportService
```python
class ReportService:
    def generate_report(scan_id: int, user_id: int) -> ComplianceReport
    def format_report_json(scan_result: ScanResult) -> dict
```

### 3. Data Access Layer

#### Repositories
```python
class UserRepository:
    def create(user: User) -> User
    def get_by_username(username: str) -> User | None
    def get_by_id(user_id: int) -> User | None

class ScanRepository:
    def create(scan: Scan) -> Scan
    def get_by_id(scan_id: int) -> Scan | None
    def get_by_user(user_id: int, skip: int, limit: int) -> List[Scan]
    def update_results(scan_id: int, results: dict) -> Scan
```

## Data Models

### Database Models (SQLModel)

```python
class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    hashed_password: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
class Scan(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    license_text: str
    status: str  # "pending", "completed", "failed"
    results_json: str | None  # JSON string of results
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None
```

### API Models (Pydantic)

```python
class RegisterRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class ScanRequest(BaseModel):
    license_text: str

class LicenseMatch(BaseModel):
    license_type: str
    confidence: float
    matched_text: str
    start_position: int
    end_position: int

class ScanResult(BaseModel):
    scan_id: int
    status: str
    licenses: List[LicenseMatch]
    created_at: datetime
    completed_at: datetime | None

class ComplianceReport(BaseModel):
    scan_id: int
    user_id: int
    timestamp: datetime
    total_licenses_found: int
    licenses: List[LicenseMatch]
    warnings: List[str]
    summary: dict
```

### Rule Configuration (JSON)

```json
{
  "rules": [
    {
      "license_type": "MIT",
      "patterns": [
        "MIT License",
        "Permission is hereby granted, free of charge"
      ],
      "keywords": ["MIT", "permission", "free of charge"],
      "confidence_weight": 1.0
    },
    {
      "license_type": "Apache-2.0",
      "patterns": [
        "Apache License, Version 2.0",
        "Licensed under the Apache License"
      ],
      "keywords": ["Apache", "Version 2.0"],
      "confidence_weight": 1.0
    }
  ]
}
```


## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Authentication Properties

**Property 1: Password encryption on registration**
*For any* valid username and password, when a user is registered, the stored password in the database should be encrypted (hashed) and not equal to the plain text password.
**Validates: Requirements 1.1, 8.3**

**Property 2: JWT token generation on login**
*For any* registered user with valid credentials, logging in should return a JWT token that can be decoded and has an expiration time in the future.
**Validates: Requirements 1.2**

**Property 3: Valid token grants access**
*For any* authenticated user with a valid JWT token, requests to protected endpoints should succeed and return 200-level status codes.
**Validates: Requirements 1.3**

**Property 4: Invalid tokens are rejected**
*For any* malformed, expired, or invalid JWT token, requests to protected endpoints should be rejected with 401 status code.
**Validates: Requirements 1.4**

**Property 5: Password complexity enforcement**
*For any* password that violates complexity requirements (too short, lacks character diversity), registration should fail with a validation error.
**Validates: Requirements 1.5**

### Scan Submission Properties

**Property 6: Scan creation with unique identifier**
*For any* authenticated user submitting valid license text, a scan should be created with a unique scan ID and associated with that user.
**Validates: Requirements 2.1, 2.5**

**Property 7: Input validation rejects malformed data**
*For any* malformed or invalid license data input, the submission should be rejected with a specific validation error message.
**Validates: Requirements 2.3**

**Property 8: Input method equivalence**
*For any* license text, submitting it via direct text input or file upload should produce equivalent scan results.
**Validates: Requirements 2.4**

### License Detection Properties

**Property 9: All rules are applied**
*For any* license text that contains patterns matching multiple rules, the scan results should include matches from all applicable rules.
**Validates: Requirements 3.1, 3.4**

**Property 10: Matches include confidence scores**
*For any* detected license match, the result should include the license type, matched text, position, and a confidence score between 0 and 1.
**Validates: Requirements 3.2**

**Property 11: Pattern type support**
*For any* rule using exact string matching, keyword matching, or regular expressions, the license engine should correctly identify matches of that pattern type.
**Validates: Requirements 3.5**

### Scan Results Properties

**Property 12: Complete results with locations**
*For any* completed scan, the results should contain all identified licenses with their match locations (start and end positions) and confidence scores.
**Validates: Requirements 4.1, 4.3**

**Property 13: Scan persistence round-trip**
*For any* scan with results, storing it to the database and then retrieving it by scan ID should return equivalent results with all detected licenses preserved.
**Validates: Requirements 4.5, 6.4**

### Compliance Report Properties

**Property 14: Report completeness**
*For any* completed scan, the generated compliance report should include all detected licenses, scan timestamp, user identifier, and summary statistics.
**Validates: Requirements 5.1, 5.2**

**Property 15: Report JSON schema validity**
*For any* generated compliance report, the output should be valid JSON that conforms to the defined ComplianceReport schema.
**Validates: Requirements 5.3**

**Property 16: Warning generation**
*For any* scan that detects licenses with known compliance issues, the report should include appropriate warnings in the warnings list.
**Validates: Requirements 5.4**

### Scan History Properties

**Property 17: User scan isolation**
*For any* authenticated user requesting scan history, the returned scans should only include scans created by that user and no scans from other users.
**Validates: Requirements 6.1**

**Property 18: Pagination correctness**
*For any* user with N scans, requesting page P with size S should return scans from index (P*S) to min((P+1)*S, N), and the total across all pages should equal N.
**Validates: Requirements 6.2**

**Property 19: History metadata only**
*For any* scan in the history list, the returned data should include scan ID, status, timestamp, but should not include the full results_json field.
**Validates: Requirements 6.3**

**Property 20: Chronological ordering**
*For any* user's scan history, the scans should be ordered by created_at timestamp in descending order (most recent first).
**Validates: Requirements 6.5**

### Error Handling Properties

**Property 21: Internal error safety**
*For any* internal error during request processing, the system should log the error details and return a generic 500 error message without exposing internal details.
**Validates: Requirements 7.1**

**Property 22: Validation error specificity**
*For any* request with validation errors, the error response should include specific messages indicating which fields are invalid and why.
**Validates: Requirements 7.2**

**Property 23: HTTP status code correctness**
*For any* error type (validation, authentication, not found, internal), the response should use the appropriate HTTP status code (400, 401, 404, 500).
**Validates: Requirements 7.3**

**Property 24: Database failure resilience**
*For any* database operation failure, the system should handle it gracefully without corrupting existing data or leaving partial writes.
**Validates: Requirements 7.4**

**Property 25: Request timeout handling**
*For any* request that exceeds the configured timeout threshold, the system should terminate the request and return a timeout error.
**Validates: Requirements 7.5**

### Data Integrity Properties

**Property 26: Relational integrity**
*For any* scan record in the database, the user_id foreign key should reference a valid user record, maintaining referential integrity.
**Validates: Requirements 8.4**

## Error Handling

### Error Categories

1. **Validation Errors (400)**
   - Invalid input format
   - Missing required fields
   - Password complexity violations
   - License text exceeds size limits

2. **Authentication Errors (401)**
   - Invalid credentials
   - Expired JWT token
   - Malformed JWT token
   - Missing authentication header

3. **Authorization Errors (403)**
   - Attempting to access another user's scans
   - Insufficient permissions

4. **Not Found Errors (404)**
   - Scan ID does not exist
   - User not found
   - Report not available

5. **Internal Server Errors (500)**
   - Database connection failures
   - Rule loading failures
   - Unexpected exceptions

### Error Response Format

All errors follow a consistent JSON structure:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input data",
    "details": {
      "field": "password",
      "reason": "Password must be at least 8 characters"
    }
  }
}
```

### Error Handling Strategy

- **Logging**: All errors are logged with full stack traces and context
- **User Messages**: Generic messages for internal errors, specific messages for validation errors
- **Rollback**: Database transactions are rolled back on errors to prevent partial writes
- **Timeouts**: Requests timeout after 30 seconds to prevent resource exhaustion
- **Retry Logic**: Not implemented at the API level (client responsibility)

## Testing Strategy

### Unit Testing

The system will use **pytest** as the testing framework with the following structure:

- **Test Organization**: Tests are co-located with source files using `test_*.py` naming
- **Fixtures**: Shared fixtures for database setup, test users, and sample license text
- **Mocking**: Minimal mocking; prefer testing against real SQLite database in memory mode
- **Coverage**: Focus on critical business logic and edge cases

**Unit Test Coverage:**

1. **Authentication Tests**
   - Test password hashing and verification
   - Test JWT token creation and validation
   - Test token expiration handling
   - Edge case: Empty username/password
   - Edge case: SQL injection attempts in username

2. **License Detection Tests**
   - Test exact string matching
   - Test keyword matching
   - Test regex pattern matching
   - Edge case: Empty license text
   - Edge case: Very large license text (size limits)
   - Edge case: Text with no matches

3. **API Endpoint Tests**
   - Test successful registration and login flows
   - Test scan submission and retrieval
   - Test report generation
   - Test pagination with various page sizes
   - Edge case: Invalid scan IDs
   - Edge case: Accessing other users' scans

4. **Database Tests**
   - Test schema initialization
   - Test foreign key constraints
   - Edge case: Database connection failures

### Property-Based Testing

The system will use **Hypothesis** for property-based testing to verify universal properties across many randomly generated inputs.

**Configuration:**
- Each property test should run a minimum of 100 iterations
- Each property test must include a comment tag referencing the design document property
- Tag format: `# Feature: license-compliance-scanner, Property {number}: {property_text}`

**Property Test Coverage:**

1. **Authentication Properties** (Properties 1-5)
   - Generate random valid/invalid usernames and passwords
   - Generate random JWT tokens (valid and malformed)
   - Verify encryption, token generation, access control, and validation

2. **Scan Properties** (Properties 6-8)
   - Generate random license text of varying lengths
   - Generate random user IDs
   - Verify scan creation, validation, and input method equivalence

3. **Detection Properties** (Properties 9-11)
   - Generate license text with known patterns
   - Generate text matching multiple rules
   - Verify all rules are applied and confidence scores are present

4. **Results Properties** (Properties 12-13)
   - Generate random scan results
   - Verify persistence round-trip and completeness

5. **Report Properties** (Properties 14-16)
   - Generate random scans with various license combinations
   - Verify report completeness, schema validity, and warning generation

6. **History Properties** (Properties 17-20)
   - Generate multiple users with varying numbers of scans
   - Verify isolation, pagination, metadata filtering, and ordering

7. **Error Handling Properties** (Properties 21-25)
   - Generate various error conditions
   - Verify error responses, status codes, and resilience

8. **Data Integrity Properties** (Property 26)
   - Generate random database operations
   - Verify referential integrity is maintained

### Integration Testing

- **End-to-End Flows**: Test complete user journeys from registration through scan to report
- **Database Integration**: Test against actual SQLite database (in-memory for speed)
- **Rule Loading**: Test with actual rules.json file
- **API Integration**: Test full request/response cycles through FastAPI test client

### Test Data Strategy

- **Sample License Texts**: Maintain a collection of real-world license texts (MIT, Apache, GPL, etc.)
- **Rule Fixtures**: Test rules.json with known patterns for predictable testing
- **User Fixtures**: Predefined test users with known credentials
- **Scan Fixtures**: Pre-created scans with known results for testing retrieval and reports

## Security Considerations

1. **Password Security**
   - Passwords hashed using bcrypt with appropriate work factor
   - Plain text passwords never logged or stored
   - Password complexity requirements enforced

2. **JWT Security**
   - Tokens signed with strong secret key
   - Short expiration times (e.g., 24 hours)
   - Token validation on every protected endpoint

3. **Input Validation**
   - All inputs validated using Pydantic models
   - SQL injection prevented by ORM parameterization
   - File size limits enforced to prevent DoS

4. **Authorization**
   - Users can only access their own scans
   - User ID extracted from JWT token, not request parameters

5. **Error Messages**
   - Internal errors return generic messages
   - No stack traces or sensitive data exposed to clients

## Performance Considerations

1. **Database Indexing**
   - Index on `user.username` for login lookups
   - Index on `scan.user_id` for history queries
   - Index on `scan.created_at` for chronological ordering

2. **Rule Loading**
   - Rules loaded once at startup and cached in memory
   - No disk I/O during scan processing

3. **Scan Processing**
   - Pattern matching optimized for common cases
   - Early termination for oversized inputs
   - Target: < 2 seconds for 100KB inputs

4. **Pagination**
   - Limit maximum page size to prevent large result sets
   - Use offset-based pagination (simple, sufficient for this use case)

## Deployment Considerations

1. **Database**
   - SQLite file stored in persistent volume
   - Database file path configurable via environment variable
   - Automatic schema initialization on first run

2. **Configuration**
   - JWT secret key from environment variable
   - Rules file path configurable
   - Server host/port configurable

3. **Logging**
   - Structured logging to stdout
   - Log level configurable via environment variable
   - Request/response logging for debugging

4. **API Documentation**
   - Automatic OpenAPI docs at `/docs`
   - ReDoc documentation at `/redoc`
