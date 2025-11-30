# License Compliance Scanner

Backend system for automated license detection and compliance reporting using rule-based pattern matching.

## Project Structure

```
.
├── app/                    # Application source code
├── tests/                  # Test suite
├── config/                 # Configuration modules
├── main.py                 # Application entry point
└── requirements.txt        # Python dependencies
```

## Setup

### 1. Create Virtual Environment

```bash
python -m venv venv
```

### 2. Activate Virtual Environment

**Windows:**
```bash
venv\Scripts\activate
```

**Linux/Mac:**
```bash
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

## Configuration

The application uses environment variables for configuration. Copy `.env.example` to `.env` and update the values:

```bash
cp .env.example .env
```

### Configuration Options

| Variable | Description | Default |
|----------|-------------|---------|
| `JWT_SECRET_KEY` | Secret key for JWT token signing (MUST change in production!) | `your-secret-key-here-change-in-production` |
| `JWT_ALGORITHM` | JWT signing algorithm | `HS256` |
| `JWT_EXPIRATION_HOURS` | JWT token expiration time in hours | `24` |
| `DATABASE_URL` | Database connection URL | `sqlite:///./lcs.db` |
| `RULES_FILE_PATH` | Path to license rules JSON file | `rules.json` |
| `SERVER_HOST` | Server host address | `0.0.0.0` |
| `SERVER_PORT` | Server port | `8000` |
| `LOG_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) | `INFO` |
| `REQUEST_TIMEOUT_SECONDS` | Request timeout in seconds | `30` |

### Configuration Validation

The application validates all configuration on startup:
- Checks that required files exist (rules.json)
- Validates configuration values (port ranges, log levels, etc.)
- Logs configuration summary (without sensitive values)

If configuration is invalid, the application will fail to start with a clear error message.

## Running the Application

```bash
python main.py
```

Or using uvicorn directly:

```bash
uvicorn main:app --reload
```

The API will be available at `http://localhost:8000` (or the configured `SERVER_HOST:SERVER_PORT`)

## API Documentation

- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## Running Tests

```bash
pytest
```

Run with coverage:

```bash
pytest --cov=app tests/
```

## Development

The application uses:
- **FastAPI** - Web framework
- **SQLModel** - ORM and data validation
- **PyJWT** - JWT token handling
- **Passlib/Bcrypt** - Password hashing
- **Pytest** - Unit testing
- **Hypothesis** - Property-based testing
