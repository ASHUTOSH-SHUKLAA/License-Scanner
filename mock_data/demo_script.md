# Video Demo Script
## License & Compliance Scanner

This script will guide you through recording a professional demo video of your application.

---

## 🎬 Demo Flow (Recommended Order)

### Part 1: Introduction (30 seconds)
**What to show:**
- Open browser to your deployed app or localhost
- Show the Swagger UI documentation page

**What to say:**
> "This is the License & Compliance Scanner - a backend API system that automatically detects software licenses using rule-based pattern matching. Let me show you how it works."

---

### Part 2: API Documentation Overview (30 seconds)
**What to show:**
- Scroll through Swagger UI
- Highlight the three main sections: Authentication, Scans, Reports

**What to say:**
> "The API has three main sections: Authentication for user management, Scans for license detection, and Reports for compliance reporting. Let's start by creating a user account."

---

### Part 3: User Registration (45 seconds)
**What to show:**
- Expand `POST /api/auth/register`
- Click "Try it out"
- Enter sample data:
  ```json
  {
    "username": "demo_user",
    "password": "SecurePass123!"
  }
  ```
- Execute the request
- Show the JWT token response

**What to say:**
> "First, I'll register a new user. The system validates password complexity and returns a JWT token for authentication. Notice the token is automatically generated upon registration."

---

### Part 4: Authentication (30 seconds)
**What to show:**
- Copy the JWT token from response
- Click the "Authorize" button at the top
- Paste token in format: `Bearer <token>`
- Click "Authorize"

**What to say:**
> "Now I'll authenticate using the JWT token. This token will be included in all subsequent requests to protected endpoints."

---

### Part 5: License Scanning - MIT (1 minute)
**What to show:**
- Expand `POST /api/scans`
- Click "Try it out"
- Paste MIT license text from `sample_licenses.json` (sample 1)
- Execute request
- Show the response with detected licenses

**What to say:**
> "Let's scan a complete MIT license. The engine uses three detection strategies: exact pattern matching, keyword matching, and regex patterns. Here you can see it detected MIT with 95% confidence, showing the exact matched text and position in the document."

**Point out in response:**
- `license_type: "MIT"`
- `confidence: 0.95`
- `matched_text`
- `start_position` and `end_position`

---

### Part 6: License Scanning - Apache 2.0 (45 seconds)
**What to show:**
- Use `POST /api/scans` again
- Paste Apache 2.0 license text (sample 2)
- Execute and show results

**What to say:**
> "Here's an Apache 2.0 license. The system correctly identifies it with high confidence. Notice how it can detect multiple patterns within the same text."

---

### Part 7: Multiple License Detection (45 seconds)
**What to show:**
- Scan the "Multiple Licenses" sample (sample 8)
- Show both MIT and Apache detected

**What to say:**
> "The scanner can also detect multiple licenses in a single text. Here it found both MIT and Apache 2.0 references with their respective confidence scores."

---

### Part 8: Retrieve Scan Results (30 seconds)
**What to show:**
- Expand `GET /api/scans/{scan_id}`
- Enter the scan_id from previous response
- Execute and show full results

**What to say:**
> "I can retrieve any previous scan by its ID. This shows the complete scan results including all detected licenses and metadata."

---

### Part 9: Generate Compliance Report (45 seconds)
**What to show:**
- Expand `GET /api/reports/{scan_id}`
- Use the same scan_id
- Execute and show the structured report

**What to say:**
> "The compliance report provides a structured summary including total licenses detected, license types, average confidence, and any compliance warnings. This is useful for legal teams and audit purposes."

**Point out in response:**
- `summary` section with totals
- `licenses` array with details
- `compliance_warnings` (if any)

---

### Part 10: Scan History (30 seconds)
**What to show:**
- Expand `GET /api/scans`
- Set parameters: `skip=0`, `limit=10`
- Execute and show paginated list

**What to say:**
> "The system maintains a complete history of all scans. Here's a paginated list showing scan IDs, status, and timestamps. Users can only access their own scans for security."

---

### Part 11: Edge Cases (Optional - 30 seconds)
**What to show:**
- Scan the "Unknown License" sample (sample 10)
- Show empty results

**What to say:**
> "The system gracefully handles edge cases. Here's a proprietary license that doesn't match any known patterns - it returns no matches rather than false positives."

---

### Part 12: Conclusion (20 seconds)
**What to show:**
- Scroll back to top of Swagger UI
- Show the complete API documentation

**What to say:**
> "This License & Compliance Scanner demonstrates a production-ready backend API with JWT authentication, sophisticated pattern matching, and comprehensive compliance reporting. The system is deployed on Render with PostgreSQL and includes extensive testing coverage."

---

## 📋 Pre-Recording Checklist

### Setup:
- [ ] Application is running (locally or on Render)
- [ ] Browser is open to Swagger UI (`/docs`)
- [ ] `sample_licenses.json` file is open for copy-paste
- [ ] Screen recording software is ready
- [ ] Browser zoom is set to comfortable level (100-110%)
- [ ] Close unnecessary tabs/windows
- [ ] Disable notifications

### Test Run:
- [ ] Do a complete dry run before recording
- [ ] Verify all endpoints work
- [ ] Have sample data ready to paste
- [ ] Know which scan_id you'll use for demos

### Recording Settings:
- [ ] Record in 1080p (1920x1080) if possible
- [ ] Enable microphone for narration
- [ ] Consider using a tool like OBS Studio or Loom
- [ ] Record browser window only (not full screen)

---

## 🎯 Quick Copy-Paste Data

### User Registration:
```json
{
  "username": "demo_user",
  "password": "SecurePass123!"
}
```

### MIT License (Short):
```
MIT License

Copyright (c) 2024 Ashutosh Mani Shukla

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software.
```

### Apache 2.0 (Short):
```
Apache License, Version 2.0

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
```

### Multiple Licenses:
```
This project uses multiple licenses:

Core library: MIT License - Permission is hereby granted, free of charge, to any person obtaining a copy.

Plugin system: Licensed under the Apache License, Version 2.0.
```

---

## 💡 Tips for Great Video

### Do's:
✅ Speak clearly and at moderate pace  
✅ Pause briefly between sections  
✅ Highlight important parts of responses  
✅ Show confidence scores and matched text  
✅ Demonstrate error handling (optional)  
✅ Keep video under 5 minutes total  

### Don'ts:
❌ Don't rush through explanations  
❌ Don't skip showing the responses  
❌ Don't use overly technical jargon  
❌ Don't make the video too long (max 6-7 minutes)  
❌ Don't forget to show the compliance report  

---

## 🎥 Alternative: Postman Demo

If you prefer Postman over Swagger UI:

1. Import the API endpoints into Postman
2. Create a collection with:
   - Register request
   - Login request
   - Scan requests (with different licenses)
   - Get scan request
   - Get report request
   - Get history request
3. Use Postman's environment variables for the JWT token
4. Record the Postman window instead

---

## ⏱️ Timing Breakdown

| Section | Duration | Total |
|---------|----------|-------|
| Introduction | 0:30 | 0:30 |
| API Overview | 0:30 | 1:00 |
| Registration | 0:45 | 1:45 |
| Authentication | 0:30 | 2:15 |
| MIT Scan | 1:00 | 3:15 |
| Apache Scan | 0:45 | 4:00 |
| Multiple Licenses | 0:45 | 4:45 |
| Retrieve Scan | 0:30 | 5:15 |
| Compliance Report | 0:45 | 6:00 |
| Scan History | 0:30 | 6:30 |
| Conclusion | 0:20 | 6:50 |

**Target Duration:** 5-7 minutes

---

## 📝 Script Variations

### For Technical Audience:
Focus on:
- Architecture (layered design, repository pattern)
- Pattern matching algorithms
- Confidence scoring calculation
- Database schema and relationships
- Testing coverage

### For Non-Technical Audience:
Focus on:
- Problem it solves
- Ease of use
- Practical applications
- Compliance benefits
- Real-world scenarios

---

Good luck with your recording! 🎬
