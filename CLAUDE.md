# VSNx00 Monitor - Project Notes and Technical Documentation

## Project Overview

Python script for capturing and exporting solar inverter data from ABB VSN300 and VSN700 data loggers via their REST API endpoints.

**Supported Devices:**
- ABB VSN300 (uses X-Digest authentication - non-standard Digest variant)
- ABB VSN700 (uses HTTP Basic authentication)

**API Endpoints:**
- `/v1/status` - Device status information
- `/v1/livedata` - Real-time inverter data
- `/v1/feeds` - Historical feed data

**Output:** JSON file (vsnx00_data.json) containing all captured data

---

## Authentication Architecture

### VSN300 Authentication (X-Digest)
- **Protocol:** Custom variant of HTTP Digest Authentication
- **Header:** `X-Digest` instead of standard `WWW-Authenticate: Digest`
- **Implementation:** `VSN300HTTPDigestAuthHandler` class
- **Challenge-Response:** Server sends 401 with `X-Digest` challenge, client responds with credentials
- **Realm:** Uses `realm=None` in password manager (critical - see "Realm Handling" below)

### VSN700 Authentication (Basic)
- **Protocol:** HTTP Basic Authentication (preemptive)
- **Header:** Standard `WWW-Authenticate: Basic`
- **Implementation:** `VSN700HTTPPreemptiveBasicAuthHandler` class
- **Preemptive:** Sends credentials with first request without waiting for 401 challenge
- **Empty Passwords:** Supports empty passwords for guest accounts

### Account Types
Both devices support two account types:
1. **Guest Account**
   - Username: `guest` (lowercase, not "User")
   - Password: empty string
   - Recommended for read-only access

2. **Admin Account**
   - Username: `admin`
   - Password: device-specific password
   - Required for write operations

---

## Critical Bug Fixes

### 1. SSL Context Bypass Issue (ROOT CAUSE)

**Problem:**
All requests returned HTTP 401 errors despite correct credentials.

**Root Cause:**
The `make_request()` function was passing an SSL context parameter to `urlopen()`:
```python
# BROKEN CODE:
return urlopen(requested_url, timeout=10, context=unverified_context)
```

When an SSL context is passed to `urlopen()`, Python bypasses the globally installed opener with authentication handlers and creates a new opener without them.

**Fix:**
Remove the context parameter entirely:
```python
# WORKING CODE:
return urlopen(requested_url, timeout=10)
```

**Location:** vsnx00-monitor.py:25

**User Feedback:** "WOOOOOOOOOOOOOOOORKS!!!!"

**Lesson Learned:** Never pass `context` parameter to `urlopen()` when using custom authentication handlers via `install_opener()`.

---

### 2. Null Check for Failed Requests

**Problem:**
When authentication failed, `make_request()` returned `None`, but code attempted to call `json.load()` on it, causing `AttributeError: 'NoneType' object has no attribute 'read'`.

**Fix:**
Added null checks in all three data fetching methods:
```python
json_response = make_request(url_status_data)
if json_response is None:
    return None
```

**Locations:**
- vsnx00-monitor.py:119-120 (get_vsnx00_status_data)
- vsnx00-monitor.py:138-139 (get_vsnx00_live_data)
- vsnx00-monitor.py:157-158 (get_vsnx00_feeds_data)

---

### 3. Variable Shadowing in VSN300HTTPDigestAuthHandler

**Problem:**
Parameter `auth` was being overwritten by assignment, causing potential bugs.

**Fix:**
Renamed local variable to avoid shadowing:
```python
# BEFORE:
auth = self.get_authorization(req, chal)
if auth:
    auth_val = 'X-Digest %s' % auth

# AFTER:
auth_response = self.get_authorization(req, chal)
if auth_response:
    auth_val = 'X-Digest %s' % auth_response
```

**Location:** vsnx00-monitor.py:39-41

---

### 4. Config File Write Mode Error

**Problem:**
ConfigParser.write() expects text mode, but file was opened in binary mode.

**Fix:**
```python
# BEFORE:
with open(path, 'wb') as configfile:

# AFTER:
with open(path, 'w') as configfile:
```

**Location:** vsnx00-monitor.py:248

---

### 5. VSN700 Empty Password Support

**Problem:**
Preemptive Basic auth handler didn't send credentials when password was empty.

**Fix:**
Changed condition from `if pw:` to `if user:` to support empty passwords:
```python
user, pw = self.passwd.find_user_password(realm, url)
if user:  # Send auth if we have a user (password can be empty)
    raw = "%s:%s" % (user, pw if pw else "")
```

**Location:** vsnx00-monitor.py:77-79

---

## Realm Handling - Critical Configuration

### What is a Realm?
In HTTP authentication, a "realm" is a string that identifies a protection space. Servers use it to group resources that share the same credentials.

### The Working Configuration: `realm = None`

**CRITICAL:** The code MUST use `realm = None` for the password manager, not `realm = ""` or a specific realm string.

```python
self.realm = None
self.passman.add_password(self.realm, self.url, self.user, self.password)
```

### Why `None` Works

When `realm = None` is used:
- HTTPPasswordMgr treats it as a wildcard that matches ANY realm the server provides
- The password manager will provide credentials for authentication challenges regardless of the server's realm value
- This is essential because the VSN300 device uses realm="registered_user@power-one.com" which we discovered from browser inspection

### What Doesn't Work

**Using specific realm string (BROKEN):**
```python
self.realm = "registered_user@power-one.com"  # DON'T DO THIS
```
This breaks because the password manager becomes too restrictive.

**Using empty string (BROKEN):**
```python
self.realm = ""  # DON'T DO THIS
```
This also fails - empty string is NOT the same as None.

### Historical Context

During debugging, we tried different realm values after discovering the actual realm from browser dev tools. However, changing from `None` to a specific realm broke authentication. The original working code used `None`, and we reverted to it using:
```bash
git checkout 6f4c5633dc3b11aed22be0cf24b501a8154807c8 -- vsnx00-monitor.py
```

**Decision:** Keep `realm = None` - don't break what works.

---

## Admin Account Authentication Issue

### Problem Discovery

User feedback: "for guest and empty password it works as in release v1.0.0 without changes. for admin I have to pass only handler_vsn300 to build_opener, just changing order to put vsn300 before vsn700 does not work"

### Root Cause

When both handlers are registered with `build_opener(self.handler_vsn700, self.handler_vsn300)`:
- The VSN700 preemptive Basic auth handler sends credentials with every request
- This interferes with the VSN300 Digest auth challenge-response flow
- Admin account requires proper Digest authentication, which gets disrupted

### User's Workaround

```python
# Workaround that works for admin:
self.opener = build_opener(self.handler_vsn300)  # Only VSN300 handler
```

This works but is not a proper solution since it breaks VSN700 support.

---

## Device Type Detection Design

### Objective
Automatically detect whether the device is VSN300 or VSN700 at initialization, then instantiate only the correct authentication handler.

### Design Principles (User-Specified)

1. **At init, first determine the device model and auth type** by analyzing the authentication challenge response
2. **Once we know the model/auth type, prepare only the correct handler** - we don't need both
3. **Once we have the handler, the rest of the code doesn't need any checks** - it just works

### Implementation (COMPLETED)

**New Method: `_detect_device_type()`**

Located at: [vsnx00-monitor.py:89-159](vsnx00-monitor.py#L89-L159)

The method performs the following steps:
1. Probes `/v1/status` endpoint without authentication
2. Catches the expected 401 response
3. Examines the `WWW-Authenticate` header from the error
4. Determines device type based on authentication scheme:
   - `X-Digest` or `Digest` → Returns `'VSN300'`
   - `Basic` → Returns `'VSN700'`
5. Retries up to 3 times on network errors with 2-second delays
6. Raises exception if detection fails after all retries

**Modified `__init__()` Logic:**

Located at: [vsnx00-monitor.py:161-191](vsnx00-monitor.py#L161-L191)

1. Calls `_detect_device_type()` first (line 177)
2. Sets up password manager with credentials (lines 180-181)
3. Based on detected device type, instantiates ONLY the correct handler (lines 183-188):
   - VSN300: Creates only `VSN300HTTPDigestAuthHandler`
   - VSN700: Creates only `VSN700HTTPPreemptiveBasicAuthHandler`
4. Builds opener with single handler (line 190)
5. Installs opener globally (line 191)
6. Rest of class methods remain unchanged

**Code Example:**
```python
# Detect device type first
device_type = self._detect_device_type()

# Setup authentication based on detected device type
self.passman = HTTPPasswordMgrWithPriorAuth()
self.passman.add_password(self.realm, self.url, self.user, self.password)

if device_type == "VSN300":
    self.logger.info("Initializing VSN300 X-Digest authentication handler")
    handler = VSN300HTTPDigestAuthHandler(self.passman)
else:  # VSN700
    self.logger.info("Initializing VSN700 Basic authentication handler")
    handler = VSN700HTTPPreemptiveBasicAuthHandler(self.passman)

self.opener = build_opener(handler)
install_opener(self.opener)
```

### Key Design Decisions

**Q: Should we use `realm = ""` or `realm = None`?**
**A:** Keep `realm = None` - don't break what works.

**Q: Should we cache the detected device type?**
**A:** No caching. Detection happens once per vsnx00Reader instance initialization.

**Q: Should we retry the probe request if it fails?**
**A:** Yes, retry up to 3 times with 2-second delays to handle transient network issues.

**Q: Should we remove the handler classes?**
**A:** No, keep both handler classes. We just instantiate only the one we need based on autodetection.

### Error Handling Philosophy

**Two types of failures to distinguish:**

1. **Wrong Authentication TYPE** (VSN300 vs VSN700)
   - Detected at initialization via `_detect_device_type()`
   - Automatic - no user configuration needed
   - Fail fast with clear exception if detection fails

2. **Wrong Credentials** (username/password)
   - Detected during actual API requests
   - User configuration error in vsnx00-monitor.cfg
   - Return None from data fetching methods, log warning

### Benefits of This Approach

1. **Fixes Admin Authentication Issue:** By instantiating only one handler, VSN700's preemptive Basic auth no longer interferes with VSN300's Digest auth
2. **Automatic Configuration:** Users don't need to specify device type in config file
3. **Clean Architecture:** Detection happens once at initialization, rest of code is unchanged
4. **Robust Error Handling:** Retries handle transient network issues, clear exceptions for persistent failures
5. **Debugging Support:** Comprehensive logging shows detection process with `--debug` flag

---

## Configuration File Format

**File:** vsnx00-monitor.cfg

```ini
[VSNX00]
# url: full URL of the VSN datalogger (including HTTP/HTTPS prefix)
# username: guest or admin
# password: if user is admin, set the password

url = http://abb-vsn300.axel.dom
username = guest
password =
```

### Important Notes

- **URL must include protocol:** `http://` or `https://`
- **Username is case-sensitive:** Use `guest` (lowercase), not "User" or "Guest"
- **Empty password:** Leave blank for guest account, no placeholder text
- **Admin password:** Device-specific, configured on the VSN device itself

### Discovery of Correct Credentials

Through browser dev tools inspection of the VSN300 web interface:
- Web UI shows two account types: "User" and "Admin"
- When "User" is selected, password field disappears
- After successful login, cookie revealed: `auth.user={"id":"guest",...}`
- Therefore: username = `guest`, password = empty

---

## Git Workflow and Versioning

### Repository Structure

```
vsnx00-monitor/
├── vsnx00-monitor.py       # Main script
├── vsnx00-monitor.cfg      # Configuration file (user-editable)
├── .gitignore              # Excludes .claude/ and vsnx00_data.json
├── claude.md               # This documentation file
└── vsnx00_data.json        # Generated output (ignored by git)
```

### Release v1.0.0

**Tag:** v1.0.0

**Commit Message:**
```
Fix authentication and improve error handling for VSN300/VSN700 data capture

- Fixed critical authentication bug where SSL context parameter bypassed auth handlers
- Added null checks to prevent AttributeError when requests fail
- Fixed variable shadowing in VSN300HTTPDigestAuthHandler
- Improved VSN700 basic auth to support empty passwords
- Fixed config file write mode (binary to text)
- Removed unused SSL import
- Updated config to use correct realm for VSN300 device
- Added debug logging for troubleshooting authentication issues

This release restores full functionality for capturing data from ABB VSN300
and VSN700 solar inverter data loggers via their REST API endpoints.
```

**Testing:** Fresh clone of v1.0.0 confirmed working with VSN300 guest account.

### .gitignore Entries

```
.claude/              # Claude Code configuration
vsnx00_data.json      # Generated output file
```

**Why ignored:**
- `.claude/`: IDE-specific configuration, not part of the application
- `vsnx00_data.json`: Generated output file containing live data, should not be in version control

---

## Debugging and Troubleshooting

### Enable Debug Logging

```bash
python vsnx00-monitor.py --debug
```

This enables detailed logging including:
- URL requests being made
- JSON parsing steps
- Authentication flow details

### Common Issues

**1. HTTP 401 Errors**
- Check username is `guest` (lowercase)
- Check password is empty for guest account
- Verify URL is correct and device is reachable
- Run with `--debug` to see authentication details

**2. Connection Timeouts**
- Verify network connectivity to device
- Check firewall rules
- Device may be rebooting (wait and retry)

**3. AttributeError: 'NoneType' object has no attribute 'read'**
- This was fixed in v1.0.0 with null checks
- If you see this, update to latest version

**4. Admin Account Not Working**
- This is the current known issue being addressed
- Temporary workaround: modify code to use only `handler_vsn300`
- Permanent fix: device type detection (in progress)

### Historical Debugging Journey

1. Started with HTTP 401 errors on all requests
2. Investigated realm configuration (red herring)
3. Tried different realm values (broke it further)
4. Reverted to commit 6f4c5633 using git checkout
5. Discovered browser shows username as "guest" via dev tools
6. Still had 401 errors - realm was not the issue
7. **Breakthrough:** Discovered SSL context was bypassing auth handlers
8. Removed context parameter from urlopen()
9. **Success:** Authentication working for guest account
10. User testing revealed admin account issue
11. Designing device type detection to fix admin auth

---

## Python Dependencies

**Python Version:** 3.x

**Standard Library Only** - No external dependencies required:
- `argparse` - Command-line argument parsing
- `base64` - Basic auth encoding
- `configparser` - Configuration file parsing
- `json` - JSON data handling
- `logging` - Debug and error logging
- `os` - File path operations
- `sys` - System exit handling
- `urllib.error` - HTTP error handling
- `urllib.parse` - URL parsing
- `urllib.request` - HTTP requests and authentication

---

## Code Architecture Patterns

### Custom Authentication Handlers

Both custom handlers extend urllib.request base classes:

**VSN300HTTPDigestAuthHandler:**
- Extends: `HTTPDigestAuthHandler`
- Overrides: `retry_http_digest_auth()` and `http_error_auth_reqed()`
- Purpose: Handle non-standard `X-Digest` authentication scheme

**VSN700HTTPPreemptiveBasicAuthHandler:**
- Extends: `HTTPBasicAuthHandler`
- Overrides: `http_request()` and `https_request()`
- Purpose: Send credentials preemptively without waiting for 401 challenge
- Pattern: Based on StackOverflow solution https://stackoverflow.com/a/24048772

### Opener Pattern

Uses urllib's opener/handler pattern:
1. Create password manager with credentials
2. Create authentication handlers with password manager
3. Build custom opener with handlers
4. Install opener globally with `install_opener()`
5. All subsequent `urlopen()` calls use the installed opener

**Critical:** Once opener is installed, `urlopen()` must NOT receive a `context` parameter or it will bypass the opener.

---

## Future Enhancements

### Completed
- ✅ Fix SSL context bypass issue
- ✅ Add proper error handling
- ✅ Support VSN300 X-Digest authentication
- ✅ Support VSN700 Basic authentication
- ✅ Configuration file support
- ✅ Debug logging
- ✅ v1.0.0 release

### In Progress
- ✅ Automatic device type detection (IMPLEMENTED)
- ✅ Fix admin account authentication (IMPLEMENTED)

### Potential Future Work
- Add command-line override for username/password (bypass config file)
- Support for multiple devices in single config file
- Periodic data capture with cron/scheduler
- Database storage instead of JSON file
- Real-time monitoring dashboard
- HTTPS certificate validation options
- Add unit tests
- Add integration tests with mock servers

---

## References and Resources

### ABB VSN Documentation
- Device manuals and API documentation (if available from ABB)
- REST API endpoints: `/v1/status`, `/v1/livedata`, `/v1/feeds`

### Python urllib Documentation
- https://docs.python.org/3/library/urllib.request.html
- HTTPPasswordMgrWithPriorAuth documentation
- Authentication handler documentation

### StackOverflow Solutions
- Preemptive Basic Auth: https://stackoverflow.com/a/24048772

### Project Repository
- GitHub: (repository URL if public)
- Issues: Report bugs and request features
- Releases: v1.0.0 and future versions

---

## Contact and Support

For issues, questions, or contributions, please use the GitHub issue tracker.

**Maintainer:** (Add maintainer information if desired)

---

*Last Updated: 2025-10-22*
*Version: 1.0.0*
