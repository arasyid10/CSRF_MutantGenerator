# 🛡️ Cross Site Request Forgery Vulnerability Simulation

This dummy PHP project is designed to **simulate and test real-world file access vulnerabilities**, specifically:

- 🔓 **CSRF (CWE-352)**
- ✅ PHPUnit tests all pass (expected behavior)
- 🧪 Infection detects **surviving mutants** due to intentionally weak validation logic

The project is useful for:

- Security researchers
- QA testers
- Students studying web security
- Test case mutation testers

---

## 🧱 Project Structure
```
traversal-vulnerabilities/
├── src/
│ ├── VulnFileRead.php # Path traversal simulation
│ └── UserProfileRead.php # Auth bypass simulation
├── tests/ # PHPUnit test cases (CWE-specific)
│ └── CweXX<...>Test.php # Individual CWE test cases
├── vulnerable_files/ # Target files for test access
│ ├── etc/ # Simulated /etc/passwd
│ ├── secret_dir/ # Simulated sensitive content
│ ├── safe_dir/ # Legitimate user-accessible files
│ └── users/ # Simulated user profile directories
├── patterns.json # Attack patterns used in tests
├── phpunit.xml.dist # PHPUnit configuration
├── infection.json.dist # Infection mutation config
└── composer.json # Autoload & dependencies
```


---

## 🔍 Vulnerability Simulation Explanation

### `src/VulnFileRead.php`

- Core vulnerable logic using `realpath()` and `str_starts_with()`
- Doesn't sanitize or normalize input paths
- Allows traversal via obfuscation or encoding
- ❗Allows Infection to mutate path checks without failing tests

### `src/UserProfileRead.php`

- Simulates user profile file access by `user_id`
- No ownership validation — predictable ID = access to any user
- Covers **CWE-639** (Authorization Bypass)

---

## 🧪 Test Cases Breakdown (by CWE)


## ✅ How to Run

### 1. Install Dependencies

```bash
composer install
```

### 2. Run PHPUnit

```bash
vendor/bin/phpunit
```

### 3. Run Infection (Mutation Testing)

```bash
vendor/bin/infection
```

⚠️ Infection will detect surviving mutants due to poor validation logic, simulating real-world exploitation potential.


### ⚙️ Requirements
- PHP >= 8.0
- Composer
- PHPUnit (via composer)
- Infection mutation testing (via composer)
