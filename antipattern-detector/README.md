# Antipattern Detector - Reusable Testing Tool
**File:** /Users/liborballaty/LocalProjects/GitHubProjectsDocuments/xLLMArionComply/tools/antipattern-detector/README.md
**Description:** Reusable antipattern detection that can be used across multiple repositories
**Author:** Libor Ballaty <libor@arionetworks.com>
**Created:** 2025-10-16

## Purpose

Detect security, performance, and code quality antipatterns across JavaScript, TypeScript, Python, and other codebases. Catches problems EARLY before they become major refactoring tasks.

## Features

- **JavaScript/TypeScript Security**: XSS, CSRF, auth issues, unsafe DOM manipulation
- **Python Code Quality**: God functions, god classes, deep nesting, long parameter lists
- **Universal Patterns**: Hardcoded config, magic numbers, duplicate code, missing error handling
- **Pre-commit Integration**: Automatically run checks before commits
- **CI/CD Ready**: JSON output for automated pipelines

## Installation

### Option 1: NPM Package (JavaScript/TypeScript repos)

```bash
npm install --save-dev @arioncomply/antipattern-detector
```

Then in your test files:
```javascript
const { GUI_ANTIPATTERNS, scanDirectoryForAntiPatterns } = require('@arioncomply/antipattern-detector');

// Scan your code
const violations = await scanDirectoryForAntiPatterns('./src', GUI_ANTIPATTERNS.xss);
```

### Option 2: Git Submodule (Any repo type)

```bash
# Add to your repo
git submodule add https://github.com/arionnetworks/arioncomply-tools tools/arioncomply

# Update in the future
git submodule update --remote
```

### Option 3: Direct Copy (Quick start)

Copy these files to your repo:
```bash
# JavaScript antipattern detection
tools/antipattern-detector/gui-security-antipatterns.js

# Python antipattern detection
tools/antipattern-detector/validate-code-antipatterns.py

# Pre-commit hook
.pre-commit-hooks/antipattern-check.sh
```

## Usage

### In Playwright Tests

```javascript
const { test, expect } = require('@playwright/test');
const { GUI_ANTIPATTERNS, scanDirectoryForAntiPatterns } = require('./tools/antipattern-detector/gui-security-antipatterns');

test('should not contain XSS vulnerabilities', async () => {
  const violations = await scanDirectoryForAntiPatterns('./src', GUI_ANTIPATTERNS.xss);
  expect(violations).toHaveLength(0);
});
```

### Python Code Analysis

```bash
python3 tools/antipattern-detector/validate-code-antipatterns.py \
  --patterns "**/*.py" \
  --json-output > antipatterns.json
```

### Pre-commit Hook

Add to `.pre-commit-config.yaml`:
```yaml
repos:
  - repo: local
    hooks:
      - id: antipattern-check
        name: Antipattern Detection
        entry: tools/antipattern-detector/run-antipattern-check.sh
        language: script
        pass_filenames: true
        types: [python, javascript, typescript]
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Run Antipattern Detection
  run: |
    npm run test:antipatterns
    python3 tools/antipattern-detector/validate-code-antipatterns.py --json-output > results.json

- name: Upload Results
  uses: actions/upload-artifact@v3
  with:
    name: antipattern-results
    path: results.json
```

## Antipattern Rules

### JavaScript/TypeScript Security (GUI_ANTIPATTERNS)

| Category | Severity | Examples |
|----------|----------|----------|
| XSS | CRITICAL | `innerHTML = user + input`, `eval(userInput)` |
| DOM Manipulation | HIGH | Unsafe `insertAdjacentHTML`, direct `innerHTML` |
| Authentication | CRITICAL | Hardcoded passwords, tokens in localStorage |
| CSRF | HIGH | POST requests without CSRF tokens |
| Cryptography | CRITICAL | `Math.random()` for tokens, MD5/SHA1 for passwords |
| Data Exposure | MEDIUM | `console.log(user)`, debugger statements |

### Python Code Quality

| Antipattern | Threshold | Why It Matters |
|-------------|-----------|----------------|
| God Functions | >200 lines | Prevents 578-line nightmares |
| God Classes | >500 lines or >15 methods | Single Responsibility Principle |
| Deep Nesting | >4 levels | Code readability |
| Long Parameter Lists | >5 params | Interface complexity |
| Hardcoded Config | URLs, passwords, API keys | Security and maintainability |
| Magic Numbers | Numbers used >3 times | Should be named constants |

## Customization

### Adding Your Own Rules

```javascript
// In your project's test file
const CUSTOM_ANTIPATTERNS = {
  myRule: {
    patterns: [
      /somePattern/,
      /anotherPattern/
    ],
    severity: 'HIGH',
    message: 'Description of the issue'
  }
};

const violations = await scanDirectoryForAntiPatterns('./src', CUSTOM_ANTIPATTERNS.myRule);
```

### Adjusting Thresholds

```python
# For Python detection
detector = AntiPatternDetector()
detector.thresholds['god_function_lines'] = 150  # Stricter than default 200
detector.thresholds['deep_nesting_level'] = 3    # Stricter than default 4
```

## Real-World Example

**Before using antipattern detection:**
- 578-line function caused 3-day refactoring nightmare
- XSS vulnerability found in production
- Hardcoded API keys in code

**After using antipattern detection:**
- Caught 200+ line function before it became 578 lines
- XSS patterns blocked in pre-commit hook
- Hardcoded secrets detected before commit

## Integration with ArionComply Tools

This detector is part of the ArionComply development toolchain:

1. **Development**: Catches issues while coding
2. **Pre-commit**: Blocks bad code from entering repo
3. **CI/CD**: Automated quality gates
4. **Production**: Monitors deployed code quality

## Files in This Package

```
tools/antipattern-detector/
├── README.md                              # This file
├── package.json                           # NPM package definition
├── gui-security-antipatterns.js          # JavaScript/TypeScript rules
├── validate-code-antipatterns.py         # Python antipattern detection
├── run-antipattern-check.sh              # Pre-commit hook script
└── examples/
    ├── playwright-example.spec.js        # Example Playwright test
    ├── pre-commit-example.yaml           # Example pre-commit config
    └── github-actions-example.yml        # Example CI/CD workflow
```

## Contributing

Found a new antipattern? Add it to the detection rules:

1. Add pattern to appropriate rule set (JavaScript or Python)
2. Add test case demonstrating the antipattern
3. Document why it's problematic
4. Submit PR with examples

## Support

Questions: libor@arionetworks.com

## License

Proprietary - ArionNetworks © 2025
