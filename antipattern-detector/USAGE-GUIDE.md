# Antipattern Detector - Usage Guide
**File:** /Users/liborballaty/LocalProjects/GitHubProjectsDocuments/xLLMArionComply/tools/antipattern-detector/USAGE-GUIDE.md
**Description:** Step-by-step guide to use antipattern detection across all your repositories
**Author:** Libor Ballaty <libor@arionetworks.com>
**Created:** 2025-10-16

---

## Quick Start: Use in Any Repo (3 Steps)

### Step 1: Copy the detector to your repo

```bash
# From your other repo
cd /path/to/your-other-repo

# Create tools directory
mkdir -p tools

# Copy the antipattern detector
cp -r /Users/liborballaty/LocalProjects/GitHubProjectsDocuments/xLLMArionComply/tools/antipattern-detector tools/

# Or use symlink (if repos are on same machine)
ln -s /Users/liborballaty/LocalProjects/GitHubProjectsDocuments/xLLMArionComply/tools/antipattern-detector tools/antipattern-detector
```

### Step 2: Create a test file

Create `tests/antipattern-check.spec.js`:

```javascript
const { test, expect } = require('@playwright/test');
const { scanAllAntipatterns, getSummary, hasCriticalIssues } = require('../tools/antipattern-detector');

test('should not contain critical antipatterns', async () => {
  // Scan your source directory
  const results = await scanAllAntipatterns('./src');

  // Get summary
  const summary = getSummary(results);
  console.log('Antipattern Summary:', summary);

  // Fail if critical issues found
  expect(hasCriticalIssues(results)).toBe(false);

  // Optional: Fail if too many issues
  expect(summary.total).toBeLessThan(10);
});
```

### Step 3: Run the test

```bash
npx playwright test tests/antipattern-check.spec.js
```

Done! You now have antipattern detection in your repo.

---

## Advanced Usage

### Option A: NPM Package (Best for Multiple Repos)

If you manage multiple repos, publish as an NPM package:

```bash
# In ArionComply repo
cd tools/antipattern-detector

# Publish to GitHub packages (private)
npm login --registry=https://npm.pkg.github.com
npm publish --access=restricted

# Or publish to npm (public)
npm login
npm publish --access=public
```

Then in other repos:

```bash
npm install --save-dev @arioncomply/antipattern-detector

# Use in tests
const { scanAllAntipatterns } = require('@arioncomply/antipattern-detector');
```

### Option B: Git Submodule (Shared Codebase)

Use git submodules to share the detector:

```bash
# In ArionComply repo, create a tools-only repo
cd /Users/liborballaty/LocalProjects/GitHubProjectsDocuments
git init arioncomply-tools
cd arioncomply-tools
cp -r xLLMArionComply/tools/antipattern-detector .
git add .
git commit -m "Initial antipattern detector"
git remote add origin https://github.com/arionnetworks/arioncomply-tools
git push -u origin main

# In other repos
cd /path/to/your-other-repo
git submodule add https://github.com/arionnetworks/arioncomply-tools tools/arioncomply
```

### Option C: Pre-commit Hook (Automatic Checking)

Add to `.pre-commit-config.yaml` in any repo:

```yaml
repos:
  - repo: local
    hooks:
      - id: antipattern-check
        name: Antipattern Detection
        entry: tools/antipattern-detector/run-antipattern-check.sh
        language: script
        pass_filenames: true
        types: [javascript, typescript, python]
```

Create the hook script [tools/antipattern-detector/run-antipattern-check.sh](file:///Users/liborballaty/LocalProjects/GitHubProjectsDocuments/xLLMArionComply/tools/antipattern-detector/run-antipattern-check.sh):

```bash
#!/bin/bash
# Run antipattern detection on changed files

echo "🔍 Checking for antipatterns..."

# Run JavaScript antipattern detection
for file in "$@"; do
  if [[ "$file" =~ \.(js|jsx|ts|tsx)$ ]]; then
    echo "Checking $file..."
    node tools/antipattern-detector/cli.js "$file"
  fi
done

# Run Python antipattern detection
python3 tools/antipattern-detector/validate-code-antipatterns.py --patterns "$@"
```

---

## Real-World Examples

### Example 1: React Project

```javascript
// tests/security-check.spec.js
const { test, expect } = require('@playwright/test');
const { GUI_ANTIPATTERNS, scanDirectory } = require('../tools/antipattern-detector');

test('React components should not have XSS vulnerabilities', async () => {
  const violations = await scanDirectory('./src/components', GUI_ANTIPATTERNS.xss);

  if (violations.length > 0) {
    console.log('❌ XSS vulnerabilities found:');
    violations.forEach(v => {
      console.log(`   ${v.file}:${v.line} - ${v.context}`);
    });
  }

  expect(violations).toHaveLength(0);
});
```

### Example 2: Python API Project

```bash
# Run Python antipattern detection
python3 tools/antipattern-detector/validate-code-antipatterns.py \
  --patterns "**/*.py" \
  --json-output > antipatterns.json

# Check if there are critical issues
if grep -q '"critical_issues": [^0]' antipatterns.json; then
  echo "❌ Critical antipatterns found!"
  exit 1
fi
```

### Example 3: CI/CD Pipeline

```yaml
# .github/workflows/antipattern-check.yml
name: Antipattern Detection

on: [push, pull_request]

jobs:
  antipattern-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install dependencies
        run: npm install

      - name: Run antipattern detection
        run: npm run test:antipatterns

      - name: Upload results
        if: failure()
        uses: actions/upload-artifact@v3
        with:
          name: antipattern-results
          path: test-results/antipatterns/
```

---

## Configuration

### Customize Detection Rules

Create `antipattern-config.js` in your repo:

```javascript
const { GUI_ANTIPATTERNS } = require('./tools/antipattern-detector');

// Extend with custom rules
const CUSTOM_RULES = {
  // Add your own patterns
  customRule: {
    patterns: [
      /TODO.*FIXME/,  // TODOs with FIXME are critical
      /HACK.*URGENT/   // Urgent hacks
    ],
    severity: 'HIGH',
    message: 'Critical technical debt marker found'
  }
};

module.exports = {
  ...GUI_ANTIPATTERNS,
  ...CUSTOM_RULES
};
```

Use in tests:

```javascript
const RULES = require('./antipattern-config');
const violations = await scanDirectory('./src', RULES.customRule);
```

### Ignore Certain Directories

```javascript
const { getJavaScriptFiles } = require('./tools/antipattern-detector');

// Filter out test files, node_modules, etc.
const files = await getJavaScriptFiles('./src');
const productionFiles = files.filter(f =>
  !f.includes('test') &&
  !f.includes('node_modules')
);
```

---

## Troubleshooting

### "Module not found" error

Make sure you copied the entire `tools/antipattern-detector` directory, not just individual files.

```bash
# Check if all files exist
ls -la tools/antipattern-detector/
# Should show: index.js, gui-security-antipatterns.js, validate-code-antipatterns.py
```

### Python script not found

Make sure Python script is executable:

```bash
chmod +x tools/antipattern-detector/validate-code-antipatterns.py
```

### Playwright not installed

Install Playwright if not already:

```bash
npm install --save-dev @playwright/test
npx playwright install
```

---

## Summary: 3 Ways to Use Across Repos

| Method | Best For | Setup Complexity | Maintenance |
|--------|----------|------------------|-------------|
| **Direct Copy** | 1-2 repos, quick start | ⭐ Easy | Manual sync |
| **NPM Package** | 5+ repos, centralized | ⭐⭐⭐ Medium | `npm update` |
| **Git Submodule** | Shared codebase | ⭐⭐ Medium | `git submodule update` |

**Recommendation:**
- **1-3 repos**: Direct copy + symlink
- **5+ repos**: Publish as NPM package
- **Related projects**: Git submodule

---

## Next Steps

1. ✅ Choose integration method (copy, NPM, or submodule)
2. ✅ Add antipattern test to one repo as proof-of-concept
3. ✅ Run test and fix any critical issues
4. ✅ Add to pre-commit hooks
5. ✅ Roll out to other repos

Questions: libor@arionetworks.com
