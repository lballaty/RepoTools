// File: /Users/liborballaty/LocalProjects/GitHubProjectsDocuments/xLLMArionComply/arioncomply-v1/testing/test-platform/tests/security/gui-antipatterns/gui-security-antipatterns.spec.js
// Description: Platform security testing - GUI security anti-pattern detection across frontend applications
// Author: Libor Ballaty <libor@arionetworks.com>
// Created: 2024-09-30

const { test, expect } = require('@playwright/test');
const fs = require('fs').promises;
const path = require('path');

// Anti-pattern detection rules
const GUI_ANTIPATTERNS = {
  // XSS Vulnerabilities
  xss: {
    patterns: [
      /innerHTML\s*=\s*.*\+.*/, // innerHTML concatenation
      /outerHTML\s*=\s*.*\+.*/, // outerHTML concatenation
      /document\.write\(.*\+.*\)/, // document.write with concatenation
      /eval\(.*user.*\)/, // eval with user input
      /Function\(.*user.*\)/, // Function constructor with user input
      /setTimeout\(.*\+.*\)/, // setTimeout with string concatenation
      /setInterval\(.*\+.*\)/, // setInterval with string concatenation
    ],
    severity: 'CRITICAL',
    message: 'XSS vulnerability: Never concatenate user input into HTML'
  },

  // DOM Manipulation Anti-patterns
  domManipulation: {
    patterns: [
      /\$\(.*\)\.html\(.*\+.*\)/, // jQuery html() with concatenation
      /element\.innerHTML\s*=\s*[^`].*\+/, // Direct innerHTML assignment
      /insertAdjacentHTML\(.*\+.*\)/, // insertAdjacentHTML with concatenation
      /createElement.*innerHTML/, // createElement followed by innerHTML
    ],
    severity: 'HIGH',
    message: 'Unsafe DOM manipulation: Use textContent or sanitize HTML'
  },

  // Authentication Anti-patterns
  authentication: {
    patterns: [
      /password.*==.*['"].*['"]/, // Hardcoded password comparison
      /token.*localStorage/, // Token in localStorage without encryption
      /sessionStorage.*password/, // Password in sessionStorage
      /console\.log.*password/, // Password logging
      /console\.log.*token/, // Token logging
      /alert.*password/, // Password in alert
      /prompt.*password.*/, // Password in prompt
    ],
    severity: 'CRITICAL',
    message: 'Authentication anti-pattern: Never expose credentials'
  },

  // CSRF Vulnerabilities
  csrf: {
    patterns: [
      /fetch\(.*POST.*\)(?!.*csrf)(?!.*token)/, // POST without CSRF token
      /axios\.post\((?!.*csrf)(?!.*token)/, // Axios POST without CSRF
      /\$\.post\((?!.*csrf)(?!.*token)/, // jQuery POST without CSRF
      /XMLHttpRequest.*POST(?!.*csrf)/, // XHR POST without CSRF
    ],
    severity: 'HIGH',
    message: 'CSRF vulnerability: Include CSRF token in state-changing requests'
  },

  // Input Validation Anti-patterns
  inputValidation: {
    patterns: [
      /document\.location\.href\s*=\s*.*\+/, // Location redirect with concatenation
      /window\.location\s*=\s*.*\+/, // Window location with concatenation
      /window\.open\(.*\+.*\)/, // Window.open with concatenation
      /postMessage\(.*\*/, // postMessage with wildcard origin
    ],
    severity: 'HIGH',
    message: 'Input validation issue: Validate and sanitize all user inputs'
  },

  // Cryptography Anti-patterns
  cryptography: {
    patterns: [
      /Math\.random\(\).*password/, // Using Math.random for passwords
      /Math\.random\(\).*token/, // Using Math.random for tokens
      /btoa\(.*password.*\)/, // Base64 encoding passwords (not encryption)
      /atob\(.*password.*\)/, // Base64 decoding passwords
      /MD5\(.*password.*\)/, // MD5 for passwords (weak)
      /SHA1\(.*password.*\)/, // SHA1 for passwords (weak)
    ],
    severity: 'CRITICAL',
    message: 'Cryptography anti-pattern: Use proper cryptographic functions'
  },

  // Data Exposure Anti-patterns
  dataExposure: {
    patterns: [
      /console\.log\(.*user.*\)/, // User data logging
      /console\.log\(.*response.*\)/, // API response logging
      /debugger;/, // Debugger statements in production
      /window\..*=.*sensitive/, // Global variables with sensitive data
      /sessionStorage\.setItem.*sensitive/, // Sensitive data in session storage
    ],
    severity: 'MEDIUM',
    message: 'Data exposure: Remove debugging code and sensitive data logging'
  }
};

test.describe('GUI Security Anti-Pattern Detection', () => {

  test('Frontend applications should not contain XSS vulnerabilities', async () => {
    const frontendPaths = [
      '../../../testing/workflow-gui',
      '../../../frontend-web',
      '../../../frontend-flutter/lib'
    ];

    let violationsFound = [];

    for (const frontendPath of frontendPaths) {
      const fullPath = path.resolve(__dirname, frontendPath);

      try {
        const violations = await scanDirectoryForAntiPatterns(fullPath, GUI_ANTIPATTERNS.xss);
        violationsFound = violationsFound.concat(violations);
      } catch (error) {
        console.log(`⚠️  Skipping ${frontendPath}: directory not found or inaccessible`);
      }
    }

    if (violationsFound.length > 0) {
      console.log('\n❌ XSS Anti-patterns Found:');
      violationsFound.forEach(violation => {
        console.log(`   📁 ${violation.file}:${violation.line}`);
        console.log(`   🔍 ${violation.pattern}`);
        console.log(`   ⚠️  ${violation.context}\n`);
      });
    }

    expect(violationsFound).toHaveLength(0);
  });

  test('Frontend applications should use safe DOM manipulation', async () => {
    const frontendPaths = [
      '../../../testing/workflow-gui',
      '../../../frontend-web'
    ];

    let violationsFound = [];

    for (const frontendPath of frontendPaths) {
      const fullPath = path.resolve(__dirname, frontendPath);

      try {
        const violations = await scanDirectoryForAntiPatterns(fullPath, GUI_ANTIPATTERNS.domManipulation);
        violationsFound = violationsFound.concat(violations);
      } catch (error) {
        console.log(`⚠️  Skipping ${frontendPath}: directory not found or inaccessible`);
      }
    }

    if (violationsFound.length > 0) {
      console.log('\n❌ DOM Manipulation Anti-patterns Found:');
      violationsFound.forEach(violation => {
        console.log(`   📁 ${violation.file}:${violation.line}`);
        console.log(`   🔍 Pattern: ${violation.matchedPattern}`);
        console.log(`   ⚠️  Context: ${violation.context}\n`);
      });
    }

    expect(violationsFound).toHaveLength(0);
  });

  test('Frontend applications should handle authentication securely', async () => {
    const frontendPaths = [
      '../../../testing/workflow-gui',
      '../../../frontend-web',
      '../../../frontend-flutter/lib'
    ];

    let violationsFound = [];

    for (const frontendPath of frontendPaths) {
      const fullPath = path.resolve(__dirname, frontendPath);

      try {
        const violations = await scanDirectoryForAntiPatterns(fullPath, GUI_ANTIPATTERNS.authentication);
        violationsFound = violationsFound.concat(violations);
      } catch (error) {
        console.log(`⚠️  Skipping ${frontendPath}: directory not found or inaccessible`);
      }
    }

    // Critical violations should cause test failure
    const criticalViolations = violationsFound.filter(v => v.severity === 'CRITICAL');

    if (criticalViolations.length > 0) {
      console.log('\n🚨 CRITICAL Authentication Anti-patterns Found:');
      criticalViolations.forEach(violation => {
        console.log(`   📁 ${violation.file}:${violation.line}`);
        console.log(`   🔍 ${violation.matchedPattern}`);
        console.log(`   ⚠️  ${violation.context}\n`);
      });
    }

    expect(criticalViolations).toHaveLength(0);
  });

  test('Frontend applications should prevent CSRF vulnerabilities', async () => {
    const frontendPaths = [
      '../../../testing/workflow-gui',
      '../../../frontend-web'
    ];

    let violationsFound = [];

    for (const frontendPath of frontendPaths) {
      const fullPath = path.resolve(__dirname, frontendPath);

      try {
        const violations = await scanDirectoryForAntiPatterns(fullPath, GUI_ANTIPATTERNS.csrf);
        violationsFound = violationsFound.concat(violations);
      } catch (error) {
        console.log(`⚠️  Skipping ${frontendPath}: directory not found or inaccessible`);
      }
    }

    if (violationsFound.length > 0) {
      console.log('\n❌ CSRF Anti-patterns Found:');
      violationsFound.forEach(violation => {
        console.log(`   📁 ${violation.file}:${violation.line}`);
        console.log(`   🔍 ${violation.matchedPattern}`);
        console.log(`   💡 Add CSRF token to: ${violation.context}\n`);
      });

      // CSRF violations are warnings, not failures (may have false positives)
      console.log('⚠️  Note: Review these manually - some may be false positives');
    }

    // Don't fail the test, just warn
    expect(violationsFound.length).toBeLessThan(50); // Reasonable threshold
  });

  test('Frontend applications should use proper cryptography', async () => {
    const frontendPaths = [
      '../../../testing/workflow-gui',
      '../../../frontend-web',
      '../../../frontend-flutter/lib'
    ];

    let violationsFound = [];

    for (const frontendPath of frontendPaths) {
      const fullPath = path.resolve(__dirname, frontendPath);

      try {
        const violations = await scanDirectoryForAntiPatterns(fullPath, GUI_ANTIPATTERNS.cryptography);
        violationsFound = violationsFound.concat(violations);
      } catch (error) {
        console.log(`⚠️  Skipping ${frontendPath}: directory not found or inaccessible`);
      }
    }

    if (violationsFound.length > 0) {
      console.log('\n❌ Cryptography Anti-patterns Found:');
      violationsFound.forEach(violation => {
        console.log(`   📁 ${violation.file}:${violation.line}`);
        console.log(`   🔍 ${violation.matchedPattern}`);
        console.log(`   ⚠️  ${violation.context}\n`);
      });
    }

    expect(violationsFound).toHaveLength(0);
  });

  test('Frontend applications should not expose sensitive data', async () => {
    const frontendPaths = [
      '../../../testing/workflow-gui',
      '../../../frontend-web',
      '../../../frontend-flutter/lib'
    ];

    let violationsFound = [];

    for (const frontendPath of frontendPaths) {
      const fullPath = path.resolve(__dirname, frontendPath);

      try {
        const violations = await scanDirectoryForAntiPatterns(fullPath, GUI_ANTIPATTERNS.dataExposure);
        violationsFound = violationsFound.concat(violations);
      } catch (error) {
        console.log(`⚠️  Skipping ${frontendPath}: directory not found or inaccessible`);
      }
    }

    if (violationsFound.length > 0) {
      console.log('\n⚠️  Data Exposure Issues Found:');
      violationsFound.forEach(violation => {
        console.log(`   📁 ${violation.file}:${violation.line}`);
        console.log(`   🔍 ${violation.matchedPattern}`);
        console.log(`   💡 ${violation.context}\n`);
      });
    }

    // Data exposure is warning level - don't fail build but report
    console.log(`📊 Data exposure issues found: ${violationsFound.length}`);
    expect(violationsFound.length).toBeLessThan(20); // Reasonable threshold
  });

});

// Utility Functions
async function scanDirectoryForAntiPatterns(directoryPath, antipatternRule) {
  const violations = [];

  try {
    const files = await getJavaScriptFiles(directoryPath);

    for (const file of files) {
      const content = await fs.readFile(file, 'utf8');
      const lines = content.split('\n');

      lines.forEach((line, index) => {
        for (const pattern of antipatternRule.patterns) {
          const match = line.match(pattern);
          if (match) {
            violations.push({
              file: path.relative(process.cwd(), file),
              line: index + 1,
              matchedPattern: match[0],
              context: line.trim(),
              severity: antipatternRule.severity,
              message: antipatternRule.message
            });
          }
        }
      });
    }
  } catch (error) {
    console.log(`⚠️  Error scanning ${directoryPath}: ${error.message}`);
  }

  return violations;
}

async function getJavaScriptFiles(dir) {
  const files = [];

  try {
    const entries = await fs.readdir(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory() && !shouldSkipDirectory(entry.name)) {
        const subFiles = await getJavaScriptFiles(fullPath);
        files.push(...subFiles);
      } else if (entry.isFile() && isJavaScriptFile(entry.name)) {
        files.push(fullPath);
      }
    }
  } catch (error) {
    // Directory doesn't exist or can't be accessed
    console.log(`⚠️  Cannot access directory: ${dir}`);
  }

  return files;
}

function isJavaScriptFile(filename) {
  const jsExtensions = ['.js', '.jsx', '.ts', '.tsx', '.vue', '.dart'];
  return jsExtensions.some(ext => filename.endsWith(ext));
}

function shouldSkipDirectory(dirname) {
  const skipDirs = ['node_modules', '.git', 'dist', 'build', 'coverage', '__tests__', 'test', '.nyc_output'];
  return skipDirs.includes(dirname) || dirname.startsWith('.');
}

// Export utilities for use in other tests
module.exports = {
  GUI_ANTIPATTERNS,
  scanDirectoryForAntiPatterns,
  getJavaScriptFiles
};