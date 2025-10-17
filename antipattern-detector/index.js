// File: /Users/liborballaty/LocalProjects/GitHubProjectsDocuments/xLLMArionComply/tools/antipattern-detector/index.js
// Description: Main entry point for @arioncomply/antipattern-detector package
// Author: Libor Ballaty <libor@arionetworks.com>
// Created: 2025-10-16

const {
  GUI_ANTIPATTERNS,
  scanDirectoryForAntiPatterns,
  getJavaScriptFiles
} = require('./gui-security-antipatterns');

/**
 * Antipattern Detector - Main API
 *
 * Business Purpose: Provides reusable antipattern detection across multiple repos
 * to catch security and code quality issues early.
 */

/**
 * Scan a directory for antipatterns
 *
 * @param {string} directoryPath - Path to scan
 * @param {object} antipatternRule - Rule to apply (from GUI_ANTIPATTERNS)
 * @returns {Promise<Array>} - Array of violations found
 *
 * @example
 * const violations = await scanDirectory('./src', GUI_ANTIPATTERNS.xss);
 * console.log(`Found ${violations.length} XSS vulnerabilities`);
 */
async function scanDirectory(directoryPath, antipatternRule) {
  return await scanDirectoryForAntiPatterns(directoryPath, antipatternRule);
}

/**
 * Scan a directory for all antipatterns
 *
 * @param {string} directoryPath - Path to scan
 * @returns {Promise<object>} - Object with results for each antipattern category
 *
 * @example
 * const results = await scanAllAntipatterns('./src');
 * console.log(`XSS: ${results.xss.length}, Auth: ${results.authentication.length}`);
 */
async function scanAllAntipatterns(directoryPath) {
  const results = {};

  for (const [key, rule] of Object.entries(GUI_ANTIPATTERNS)) {
    results[key] = await scanDirectoryForAntiPatterns(directoryPath, rule);
  }

  return results;
}

/**
 * Get summary statistics from scan results
 *
 * @param {object} results - Results from scanAllAntipatterns
 * @returns {object} - Summary with counts by severity and category
 */
function getSummary(results) {
  const summary = {
    total: 0,
    bySeverity: {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0
    },
    byCategory: {}
  };

  for (const [category, violations] of Object.entries(results)) {
    summary.byCategory[category] = violations.length;
    summary.total += violations.length;

    violations.forEach(v => {
      if (v.severity) {
        summary.bySeverity[v.severity] = (summary.bySeverity[v.severity] || 0) + 1;
      }
    });
  }

  return summary;
}

/**
 * Check if results contain critical issues
 *
 * @param {object} results - Results from scanAllAntipatterns
 * @returns {boolean} - True if critical issues found
 */
function hasCriticalIssues(results) {
  for (const violations of Object.values(results)) {
    if (violations.some(v => v.severity === 'CRITICAL')) {
      return true;
    }
  }
  return false;
}

// Export main API
module.exports = {
  // Core scanning functions
  scanDirectory,
  scanAllAntipatterns,

  // Analysis functions
  getSummary,
  hasCriticalIssues,

  // Rules and utilities (re-exported from gui-security-antipatterns)
  GUI_ANTIPATTERNS,
  scanDirectoryForAntiPatterns,
  getJavaScriptFiles
};
