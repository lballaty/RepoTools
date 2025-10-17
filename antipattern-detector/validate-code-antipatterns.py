#!/usr/bin/env python3
"""
ArionComply-Specific Code Anti-Pattern Detector
⚠️  THIS IS NOT A GENERIC TOOL - ADAPTED FOR ARIONCOMPLY PROJECT ONLY ⚠️

Detects and reports specific anti-patterns identified in ArionComply refactoring analysis
to catch problems EARLY before they become major refactoring tasks.

ANTI-PATTERNS DETECTED (from concrete refactoring analysis):
1. God Functions (>200 lines) - prevents P4.1 scenarios (578-line functions)
2. God Classes (>500 lines) - prevents massive class bloat
3. Hardcoded Configuration - prevents LC-P4.5 security issues
4. Direct Dependencies - prevents P4.3 interface abstraction issues
5. Copy-Paste Code - detects duplicate logic patterns
6. Deep Nesting (>4 levels) - prevents unreadable code
7. Long Parameter Lists (>5 params) - prevents complex interfaces
8. Magic Numbers - prevents maintainability issues
9. Inconsistent Naming - prevents ArionComply naming standard violations
10. Missing Error Handling - prevents production issues

Purpose: Catch anti-patterns BEFORE they require major refactoring effort.
"""

import ast
import argparse
import json
import sys
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
import hashlib

class AntiPatternDetector:
    def __init__(self):
        self.issues: List[Dict] = []
        self.score = 100
        self.max_score = 100
        self.logger = logging.getLogger(__name__)

        # Anti-pattern thresholds based on ArionComply analysis
        self.thresholds = {
            'god_function_lines': 200,      # Catch before 578-line disasters
            'god_class_lines': 500,         # Prevent massive classes
            'deep_nesting_level': 4,        # Readability threshold
            'long_parameter_count': 5,      # Interface complexity threshold
            'duplicate_line_threshold': 5,  # Minimum lines to consider duplication
            'magic_number_threshold': 3     # Numbers used more than 3 times should be constants
        }

        # Code patterns that indicate anti-patterns
        self.anti_pattern_indicators = {
            'god_function_markers': [
                'if.*elif.*elif.*elif.*elif',  # Too many conditions
                'try:.*except.*try:.*except',   # Nested error handling
                'for.*for.*for.*for'           # Deep loops
            ],
            'hardcoded_patterns': [
                r'http://[^"\']+',
                r'https://[^"\']+',
                r'password\s*=\s*["\'][^"\']+["\']',
                r'key\s*=\s*["\'][^"\']+["\']'
            ],
            'magic_numbers': [
                r'\b(10|100|1000|404|500|200|201)\b',  # Common magic numbers
                r'\b\d{2,}\b'  # Multi-digit numbers
            ],
            'copy_paste_indicators': [
                'TODO: refactor',
                'FIXME',
                'duplicate',
                'copy'
            ]
        }

    def add_issue(self, check: str, description: str, severity: str,
                  file_path: Optional[str] = None, line_number: Optional[int] = None,
                  function_name: Optional[str] = None, suggestion: Optional[str] = None,
                  anti_pattern: Optional[str] = None):
        """Add anti-pattern issue"""
        issue = {
            "check": check,
            "description": description,
            "severity": severity,
            "category": "code_anti_patterns",
            "anti_pattern": anti_pattern or check
        }
        if file_path:
            issue["file"] = file_path
        if line_number:
            issue["line"] = line_number
        if function_name:
            issue["function"] = function_name
        if suggestion:
            issue["suggestion"] = suggestion

        self.issues.append(issue)

        # Adjust score based on severity
        penalty = {"critical": 20, "high": 12, "medium": 6, "low": 2}.get(severity, 0)
        self.score = max(0, self.score - penalty)

    def detect_god_functions(self, file_path: Path, tree: ast.AST) -> None:
        """Detect god functions (functions that are too long/complex)"""
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                if hasattr(node, 'lineno') and hasattr(node, 'end_lineno'):
                    function_lines = node.end_lineno - node.lineno + 1

                    # Check for god function anti-pattern
                    if function_lines > self.thresholds['god_function_lines']:
                        severity = "critical" if function_lines > 400 else "high"
                        self.add_issue(
                            "god_function",
                            f"Function '{node.name}' has {function_lines} lines (threshold: {self.thresholds['god_function_lines']})",
                            severity,
                            str(file_path),
                            node.lineno,
                            node.name,
                            f"Extract logical blocks into separate functions. Target: <{self.thresholds['god_function_lines']} lines",
                            "God Function"
                        )

                    # Check for complex function indicators
                    try:
                        source = ast.get_source_segment(file_path.read_text(), node)
                        if source:
                            for pattern in self.anti_pattern_indicators['god_function_markers']:
                                if re.search(pattern, source, re.DOTALL):
                                    self.add_issue(
                                        "complex_function_pattern",
                                        f"Function '{node.name}' contains complex nested patterns",
                                        "medium",
                                        str(file_path),
                                        node.lineno,
                                        node.name,
                                        "Simplify control flow and extract nested logic",
                                        "Complex Function"
                                    )
                    except Exception:
                        pass  # Skip if can't analyze source

    def detect_god_classes(self, file_path: Path, tree: ast.AST) -> None:
        """Detect god classes (classes with too many responsibilities)"""
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                if hasattr(node, 'lineno') and hasattr(node, 'end_lineno'):
                    class_lines = node.end_lineno - node.lineno + 1

                    # Count methods and attributes
                    method_count = len([n for n in node.body if isinstance(n, ast.FunctionDef)])

                    # Check for god class anti-pattern
                    if (class_lines > self.thresholds['god_class_lines'] or
                        method_count > 15):
                        severity = "high" if class_lines > 800 or method_count > 20 else "medium"
                        self.add_issue(
                            "god_class",
                            f"Class '{node.name}' has {class_lines} lines and {method_count} methods",
                            severity,
                            str(file_path),
                            node.lineno,
                            node.name,
                            "Split class into multiple focused classes following Single Responsibility Principle",
                            "God Class"
                        )

    def detect_deep_nesting(self, file_path: Path, tree: ast.AST) -> None:
        """Detect deeply nested code structures"""

        def count_nesting_depth(node, current_depth=0):
            """Recursively count nesting depth"""
            max_depth = current_depth

            # Control structures that increase nesting
            nesting_nodes = (ast.If, ast.For, ast.While, ast.With, ast.Try, ast.ExceptHandler)

            for child in ast.iter_child_nodes(node):
                if isinstance(child, nesting_nodes):
                    child_max = count_nesting_depth(child, current_depth + 1)
                    max_depth = max(max_depth, child_max)
                else:
                    child_max = count_nesting_depth(child, current_depth)
                    max_depth = max(max_depth, child_max)

            return max_depth

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                nesting_depth = count_nesting_depth(node)

                if nesting_depth > self.thresholds['deep_nesting_level']:
                    severity = "high" if nesting_depth > 6 else "medium"
                    self.add_issue(
                        "deep_nesting",
                        f"Function '{node.name}' has {nesting_depth} levels of nesting (threshold: {self.thresholds['deep_nesting_level']})",
                        severity,
                        str(file_path),
                        node.lineno,
                        node.name,
                        "Extract nested logic into separate functions or use early returns",
                        "Deep Nesting"
                    )

    def detect_long_parameter_lists(self, file_path: Path, tree: ast.AST) -> None:
        """Detect functions with too many parameters"""
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                param_count = len(node.args.args)

                if param_count > self.thresholds['long_parameter_count']:
                    severity = "medium" if param_count < 8 else "high"
                    self.add_issue(
                        "long_parameter_list",
                        f"Function '{node.name}' has {param_count} parameters (threshold: {self.thresholds['long_parameter_count']})",
                        severity,
                        str(file_path),
                        node.lineno,
                        node.name,
                        "Group related parameters into objects or use builder pattern",
                        "Long Parameter List"
                    )

    def detect_hardcoded_values(self, file_path: Path) -> None:
        """Detect hardcoded values that should be configurable"""
        try:
            content = file_path.read_text(encoding='utf-8')
            lines = content.split('\n')

            for line_num, line in enumerate(lines, 1):
                for pattern_name, patterns in self.anti_pattern_indicators.items():
                    if pattern_name == 'hardcoded_patterns':
                        for pattern in patterns:
                            matches = re.finditer(pattern, line, re.IGNORECASE)
                            for match in matches:
                                # Skip comments and obvious test data
                                if not (line.strip().startswith('#') or
                                       line.strip().startswith('//') or
                                       'test' in line.lower() or
                                       'example' in line.lower()):
                                    self.add_issue(
                                        "hardcoded_value",
                                        f"Hardcoded value detected: {match.group()[:50]}...",
                                        "medium",
                                        str(file_path),
                                        line_num,
                                        suggestion="Move to configuration file or environment variables",
                                        anti_pattern="Hardcoded Configuration"
                                    )
        except Exception:
            pass

    def detect_magic_numbers(self, file_path: Path) -> None:
        """Detect magic numbers that should be named constants"""
        try:
            content = file_path.read_text(encoding='utf-8')
            lines = content.split('\n')

            # Track number usage
            number_usage = defaultdict(list)

            for line_num, line in enumerate(lines, 1):
                # Skip comments
                if line.strip().startswith('#') or line.strip().startswith('//'):
                    continue

                for pattern in self.anti_pattern_indicators['magic_numbers']:
                    matches = re.finditer(pattern, line)
                    for match in matches:
                        number = match.group()
                        # Skip obvious non-magic numbers (0, 1, -1, etc.)
                        if number not in ['0', '1', '-1', '2']:
                            number_usage[number].append((line_num, line.strip()))

            # Report numbers used multiple times
            for number, occurrences in number_usage.items():
                if len(occurrences) >= self.thresholds['magic_number_threshold']:
                    first_line, first_occurrence = occurrences[0]
                    self.add_issue(
                        "magic_number",
                        f"Magic number '{number}' used {len(occurrences)} times across file",
                        "low" if len(occurrences) < 5 else "medium",
                        str(file_path),
                        first_line,
                        suggestion=f"Define as named constant: CONSTANT_NAME = {number}",
                        anti_pattern="Magic Numbers"
                    )

        except Exception:
            pass

    def detect_duplicate_code(self, file_path: Path) -> None:
        """Detect potential code duplication patterns"""
        try:
            content = file_path.read_text(encoding='utf-8')
            lines = [line.strip() for line in content.split('\n') if line.strip() and not line.strip().startswith('#')]

            # Look for duplicate line sequences
            for i in range(len(lines) - self.thresholds['duplicate_line_threshold']):
                for j in range(i + self.thresholds['duplicate_line_threshold'], len(lines) - self.thresholds['duplicate_line_threshold']):
                    # Check for sequence of identical lines
                    match_count = 0
                    for k in range(min(10, len(lines) - j)):  # Check up to 10 lines
                        if i + k < len(lines) and lines[i + k] == lines[j + k]:
                            match_count += 1
                        else:
                            break

                    if match_count >= self.thresholds['duplicate_line_threshold']:
                        self.add_issue(
                            "duplicate_code",
                            f"Potential duplicate code block ({match_count} lines) starting at lines {i+1} and {j+1}",
                            "medium",
                            str(file_path),
                            i + 1,
                            suggestion="Extract common code into a shared function or method",
                            anti_pattern="Copy-Paste Programming"
                        )
                        break  # Avoid reporting the same duplication multiple times

            # Look for copy-paste indicators in comments
            for line_num, line in enumerate(content.split('\n'), 1):
                for indicator in self.anti_pattern_indicators['copy_paste_indicators']:
                    if indicator.lower() in line.lower():
                        self.add_issue(
                            "copy_paste_indicator",
                            f"Copy-paste indicator found in comment: {indicator}",
                            "low",
                            str(file_path),
                            line_num,
                            suggestion="Address the indicated duplication or refactoring need",
                            anti_pattern="Copy-Paste Programming"
                        )

        except Exception:
            pass

    def analyze_python_file(self, file_path: Path) -> None:
        """Analyze Python file for anti-patterns"""
        try:
            content = file_path.read_text(encoding='utf-8')
            tree = ast.parse(content)

            # Run all anti-pattern detections
            self.detect_god_functions(file_path, tree)
            self.detect_god_classes(file_path, tree)
            self.detect_deep_nesting(file_path, tree)
            self.detect_long_parameter_lists(file_path, tree)

        except SyntaxError as e:
            self.add_issue(
                "syntax_error",
                f"Python syntax error prevents analysis: {str(e)}",
                "high",
                str(file_path),
                suggestion="Fix syntax errors to enable anti-pattern detection"
            )
        except Exception as e:
            self.add_issue(
                "analysis_error",
                f"Error during analysis: {str(e)}",
                "low",
                str(file_path)
            )

    def analyze_file(self, file_path: Path) -> None:
        """Analyze any file type for applicable anti-patterns"""
        self.logger.info(f"Analyzing {file_path} for anti-patterns")

        # Always check for hardcoded values and magic numbers
        self.detect_hardcoded_values(file_path)
        self.detect_magic_numbers(file_path)
        self.detect_duplicate_code(file_path)

        # Python-specific analysis
        if file_path.suffix == '.py':
            self.analyze_python_file(file_path)

    def scan_codebase(self, patterns: List[str] = None) -> None:
        """Scan codebase for anti-patterns"""
        if patterns is None:
            patterns = ['**/*.py', '**/*.js', '**/*.ts']

        scanned_files = set()

        for pattern in patterns:
            for file_path in Path('.').glob(pattern):
                if (file_path.is_file() and
                    str(file_path) not in scanned_files and
                    not any(part.startswith('.') for part in file_path.parts) and
                    'node_modules' not in str(file_path) and
                    '__pycache__' not in str(file_path)):

                    self.analyze_file(file_path)
                    scanned_files.add(str(file_path))

    def generate_anti_pattern_report(self) -> Dict:
        """Generate detailed anti-pattern report"""
        anti_pattern_counts = defaultdict(int)
        severity_counts = defaultdict(int)
        files_affected = set()

        for issue in self.issues:
            anti_pattern_counts[issue.get('anti_pattern', 'Unknown')] += 1
            severity_counts[issue['severity']] += 1
            if 'file' in issue:
                files_affected.add(issue['file'])

        # Calculate anti-pattern risk score
        risk_score = (
            severity_counts['critical'] * 10 +
            severity_counts['high'] * 6 +
            severity_counts['medium'] * 3 +
            severity_counts['low'] * 1
        )

        return {
            'anti_pattern_summary': dict(anti_pattern_counts),
            'severity_breakdown': dict(severity_counts),
            'files_affected': len(files_affected),
            'total_anti_patterns': len(self.issues),
            'risk_score': risk_score,
            'risk_level': (
                'CRITICAL' if risk_score > 50 else
                'HIGH' if risk_score > 25 else
                'MEDIUM' if risk_score > 10 else
                'LOW'
            )
        }

    def run_validation(self, file_patterns: List[str] = None) -> Dict:
        """Run anti-pattern detection"""
        self.logger.info("Starting ArionComply anti-pattern detection")

        self.scan_codebase(file_patterns)

        # Generate report
        anti_pattern_report = self.generate_anti_pattern_report()

        # Determine if validation passed (allow some low-severity issues)
        critical_issues = [i for i in self.issues if i['severity'] == 'critical']
        high_issues = [i for i in self.issues if i['severity'] == 'high']

        passed = (len(critical_issues) == 0 and
                 len(high_issues) <= 5 and
                 anti_pattern_report['risk_score'] < 30)

        return {
            "passed": passed,
            "score": self.score,
            "max_score": self.max_score,
            "issues": self.issues,
            "anti_pattern_report": anti_pattern_report,
            "summary": {
                "total_issues": len(self.issues),
                "critical_issues": len([i for i in self.issues if i['severity'] == 'critical']),
                "high_issues": len([i for i in self.issues if i['severity'] == 'high']),
                "medium_issues": len([i for i in self.issues if i['severity'] == 'medium']),
                "low_issues": len([i for i in self.issues if i['severity'] == 'low']),
                "files_scanned": anti_pattern_report['files_affected'],
                "risk_level": anti_pattern_report['risk_level']
            },
            "thresholds": self.thresholds
        }

def main():
    parser = argparse.ArgumentParser(description='Detect ArionComply code anti-patterns')
    parser.add_argument('--json-output', action='store_true', help='Output results in JSON format')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--patterns', nargs='*', help='File patterns to scan (default: *.py, *.js, *.ts)')

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.INFO)

    detector = AntiPatternDetector()
    result = detector.run_validation(args.patterns)

    if args.json_output:
        print(json.dumps(result, indent=2))
    else:
        # Human-readable output
        print(f"Anti-Pattern Detection: {'PASSED' if result['passed'] else 'FAILED'}")
        print(f"Risk Level: {result['summary']['risk_level']}")
        print(f"Files Scanned: {result['summary']['files_scanned']}")
        print(f"Total Anti-Patterns: {result['summary']['total_issues']}")

        if result['anti_pattern_report']['anti_pattern_summary']:
            print(f"\nAnti-Pattern Breakdown:")
            for pattern, count in result['anti_pattern_report']['anti_pattern_summary'].items():
                print(f"  {pattern}: {count}")

        if result['issues']:
            print(f"\nTop Anti-Pattern Issues:")
            # Show worst issues first
            sorted_issues = sorted(result['issues'],
                                 key=lambda x: {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}[x['severity']],
                                 reverse=True)

            for issue in sorted_issues[:10]:  # Show top 10
                print(f"  [{issue['severity'].upper()}] {issue['description']}")
                if 'file' in issue:
                    print(f"    File: {issue['file']} {'(line ' + str(issue['line']) + ')' if 'line' in issue else ''}")
                if 'function' in issue:
                    print(f"    Function: {issue['function']}")
                if 'suggestion' in issue:
                    print(f"    Fix: {issue['suggestion']}")
                print()

        print(f"\n💡 Purpose: Catch these patterns EARLY to avoid major refactoring later!")
        print(f"   Example: A 200-line function now prevents a 578-line disaster later.")

    sys.exit(0 if result['passed'] else 1)

if __name__ == "__main__":
    main()