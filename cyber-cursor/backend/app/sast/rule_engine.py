#!/usr/bin/env python3
"""
SAST Rule Engine for Custom Rule Management and Execution
"""

import re
import ast
import json
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import logging
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class RuleSeverity(Enum):
    BLOCKER = "BLOCKER"
    CRITICAL = "CRITICAL"
    MAJOR = "MAJOR"
    MINOR = "MINOR"
    INFO = "INFO"

class RuleType(Enum):
    VULNERABILITY = "VULNERABILITY"
    BUG = "BUG"
    CODE_SMELL = "CODE_SMELL"
    SECURITY_HOTSPOT = "SECURITY_HOTSPOT"

@dataclass
class RuleMatch:
    """Represents a rule match in code"""
    rule_id: str
    rule_name: str
    severity: RuleSeverity
    rule_type: RuleType
    message: str
    file_path: str
    line_number: int
    start_line: int
    end_line: int
    start_column: int
    end_column: int
    code_snippet: str
    context: Dict[str, Any]
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    owasp_category: Optional[str] = None

@dataclass
class CustomRule:
    """Represents a custom SAST rule"""
    rule_id: str
    name: str
    description: str
    category: str
    subcategory: Optional[str]
    severity: RuleSeverity
    rule_type: RuleType
    languages: List[str]
    enabled: bool = True
    effort: int = 0
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    tags: List[str] = None
    
    # Rule definition
    pattern: Optional[str] = None  # Regex pattern
    ast_pattern: Optional[str] = None  # AST pattern for Python
    message_template: str = "Rule violation: {rule_name}"
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []

class RuleEngine:
    """Main rule engine for executing custom rules"""
    
    def __init__(self):
        self.rules: Dict[str, CustomRule] = {}
        self.compiled_patterns: Dict[str, re.Pattern] = {}
        self.ast_visitors: Dict[str, Any] = {}
        
    def add_rule(self, rule: CustomRule) -> bool:
        """Add a custom rule to the engine"""
        try:
            # Validate rule
            if not self._validate_rule(rule):
                return False
            
            # Compile pattern if it's a regex rule
            if rule.pattern:
                self.compiled_patterns[rule.rule_id] = re.compile(rule.pattern, re.MULTILINE)
            
            # Store rule
            self.rules[rule.rule_id] = rule
            logger.info(f"Added custom rule: {rule.rule_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding rule {rule.rule_id}: {e}")
            return False
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule from the engine"""
        try:
            if rule_id in self.rules:
                del self.rules[rule_id]
                if rule_id in self.compiled_patterns:
                    del self.compiled_patterns[rule_id]
                logger.info(f"Removed rule: {rule_id}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error removing rule {rule_id}: {e}")
            return False
    
    def update_rule(self, rule_id: str, updates: Dict[str, Any]) -> bool:
        """Update an existing rule"""
        try:
            if rule_id not in self.rules:
                return False
            
            rule = self.rules[rule_id]
            
            # Update fields
            for field, value in updates.items():
                if hasattr(rule, field):
                    if field == "severity":
                        setattr(rule, field, RuleSeverity(value.upper()))
                    elif field == "rule_type":
                        setattr(rule, field, RuleType(value.upper()))
                    else:
                        setattr(rule, field, value)
            
            # Recompile pattern if changed
            if "pattern" in updates and updates["pattern"]:
                self.compiled_patterns[rule_id] = re.compile(updates["pattern"], re.MULTILINE)
            
            logger.info(f"Updated rule: {rule_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating rule {rule_id}: {e}")
            return False
    
    def get_rule(self, rule_id: str) -> Optional[CustomRule]:
        """Get a rule by ID"""
        return self.rules.get(rule_id)
    
    def get_rules_by_language(self, language: str) -> List[CustomRule]:
        """Get all rules for a specific language"""
        return [rule for rule in self.rules.values() if language in rule.languages]
    
    def get_enabled_rules(self) -> List[CustomRule]:
        """Get all enabled rules"""
        return [rule for rule in self.rules.values() if rule.enabled]
    
    async def scan_file(self, file_path: str, language: str) -> List[RuleMatch]:
        """Scan a single file for rule violations"""
        try:
            matches = []
            
            # Get rules for this language
            language_rules = self.get_rules_by_language(language)
            if not language_rules:
                return matches
            
            # Read file content
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.splitlines()
            
            # Apply each rule
            for rule in language_rules:
                if not rule.enabled:
                    continue
                
                rule_matches = await self._apply_rule(rule, content, lines, file_path, language)
                matches.extend(rule_matches)
            
            return matches
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return []
    
    async def _apply_rule(self, rule: CustomRule, content: str, lines: List[str], 
                          file_path: str, language: str) -> List[RuleMatch]:
        """Apply a single rule to file content"""
        matches = []
        
        try:
            if rule.pattern:
                # Regex-based rule
                matches.extend(self._apply_regex_rule(rule, content, lines, file_path))
            elif rule.ast_pattern and language == "python":
                # AST-based rule for Python
                matches.extend(self._apply_ast_rule(rule, content, lines, file_path))
            else:
                # Pattern-based rule
                matches.extend(self._apply_pattern_rule(rule, content, lines, file_path))
                
        except Exception as e:
            logger.error(f"Error applying rule {rule.rule_id}: {e}")
        
        return matches
    
    def _apply_regex_rule(self, rule: CustomRule, content: str, lines: List[str], 
                          file_path: str) -> List[RuleMatch]:
        """Apply regex-based rule"""
        matches = []
        
        if rule.rule_id not in self.compiled_patterns:
            return matches
        
        pattern = self.compiled_patterns[rule.rule_id]
        
        for match in pattern.finditer(content):
            # Calculate line and column numbers
            start_pos = match.start()
            end_pos = match.end()
            
            # Find line number
            line_number = content[:start_pos].count('\n') + 1
            
            # Get code snippet
            start_line = max(0, line_number - 2)
            end_line = min(len(lines), line_number + 2)
            code_snippet = '\n'.join(lines[start_line:end_line])
            
            # Create match
            rule_match = RuleMatch(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                severity=rule.severity,
                rule_type=rule.rule_type,
                message=rule.message_template.format(rule_name=rule.name),
                file_path=file_path,
                line_number=line_number,
                start_line=start_line + 1,
                end_line=end_line,
                start_column=match.start() - content.rfind('\n', 0, match.start()) - 1,
                end_column=match.end() - content.rfind('\n', 0, match.end()) - 1,
                code_snippet=code_snippet,
                context={"match_text": match.group()},
                cwe_id=rule.cwe_id,
                cvss_score=rule.cvss_score,
                owasp_category=rule.owasp_category
            )
            
            matches.append(rule_match)
        
        return matches
    
    def _apply_ast_rule(self, rule: CustomRule, content: str, lines: List[str], 
                        file_path: str) -> List[RuleMatch]:
        """Apply AST-based rule for Python"""
        matches = []
        
        try:
            # Parse Python code
            tree = ast.parse(content)
            
            # Create AST visitor for this rule
            visitor = self._create_ast_visitor(rule)
            if visitor:
                visitor.visit(tree)
                matches = visitor.get_matches(file_path, lines, rule)
                
        except SyntaxError as e:
            logger.warning(f"Syntax error in {file_path}: {e}")
        except Exception as e:
            logger.error(f"Error applying AST rule {rule.rule_id}: {e}")
        
        return matches
    
    def _apply_pattern_rule(self, rule: CustomRule, content: str, lines: List[str], 
                           file_path: str) -> List[RuleMatch]:
        """Apply pattern-based rule (fallback)"""
        matches = []
        
        # Simple text search
        if rule.pattern:
            for i, line in enumerate(lines, 1):
                if rule.pattern.lower() in line.lower():
                    rule_match = RuleMatch(
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        rule_type=rule.rule_type,
                        message=rule.message_template.format(rule_name=rule.name),
                        file_path=file_path,
                        line_number=i,
                        start_line=i,
                        end_line=i,
                        start_column=0,
                        end_column=len(line),
                        code_snippet=line,
                        context={"line_content": line},
                        cwe_id=rule.cwe_id,
                        cvss_score=rule.cvss_score,
                        owasp_category=rule.owasp_category
                    )
                    matches.append(rule_match)
        
        return matches
    
    def _create_ast_visitor(self, rule: CustomRule):
        """Create AST visitor for Python rules"""
        # This is a simplified example - in production you'd have more sophisticated AST analysis
        class SimpleASTVisitor(ast.NodeVisitor):
            def __init__(self, rule: CustomRule):
                self.rule = rule
                self.matches = []
            
            def visit_FunctionDef(self, node):
                # Example: Check for function names that might indicate security issues
                if "password" in node.name.lower() or "secret" in node.name.lower():
                    self.matches.append({
                        "node": node,
                        "message": f"Function name '{node.name}' might indicate security concern"
                    })
                self.generic_visit(node)
            
            def visit_Call(self, node):
                # Example: Check for potentially dangerous function calls
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id.lower()
                    if func_name in ["eval", "exec", "input"]:
                        self.matches.append({
                            "node": node,
                            "message": f"Potentially dangerous function call: {func_name}"
                        })
                self.generic_visit(node)
            
            def get_matches(self, file_path: str, lines: List[str], rule: CustomRule) -> List[RuleMatch]:
                """Convert AST matches to RuleMatch objects"""
                rule_matches = []
                
                for match in self.matches:
                    line_number = match["node"].lineno
                    
                    # Get code snippet
                    start_line = max(0, line_number - 2)
                    end_line = min(len(lines), line_number + 2)
                    code_snippet = '\n'.join(lines[start_line:end_line])
                    
                    rule_match = RuleMatch(
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        rule_type=rule.rule_type,
                        message=match["message"],
                        file_path=file_path,
                        line_number=line_number,
                        start_line=start_line + 1,
                        end_line=end_line,
                        start_column=0,
                        end_column=len(lines[line_number - 1]) if line_number <= len(lines) else 0,
                        code_snippet=code_snippet,
                        context={"ast_node": match["node"]},
                        cwe_id=rule.cwe_id,
                        cvss_score=rule.cvss_score,
                        owasp_category=rule.owasp_category
                    )
                    
                    rule_matches.append(rule_match)
                
                return rule_matches
        
        return SimpleASTVisitor(rule)
    
    def _validate_rule(self, rule: CustomRule) -> bool:
        """Validate a custom rule"""
        try:
            # Check required fields
            if not rule.rule_id or not rule.name or not rule.languages:
                return False
            
            # Validate severity and type
            if not isinstance(rule.severity, RuleSeverity) or not isinstance(rule.rule_type, RuleType):
                return False
            
            # Validate pattern if provided
            if rule.pattern:
                try:
                    re.compile(rule.pattern)
                except re.error:
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Rule validation error: {e}")
            return False
    
    def export_rules(self, file_path: str) -> bool:
        """Export all rules to JSON file"""
        try:
            rules_data = []
            for rule in self.rules.values():
                rule_data = {
                    "rule_id": rule.rule_id,
                    "name": rule.name,
                    "description": rule.description,
                    "category": rule.category,
                    "subcategory": rule.subcategory,
                    "severity": rule.severity.value,
                    "rule_type": rule.rule_type.value,
                    "languages": rule.languages,
                    "enabled": rule.enabled,
                    "effort": rule.effort,
                    "cwe_id": rule.cwe_id,
                    "owasp_category": rule.owasp_category,
                    "tags": rule.tags,
                    "pattern": rule.pattern,
                    "ast_pattern": rule.ast_pattern,
                    "message_template": rule.message_template
                }
                rules_data.append(rule_data)
            
            with open(file_path, 'w') as f:
                json.dump(rules_data, f, indent=2)
            
            logger.info(f"Exported {len(rules_data)} rules to {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting rules: {e}")
            return False
    
    def import_rules(self, file_path: str) -> bool:
        """Import rules from JSON file"""
        try:
            with open(file_path, 'r') as f:
                rules_data = json.load(f)
            
            imported_count = 0
            for rule_data in rules_data:
                try:
                    rule = CustomRule(
                        rule_id=rule_data["rule_id"],
                        name=rule_data["name"],
                        description=rule_data["description"],
                        category=rule_data["category"],
                        subcategory=rule_data.get("subcategory"),
                        severity=RuleSeverity(rule_data["severity"]),
                        rule_type=RuleType(rule_data["rule_type"]),
                        languages=rule_data["languages"],
                        enabled=rule_data.get("enabled", True),
                        effort=rule_data.get("effort", 0),
                        cwe_id=rule_data.get("cwe_id"),
                        owasp_category=rule_data.get("owasp_category"),
                        tags=rule_data.get("tags", []),
                        pattern=rule_data.get("pattern"),
                        ast_pattern=rule_data.get("ast_pattern"),
                        message_template=rule_data.get("message_template", "Rule violation: {rule_name}")
                    )
                    
                    if self.add_rule(rule):
                        imported_count += 1
                        
                except Exception as e:
                    logger.error(f"Error importing rule {rule_data.get('rule_id', 'unknown')}: {e}")
            
            logger.info(f"Imported {imported_count} rules from {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error importing rules: {e}")
            return False

# Example usage and predefined rules
def create_default_rules() -> List[CustomRule]:
    """Create a set of default security rules"""
    default_rules = [
        # SQL Injection patterns
        CustomRule(
            rule_id="SQL_INJECTION_001",
            name="SQL Injection Detection",
            description="Detect potential SQL injection vulnerabilities",
            category="Security",
            subcategory="SQL Injection",
            severity=RuleSeverity.CRITICAL,
            rule_type=RuleType.VULNERABILITY,
            languages=["python", "javascript", "php", "java"],
            pattern=r"execute\s*\(\s*[\"'].*\+\s*\w+",
            cwe_id="CWE-89",
            owasp_category="A03:2021 - Injection",
            tags=["sql-injection", "security"]
        ),
        
        # XSS patterns
        CustomRule(
            rule_id="XSS_001",
            name="Cross-Site Scripting Detection",
            description="Detect potential XSS vulnerabilities",
            category="Security",
            subcategory="XSS",
            severity=RuleSeverity.CRITICAL,
            rule_type=RuleType.VULNERABILITY,
            languages=["python", "javascript", "php", "java"],
            pattern=r"innerHTML\s*=\s*[\"'].*\+\s*\w+",
            cwe_id="CWE-79",
            owasp_category="A03:2021 - Injection",
            tags=["xss", "security"]
        ),
        
        # Hardcoded credentials
        CustomRule(
            rule_id="HARDCODED_CREDS_001",
            name="Hardcoded Credentials",
            description="Detect hardcoded passwords and API keys",
            category="Security",
            subcategory="Credentials",
            severity=RuleSeverity.CRITICAL,
            rule_type=RuleType.VULNERABILITY,
            languages=["python", "javascript", "php", "java"],
            pattern=r"password\s*=\s*[\"'][^\"']{8,}[\"']",
            cwe_id="CWE-259",
            owasp_category="A07:2021 - Identification and Authentication Failures",
            tags=["credentials", "security"]
        ),
        
        # Insecure random
        CustomRule(
            rule_id="INSECURE_RANDOM_001",
            name="Insecure Random Number Generation",
            description="Detect use of insecure random number generators",
            category="Security",
            subcategory="Cryptography",
            severity=RuleSeverity.MAJOR,
            rule_type=RuleType.VULNERABILITY,
            languages=["python", "javascript", "php", "java"],
            pattern=r"Math\.random\(\)|random\.randint|rand\(\)",
            cwe_id="CWE-338",
            owasp_category="A02:2021 - Cryptographic Failures",
            tags=["cryptography", "security"]
        )
    ]
    
    return default_rules

# Initialize rule engine with default rules
rule_engine = RuleEngine()

# Add default rules
for rule in create_default_rules():
    rule_engine.add_rule(rule)
