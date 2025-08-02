#!/usr/bin/env python3
"""
AI-Powered Code Fix Suggestions and Remediation Engine
Integrates with LLMs to provide intelligent recommendations
"""

import os
import json
import asyncio
import aiohttp
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import logging
from datetime import datetime
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class AIRecommendation:
    """Represents an AI-generated recommendation"""
    vulnerability_id: str
    recommendation_type: str  # fix, explanation, best_practice
    title: str
    description: str
    code_fix: Optional[str]
    before_code: Optional[str]
    after_code: Optional[str]
    confidence_score: float
    reasoning: str
    tags: List[str]
    created_at: datetime

class AIRecommendationEngine:
    """AI-powered recommendation engine for security vulnerabilities"""
    
    def __init__(self, openai_api_key: Optional[str] = None, model: str = "gpt-3.5-turbo"):
        self.openai_api_key = openai_api_key or os.getenv("OPENAI_API_KEY")
        self.model = model
        self.base_url = "https://api.openai.com/v1/chat/completions"
        
        # Pre-defined recommendations for common vulnerabilities
        self.common_recommendations = {
            "sql_injection": {
                "title": "SQL Injection Prevention",
                "description": "Use parameterized queries or ORM to prevent SQL injection attacks",
                "code_fix": "Use parameterized queries with placeholders",
                "before_code": "query = f\"SELECT * FROM users WHERE id = {user_id}\"",
                "after_code": "query = \"SELECT * FROM users WHERE id = %s\"\ncursor.execute(query, (user_id,))",
                "confidence_score": 0.95,
                "reasoning": "Direct string concatenation in SQL queries is vulnerable to injection attacks",
                "tags": ["sql-injection", "database", "security"]
            },
            "xss": {
                "title": "Cross-Site Scripting Prevention",
                "description": "Sanitize user input and use proper output encoding",
                "code_fix": "Use HTML escaping for user input",
                "before_code": "return f\"<div>{user_input}</div>\"",
                "after_code": "import html\nreturn f\"<div>{html.escape(user_input)}</div>\"",
                "confidence_score": 0.90,
                "reasoning": "Unsanitized user input can lead to XSS attacks",
                "tags": ["xss", "input-validation", "security"]
            },
            "hardcoded_credentials": {
                "title": "Remove Hardcoded Credentials",
                "description": "Use environment variables or secure configuration management",
                "code_fix": "Use environment variables for sensitive data",
                "before_code": "password = \"admin123\"",
                "after_code": "import os\npassword = os.getenv(\"DB_PASSWORD\")",
                "confidence_score": 0.98,
                "reasoning": "Hardcoded credentials are a major security risk",
                "tags": ["credentials", "configuration", "security"]
            },
            "eval_usage": {
                "title": "Avoid eval() Function",
                "description": "The eval() function can execute arbitrary code and is a security risk",
                "code_fix": "Use safer alternatives like ast.literal_eval()",
                "before_code": "result = eval(user_input)",
                "after_code": "import ast\nresult = ast.literal_eval(user_input)",
                "confidence_score": 0.92,
                "reasoning": "eval() can execute malicious code and should be avoided",
                "tags": ["eval", "code-execution", "security"]
            }
        }
    
    async def generate_recommendation(self, vulnerability: Dict[str, Any]) -> AIRecommendation:
        """Generate AI-powered recommendation for a vulnerability"""
        try:
            # First, try to get a pre-defined recommendation
            pre_defined = self.get_predefined_recommendation(vulnerability)
            if pre_defined:
                return pre_defined
            
            # If no pre-defined recommendation, use AI
            if self.openai_api_key:
                return await self.generate_ai_recommendation(vulnerability)
            else:
                return self.generate_basic_recommendation(vulnerability)
                
        except Exception as e:
            logger.error(f"Error generating recommendation: {e}")
            return self.generate_fallback_recommendation(vulnerability)
    
    def get_predefined_recommendation(self, vulnerability: Dict[str, Any]) -> Optional[AIRecommendation]:
        """Get pre-defined recommendation for common vulnerabilities"""
        vuln_type = vulnerability.get('vulnerability_type', '').lower()
        description = vulnerability.get('description', '').lower()
        
        # Check for SQL injection
        if 'sql' in vuln_type or 'sql' in description or 'injection' in description:
            return self._create_recommendation(vulnerability, self.common_recommendations['sql_injection'])
        
        # Check for XSS
        if 'xss' in vuln_type or 'cross-site' in description or 'script' in description:
            return self._create_recommendation(vulnerability, self.common_recommendations['xss'])
        
        # Check for hardcoded credentials
        if 'credential' in vuln_type or 'password' in description or 'secret' in description:
            return self._create_recommendation(vulnerability, self.common_recommendations['hardcoded_credentials'])
        
        # Check for eval usage
        if 'eval' in vuln_type or 'eval' in description:
            return self._create_recommendation(vulnerability, self.common_recommendations['eval_usage'])
        
        return None
    
    def _create_recommendation(self, vulnerability: Dict[str, Any], template: Dict[str, Any]) -> AIRecommendation:
        """Create recommendation from template"""
        return AIRecommendation(
            vulnerability_id=vulnerability.get('id', ''),
            recommendation_type='fix',
            title=template['title'],
            description=template['description'],
            code_fix=template['code_fix'],
            before_code=template['before_code'],
            after_code=template['after_code'],
            confidence_score=template['confidence_score'],
            reasoning=template['reasoning'],
            tags=template['tags'],
            created_at=datetime.now()
        )
    
    async def generate_ai_recommendation(self, vulnerability: Dict[str, Any]) -> AIRecommendation:
        """Generate recommendation using OpenAI API"""
        try:
            prompt = self._create_ai_prompt(vulnerability)
            
            headers = {
                "Authorization": f"Bearer {self.openai_api_key}",
                "Content-Type": "application/json"
            }
            
            data = {
                "model": self.model,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert specializing in code security analysis and remediation. Provide clear, actionable recommendations for fixing security vulnerabilities."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "max_tokens": 1000,
                "temperature": 0.3
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(self.base_url, headers=headers, json=data) as response:
                    if response.status == 200:
                        result = await response.json()
                        content = result['choices'][0]['message']['content']
                        return self._parse_ai_response(vulnerability, content)
                    else:
                        logger.error(f"OpenAI API error: {response.status}")
                        return self.generate_basic_recommendation(vulnerability)
                        
        except Exception as e:
            logger.error(f"Error calling OpenAI API: {e}")
            return self.generate_basic_recommendation(vulnerability)
    
    def _create_ai_prompt(self, vulnerability: Dict[str, Any]) -> str:
        """Create AI prompt for vulnerability analysis"""
        return f"""
        Analyze this security vulnerability and provide a detailed recommendation:
        
        Vulnerability Type: {vulnerability.get('vulnerability_type', 'Unknown')}
        Description: {vulnerability.get('description', 'No description')}
        File: {vulnerability.get('file_name', 'Unknown')}
        Line: {vulnerability.get('line_number', 'Unknown')}
        Severity: {vulnerability.get('severity', 'Unknown')}
        Tool: {vulnerability.get('tool', 'Unknown')}
        
        Please provide:
        1. A clear title for the recommendation
        2. Detailed explanation of the issue
        3. Specific code fix with before/after examples
        4. Confidence score (0-1)
        5. Reasoning for the recommendation
        6. Relevant security tags
        
        Format your response as JSON with these fields:
        {{
            "title": "string",
            "description": "string",
            "code_fix": "string",
            "before_code": "string",
            "after_code": "string",
            "confidence_score": 0.95,
            "reasoning": "string",
            "tags": ["tag1", "tag2"]
        }}
        """
    
    def _parse_ai_response(self, vulnerability: Dict[str, Any], content: str) -> AIRecommendation:
        """Parse AI response and create recommendation"""
        try:
            # Extract JSON from response
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                
                return AIRecommendation(
                    vulnerability_id=vulnerability.get('id', ''),
                    recommendation_type='fix',
                    title=data.get('title', 'Security Fix Recommendation'),
                    description=data.get('description', ''),
                    code_fix=data.get('code_fix', ''),
                    before_code=data.get('before_code', ''),
                    after_code=data.get('after_code', ''),
                    confidence_score=float(data.get('confidence_score', 0.8)),
                    reasoning=data.get('reasoning', ''),
                    tags=data.get('tags', []),
                    created_at=datetime.now()
                )
            else:
                return self.generate_basic_recommendation(vulnerability)
                
        except Exception as e:
            logger.error(f"Error parsing AI response: {e}")
            return self.generate_basic_recommendation(vulnerability)
    
    def generate_basic_recommendation(self, vulnerability: Dict[str, Any]) -> AIRecommendation:
        """Generate basic recommendation without AI"""
        vuln_type = vulnerability.get('vulnerability_type', 'Security Issue')
        description = vulnerability.get('description', '')
        
        return AIRecommendation(
            vulnerability_id=vulnerability.get('id', ''),
            recommendation_type='fix',
            title=f"Fix {vuln_type}",
            description=f"Review and fix the identified {vuln_type.lower()} vulnerability",
            code_fix="Review the code and implement appropriate security measures",
            before_code="",
            after_code="",
            confidence_score=0.7,
            reasoning=f"This is a {vulnerability.get('severity', 'medium')} severity issue that should be addressed",
            tags=[vuln_type.lower().replace(' ', '-'), 'security'],
            created_at=datetime.now()
        )
    
    def generate_fallback_recommendation(self, vulnerability: Dict[str, Any]) -> AIRecommendation:
        """Generate fallback recommendation when all else fails"""
        return AIRecommendation(
            vulnerability_id=vulnerability.get('id', ''),
            recommendation_type='explanation',
            title="Security Review Required",
            description="This vulnerability requires manual review and remediation",
            code_fix="",
            before_code="",
            after_code="",
            confidence_score=0.5,
            reasoning="Unable to generate specific recommendation. Manual review recommended.",
            tags=['manual-review', 'security'],
            created_at=datetime.now()
        )
    
    async def generate_batch_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[AIRecommendation]:
        """Generate recommendations for multiple vulnerabilities"""
        tasks = []
        for vuln in vulnerabilities:
            tasks.append(self.generate_recommendation(vuln))
        
        return await asyncio.gather(*tasks, return_exceptions=True)
    
    def get_recommendation_by_type(self, vuln_type: str) -> Optional[Dict[str, Any]]:
        """Get recommendation template by vulnerability type"""
        return self.common_recommendations.get(vuln_type.lower(), None)
    
    def add_custom_recommendation(self, vuln_type: str, recommendation: Dict[str, Any]):
        """Add custom recommendation template"""
        self.common_recommendations[vuln_type.lower()] = recommendation

class RiskScoringEngine:
    """Calculate risk scores for vulnerabilities and projects"""
    
    def __init__(self):
        self.severity_weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 1
        }
        
        self.vuln_type_weights = {
            'sql_injection': 1.5,
            'xss': 1.3,
            'hardcoded_credentials': 1.4,
            'eval_usage': 1.2,
            'path_traversal': 1.1,
            'command_injection': 1.6
        }
    
    def calculate_vulnerability_risk_score(self, vulnerability: Dict[str, Any]) -> float:
        """Calculate risk score for a single vulnerability"""
        base_score = self.severity_weights.get(vulnerability.get('severity', 'medium'), 4)
        
        # Apply vulnerability type multiplier
        vuln_type = vulnerability.get('vulnerability_type', '').lower()
        type_multiplier = 1.0
        for vuln_pattern, weight in self.vuln_type_weights.items():
            if vuln_pattern in vuln_type:
                type_multiplier = weight
                break
        
        # Apply tool confidence if available
        confidence = vulnerability.get('context', {}).get('confidence', 'medium')
        confidence_multiplier = {
            'high': 1.2,
            'medium': 1.0,
            'low': 0.8
        }.get(confidence, 1.0)
        
        return base_score * type_multiplier * confidence_multiplier
    
    def calculate_project_risk_score(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate overall project risk score"""
        if not vulnerabilities:
            return {
                'total_score': 0,
                'risk_level': 'low',
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0
            }
        
        total_score = 0
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for vuln in vulnerabilities:
            score = self.calculate_vulnerability_risk_score(vuln)
            total_score += score
            
            severity = vuln.get('severity', 'medium')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Determine risk level
        if total_score >= 50 or severity_counts['critical'] > 0:
            risk_level = 'critical'
        elif total_score >= 30 or severity_counts['high'] > 2:
            risk_level = 'high'
        elif total_score >= 15 or severity_counts['medium'] > 5:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'total_score': round(total_score, 2),
            'risk_level': risk_level,
            'critical_count': severity_counts['critical'],
            'high_count': severity_counts['high'],
            'medium_count': severity_counts['medium'],
            'low_count': severity_counts['low']
        }
    
    def prioritize_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Prioritize vulnerabilities by risk score"""
        scored_vulns = []
        for vuln in vulnerabilities:
            score = self.calculate_vulnerability_risk_score(vuln)
            scored_vulns.append({
                **vuln,
                'risk_score': score
            })
        
        # Sort by risk score (highest first)
        scored_vulns.sort(key=lambda x: x['risk_score'], reverse=True)
        return scored_vulns 