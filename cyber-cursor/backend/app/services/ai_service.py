import openai
from typing import Dict, List, Optional, Any
import structlog
from datetime import datetime

from app.core.config import settings
from app.schemas.incident import IncidentType, IncidentSeverity
from app.models.phishing import ThreatLevel, EmailType

logger = structlog.get_logger()

class AIService:
    def __init__(self):
        if settings.OPENAI_API_KEY:
            openai.api_key = settings.OPENAI_API_KEY
        else:
            logger.warning("OpenAI API key not configured")
    
    async def analyze_email_content(
        self, 
        subject: str, 
        body_text: str, 
        body_html: str = None,
        sender: str = None,
        attachments: List[Dict] = None
    ) -> Dict[str, Any]:
        """
        Analyze email content for phishing indicators using AI
        """
        try:
            # Prepare content for analysis
            content = f"Subject: {subject}\n\n"
            if body_text:
                content += f"Body: {body_text}\n\n"
            if body_html:
                content += f"HTML Body: {body_html}\n\n"
            if sender:
                content += f"Sender: {sender}\n\n"
            
            if attachments:
                content += f"Attachments: {len(attachments)} files\n"
                for attachment in attachments:
                    content += f"- {attachment.get('filename', 'Unknown')} ({attachment.get('content_type', 'Unknown')})\n"
            
            # Create analysis prompt
            prompt = f"""
            Analyze the following email for phishing indicators and security threats:
            
            {content}
            
            Please provide a detailed analysis including:
            1. Threat level (safe, low, medium, high, critical)
            2. Email type (phishing, malware, spam, legitimate, suspicious)
            3. Confidence score (0-100)
            4. Specific threats detected
            5. Indicators of compromise
            6. Recommended actions
            
            Respond in JSON format with the following structure:
            {{
                "threat_level": "medium",
                "email_type": "phishing",
                "confidence_score": 85,
                "detected_threats": ["suspicious_url", "urgency_tactics"],
                "indicators": {{
                    "suspicious_domains": ["example.com"],
                    "urgency_indicators": ["immediate action required"],
                    "credential_harvesting": true
                }},
                "recommended_actions": ["quarantine", "notify_user"],
                "analysis_reasoning": "Detailed explanation of the analysis"
            }}
            """
            
            if not settings.OPENAI_API_KEY:
                # Fallback to rule-based analysis
                return self._rule_based_email_analysis(subject, body_text, sender)
            
            # Call OpenAI API
            response = await openai.ChatCompletion.acreate(
                model=settings.OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in email threat analysis."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=1000
            )
            
            # Parse response
            analysis_text = response.choices[0].message.content
            analysis = self._parse_ai_response(analysis_text)
            
            logger.info("Email analysis completed", 
                       threat_level=analysis.get("threat_level"),
                       confidence_score=analysis.get("confidence_score"))
            
            return analysis
            
        except Exception as e:
            logger.error("Email analysis failed", error=str(e))
            # Fallback to rule-based analysis
            return self._rule_based_email_analysis(subject, body_text, sender)
    
    def _rule_based_email_analysis(
        self, 
        subject: str, 
        body_text: str, 
        sender: str = None
    ) -> Dict[str, Any]:
        """
        Fallback rule-based email analysis
        """
        threat_indicators = []
        confidence_score = 50
        
        # Check for common phishing indicators
        subject_lower = subject.lower()
        body_lower = body_text.lower() if body_text else ""
        
        # Urgency indicators
        urgency_words = ["urgent", "immediate", "action required", "account suspended", "verify now"]
        if any(word in subject_lower or word in body_lower for word in urgency_words):
            threat_indicators.append("urgency_tactics")
            confidence_score += 20
        
        # Suspicious domains
        suspicious_domains = ["bit.ly", "tinyurl", "goo.gl", "t.co"]
        if any(domain in body_lower for domain in suspicious_domains):
            threat_indicators.append("suspicious_urls")
            confidence_score += 25
        
        # Credential harvesting
        credential_words = ["password", "login", "verify", "confirm", "update"]
        if any(word in body_lower for word in credential_words):
            threat_indicators.append("credential_harvesting")
            confidence_score += 15
        
        # Determine threat level
        if confidence_score >= 80:
            threat_level = "high"
            email_type = "phishing"
        elif confidence_score >= 60:
            threat_level = "medium"
            email_type = "suspicious"
        elif confidence_score >= 40:
            threat_level = "low"
            email_type = "spam"
        else:
            threat_level = "safe"
            email_type = "legitimate"
        
        return {
            "threat_level": threat_level,
            "email_type": email_type,
            "confidence_score": min(confidence_score, 100),
            "detected_threats": threat_indicators,
            "indicators": {
                "suspicious_domains": [],
                "urgency_indicators": [],
                "credential_harvesting": "credential_harvesting" in threat_indicators
            },
            "recommended_actions": ["monitor"] if threat_level == "safe" else ["quarantine"],
            "analysis_reasoning": f"Rule-based analysis detected {len(threat_indicators)} threat indicators"
        }
    
    def _parse_ai_response(self, response_text: str) -> Dict[str, Any]:
        """
        Parse AI response and extract structured data
        """
        try:
            import json
            # Try to extract JSON from response
            start_idx = response_text.find('{')
            end_idx = response_text.rfind('}') + 1
            if start_idx != -1 and end_idx != 0:
                json_str = response_text[start_idx:end_idx]
                return json.loads(json_str)
        except Exception as e:
            logger.error("Failed to parse AI response", error=str(e))
        
        # Return default structure if parsing fails
        return {
            "threat_level": "medium",
            "email_type": "suspicious",
            "confidence_score": 50,
            "detected_threats": [],
            "indicators": {},
            "recommended_actions": ["monitor"],
            "analysis_reasoning": "AI analysis failed, using default values"
        }
    
    async def classify_incident(
        self, 
        title: str, 
        description: str, 
        source_data: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Classify security incident using AI
        """
        try:
            content = f"Title: {title}\nDescription: {description}\n"
            if source_data:
                content += f"Source Data: {source_data}\n"
            
            prompt = f"""
            Classify the following security incident:
            
            {content}
            
            Please provide classification in JSON format:
            {{
                "incident_type": "phishing|malware|data_breach|unauthorized_access|cloud_misconfiguration|network_attack|other",
                "severity": "low|medium|high|critical",
                "confidence_score": 85,
                "tags": ["tag1", "tag2"],
                "recommended_playbook": "playbook_name",
                "priority": "low|medium|high|urgent"
            }}
            """
            
            if not settings.OPENAI_API_KEY:
                return self._rule_based_incident_classification(title, description)
            
            response = await openai.ChatCompletion.acreate(
                model=settings.OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity incident response expert."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=500
            )
            
            classification_text = response.choices[0].message.content
            classification = self._parse_ai_response(classification_text)
            
            logger.info("Incident classification completed", 
                       incident_type=classification.get("incident_type"),
                       severity=classification.get("severity"))
            
            return classification
            
        except Exception as e:
            logger.error("Incident classification failed", error=str(e))
            return self._rule_based_incident_classification(title, description)
    
    def _rule_based_incident_classification(
        self, 
        title: str, 
        description: str
    ) -> Dict[str, Any]:
        """
        Fallback rule-based incident classification
        """
        content_lower = f"{title} {description}".lower()
        
        # Determine incident type
        if any(word in content_lower for word in ["phish", "email", "suspicious"]):
            incident_type = "phishing"
        elif any(word in content_lower for word in ["malware", "virus", "trojan"]):
            incident_type = "malware"
        elif any(word in content_lower for word in ["breach", "leak", "exposure"]):
            incident_type = "data_breach"
        elif any(word in content_lower for word in ["unauthorized", "access", "login"]):
            incident_type = "unauthorized_access"
        elif any(word in content_lower for word in ["cloud", "aws", "azure", "gcp"]):
            incident_type = "cloud_misconfiguration"
        elif any(word in content_lower for word in ["network", "ddos", "attack"]):
            incident_type = "network_attack"
        else:
            incident_type = "other"
        
        # Determine severity
        if any(word in content_lower for word in ["critical", "urgent", "emergency"]):
            severity = "critical"
        elif any(word in content_lower for word in ["high", "severe", "important"]):
            severity = "high"
        elif any(word in content_lower for word in ["medium", "moderate"]):
            severity = "medium"
        else:
            severity = "low"
        
        return {
            "incident_type": incident_type,
            "severity": severity,
            "confidence_score": 70,
            "tags": [incident_type, severity],
            "recommended_playbook": f"{incident_type}_response",
            "priority": severity
        }
    
    async def generate_response_playbook(
        self, 
        incident_type: str, 
        severity: str, 
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Generate AI-powered response playbook
        """
        try:
            prompt = f"""
            Generate a response playbook for a {severity} severity {incident_type} incident.
            
            Context: {context or 'No additional context provided'}
            
            Please provide a structured playbook in JSON format:
            {{
                "name": "Playbook Name",
                "description": "Playbook description",
                "steps": [
                    {{
                        "step_number": 1,
                        "title": "Step Title",
                        "description": "Detailed description",
                        "action_type": "manual|automated|notification",
                        "action_details": {{}},
                        "estimated_time": 15,
                        "dependencies": [],
                        "required_approval": false
                    }}
                ],
                "estimated_total_time": 120,
                "required_roles": ["analyst", "admin"],
                "automation_opportunities": ["step1", "step2"]
            }}
            """
            
            if not settings.OPENAI_API_KEY:
                return self._get_default_playbook(incident_type, severity)
            
            response = await openai.ChatCompletion.acreate(
                model=settings.OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity incident response expert."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=1000
            )
            
            playbook_text = response.choices[0].message.content
            playbook = self._parse_ai_response(playbook_text)
            
            logger.info("Response playbook generated", 
                       incident_type=incident_type,
                       severity=severity)
            
            return playbook
            
        except Exception as e:
            logger.error("Playbook generation failed", error=str(e))
            return self._get_default_playbook(incident_type, severity)
    
    def _get_default_playbook(self, incident_type: str, severity: str) -> Dict[str, Any]:
        """
        Get default playbook based on incident type and severity
        """
        base_steps = [
            {
                "step_number": 1,
                "title": "Initial Assessment",
                "description": "Assess the incident scope and impact",
                "action_type": "manual",
                "action_details": {},
                "estimated_time": 30,
                "dependencies": [],
                "required_approval": False
            },
            {
                "step_number": 2,
                "title": "Containment",
                "description": "Contain the threat to prevent further damage",
                "action_type": "automated",
                "action_details": {},
                "estimated_time": 15,
                "dependencies": [1],
                "required_approval": True
            },
            {
                "step_number": 3,
                "title": "Investigation",
                "description": "Investigate root cause and affected systems",
                "action_type": "manual",
                "action_details": {},
                "estimated_time": 60,
                "dependencies": [2],
                "required_approval": False
            },
            {
                "step_number": 4,
                "title": "Remediation",
                "description": "Remediate the issue and restore systems",
                "action_type": "manual",
                "action_details": {},
                "estimated_time": 45,
                "dependencies": [3],
                "required_approval": True
            },
            {
                "step_number": 5,
                "title": "Documentation",
                "description": "Document the incident and lessons learned",
                "action_type": "manual",
                "action_details": {},
                "estimated_time": 30,
                "dependencies": [4],
                "required_approval": False
            }
        ]
        
        return {
            "name": f"{incident_type.title()} Response Playbook",
            "description": f"Standard response playbook for {incident_type} incidents",
            "steps": base_steps,
            "estimated_total_time": 180,
            "required_roles": ["analyst", "admin"],
            "automation_opportunities": ["step2"]
        }
    
    async def generate_auto_response(
        self, 
        email_type: str, 
        threat_level: str, 
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Generate automated response for email threats
        """
        try:
            prompt = f"""
            Generate an automated response for a {threat_level} {email_type} email.
            
            Context: {context or 'No additional context provided'}
            
            Please provide response in JSON format:
            {{
                "response_type": "auto_reply|quarantine|delete|forward",
                "subject": "Response subject",
                "message": "Response message content",
                "actions": ["action1", "action2"],
                "notify_user": true,
                "escalate": false
            }}
            """
            
            if not settings.OPENAI_API_KEY:
                return self._get_default_auto_response(email_type, threat_level)
            
            response = await openai.ChatCompletion.acreate(
                model=settings.OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity email response expert."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=500
            )
            
            response_text = response.choices[0].message.content
            auto_response = self._parse_ai_response(response_text)
            
            logger.info("Auto response generated", 
                       email_type=email_type,
                       threat_level=threat_level)
            
            return auto_response
            
        except Exception as e:
            logger.error("Auto response generation failed", error=str(e))
            return self._get_default_auto_response(email_type, threat_level)
    
    def _get_default_auto_response(self, email_type: str, threat_level: str) -> Dict[str, Any]:
        """
        Get default auto response based on email type and threat level
        """
        if threat_level in ["high", "critical"]:
            return {
                "response_type": "quarantine",
                "subject": "Suspicious Email Quarantined",
                "message": "This email has been quarantined due to security concerns.",
                "actions": ["quarantine", "notify_admin"],
                "notify_user": True,
                "escalate": True
            }
        elif threat_level == "medium":
            return {
                "response_type": "auto_reply",
                "subject": "Security Alert - Suspicious Email",
                "message": "This email has been flagged as potentially suspicious.",
                "actions": ["flag", "notify_user"],
                "notify_user": True,
                "escalate": False
            }
        else:
            return {
                "response_type": "monitor",
                "subject": "Email Monitored",
                "message": "This email is being monitored for security purposes.",
                "actions": ["monitor"],
                "notify_user": False,
                "escalate": False
            }

# Create global AI service instance
ai_service = AIService() 