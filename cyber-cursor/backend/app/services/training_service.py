import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import and_

from app.core.config import settings
from app.models.user import User
from app.services.notification_service import notification_service

logger = structlog.get_logger()

class TrainingService:
    def __init__(self):
        self.training_modules = self._get_default_modules()
        self.quiz_questions = self._get_default_quiz_questions()
    
    def _get_default_modules(self) -> List[Dict[str, Any]]:
        """Get default training modules"""
        return [
            {
                "id": 1,
                "title": "Phishing Awareness",
                "description": "Learn to identify and avoid phishing attacks",
                "category": "Email Security",
                "duration": 15,
                "difficulty": "Beginner",
                "content": {
                    "sections": [
                        {
                            "title": "What is Phishing?",
                            "content": "Phishing is a cyber attack that uses disguised email as a weapon. The goal is to trick the email recipient into believing that the message is something they want or need.",
                            "type": "text"
                        },
                        {
                            "title": "Common Phishing Indicators",
                            "content": "Look for urgent language, suspicious sender addresses, unexpected attachments, and requests for sensitive information.",
                            "type": "text"
                        },
                        {
                            "title": "How to Respond",
                            "content": "Never click suspicious links, verify sender addresses, report suspicious emails to IT, and use official channels for verification.",
                            "type": "text"
                        }
                    ]
                },
                "quiz_questions": [1, 2, 3, 4, 5],
                "passing_score": 80,
                "certificate_template": "phishing_awareness_certificate"
            },
            {
                "id": 2,
                "title": "Password Security",
                "description": "Best practices for creating and managing strong passwords",
                "category": "Account Security",
                "duration": 10,
                "difficulty": "Beginner",
                "content": {
                    "sections": [
                        {
                            "title": "Strong Password Requirements",
                            "content": "Use at least 12 characters, include uppercase, lowercase, numbers, and special characters. Avoid personal information.",
                            "type": "text"
                        },
                        {
                            "title": "Password Managers",
                            "content": "Use a reputable password manager to generate and store unique passwords for each account.",
                            "type": "text"
                        },
                        {
                            "title": "Two-Factor Authentication",
                            "content": "Enable 2FA on all accounts, especially for banking, email, and social media.",
                            "type": "text"
                        }
                    ]
                },
                "quiz_questions": [6, 7, 8, 9, 10],
                "passing_score": 80,
                "certificate_template": "password_security_certificate"
            },
            {
                "id": 3,
                "title": "Social Engineering",
                "description": "Recognize and defend against social engineering attacks",
                "category": "Human Security",
                "duration": 20,
                "difficulty": "Intermediate",
                "content": {
                    "sections": [
                        {
                            "title": "Types of Social Engineering",
                            "content": "Pretexting, baiting, quid pro quo, tailgating, and phishing are common social engineering techniques.",
                            "type": "text"
                        },
                        {
                            "title": "Psychological Manipulation",
                            "content": "Attackers use authority, urgency, scarcity, and social proof to manipulate victims.",
                            "type": "text"
                        },
                        {
                            "title": "Defense Strategies",
                            "content": "Verify identities, question unusual requests, follow security procedures, and report suspicious activities.",
                            "type": "text"
                        }
                    ]
                },
                "quiz_questions": [11, 12, 13, 14, 15],
                "passing_score": 85,
                "certificate_template": "social_engineering_certificate"
            },
            {
                "id": 4,
                "title": "Data Protection",
                "description": "Understanding data classification and protection",
                "category": "Data Security",
                "duration": 25,
                "difficulty": "Intermediate",
                "content": {
                    "sections": [
                        {
                            "title": "Data Classification",
                            "content": "Public, internal, confidential, and restricted data require different levels of protection.",
                            "type": "text"
                        },
                        {
                            "title": "Data Handling Procedures",
                            "content": "Follow proper procedures for storing, transmitting, and disposing of sensitive data.",
                            "type": "text"
                        },
                        {
                            "title": "Data Breach Response",
                            "content": "Know how to respond to data breaches, including notification procedures and containment measures.",
                            "type": "text"
                        }
                    ]
                },
                "quiz_questions": [16, 17, 18, 19, 20],
                "passing_score": 85,
                "certificate_template": "data_protection_certificate"
            }
        ]
    
    def _get_default_quiz_questions(self) -> List[Dict[str, Any]]:
        """Get default quiz questions"""
        return [
            # Phishing Awareness Questions
            {
                "id": 1,
                "question": "What is the most common indicator of a phishing email?",
                "options": [
                    "Urgent language demanding immediate action",
                    "Professional company logo",
                    "Correct spelling and grammar",
                    "Familiar sender name"
                ],
                "correct_answer": 0,
                "explanation": "Phishing emails often use urgent language to create panic and pressure victims into acting quickly without thinking."
            },
            {
                "id": 2,
                "question": "What should you do if you receive a suspicious email?",
                "options": [
                    "Click on any links to verify",
                    "Reply with your personal information",
                    "Forward to IT security team",
                    "Delete immediately without reporting"
                ],
                "correct_answer": 2,
                "explanation": "Always forward suspicious emails to your IT security team for investigation."
            },
            {
                "id": 3,
                "question": "Which of the following is NOT a red flag for phishing?",
                "options": [
                    "Generic greeting",
                    "Suspicious sender address",
                    "Request for sensitive information",
                    "Professional formatting"
                ],
                "correct_answer": 3,
                "explanation": "Professional formatting is not a red flag, but generic greetings, suspicious addresses, and requests for sensitive info are."
            },
            {
                "id": 4,
                "question": "What should you do before clicking a link in an email?",
                "options": [
                    "Click immediately if it looks legitimate",
                    "Hover over the link to see the actual URL",
                    "Forward to all colleagues",
                    "Reply to the sender for verification"
                ],
                "correct_answer": 1,
                "explanation": "Always hover over links to see the actual destination URL before clicking."
            },
            {
                "id": 5,
                "question": "Which email address format is most suspicious?",
                "options": [
                    "support@company.com",
                    "security@company.com",
                    "support@company-secure.net",
                    "help@company.com"
                ],
                "correct_answer": 2,
                "explanation": "The domain 'company-secure.net' is suspicious as it's not the company's official domain."
            },
            # Password Security Questions
            {
                "id": 6,
                "question": "What is the minimum recommended password length?",
                "options": [
                    "8 characters",
                    "10 characters",
                    "12 characters",
                    "16 characters"
                ],
                "correct_answer": 2,
                "explanation": "A minimum of 12 characters is recommended for strong passwords."
            },
            {
                "id": 7,
                "question": "Which of the following makes the strongest password?",
                "options": [
                    "Password123",
                    "MyDogSpot2023",
                    "K9#mP$2xL@qR8vN",
                    "ILoveMyJob2023"
                ],
                "correct_answer": 2,
                "explanation": "Random characters with mixed case, numbers, and symbols make the strongest passwords."
            },
            {
                "id": 8,
                "question": "What should you do if you suspect your password has been compromised?",
                "options": [
                    "Wait and see if anything happens",
                    "Change it immediately",
                    "Tell only close friends",
                    "Ignore the warning signs"
                ],
                "correct_answer": 1,
                "explanation": "Change compromised passwords immediately to prevent unauthorized access."
            },
            {
                "id": 9,
                "question": "Which authentication method is most secure?",
                "options": [
                    "Password only",
                    "Password + SMS",
                    "Password + authenticator app",
                    "Password + email"
                ],
                "correct_answer": 2,
                "explanation": "Authenticator apps are more secure than SMS or email for 2FA."
            },
            {
                "id": 10,
                "question": "How often should you change your passwords?",
                "options": [
                    "Never",
                    "Every 30 days",
                    "Every 90 days",
                    "Only when compromised"
                ],
                "correct_answer": 3,
                "explanation": "Change passwords when compromised, not on a fixed schedule."
            }
        ]
    
    async def get_user_training_progress(self, db: AsyncSession, user_id: int) -> Dict[str, Any]:
        """Get user's training progress"""
        try:
            # In a real implementation, this would query a training_progress table
            # For now, return mock data
            completed_modules = 2  # Mock data
            total_modules = len(self.training_modules)
            overall_score = 85  # Mock data
            
            return {
                "completed_modules": completed_modules,
                "total_modules": total_modules,
                "overall_score": overall_score,
                "completion_percentage": round((completed_modules / total_modules) * 100, 1),
                "next_training": (datetime.utcnow() + timedelta(days=7)).isoformat(),
                "last_completed": (datetime.utcnow() - timedelta(days=3)).isoformat()
            }
        except Exception as e:
            logger.error("Error getting training progress", error=str(e), user_id=user_id)
            return {
                "completed_modules": 0,
                "total_modules": len(self.training_modules),
                "overall_score": 0,
                "completion_percentage": 0,
                "next_training": (datetime.utcnow() + timedelta(days=7)).isoformat(),
                "last_completed": None
            }
    
    async def get_training_modules(self, db: AsyncSession, user_id: int) -> List[Dict[str, Any]]:
        """Get all training modules with user progress"""
        try:
            user_progress = await self.get_user_training_progress(db, user_id)
            
            modules_with_progress = []
            for module in self.training_modules:
                # Mock progress data - in real implementation, query training_progress table
                is_completed = module["id"] <= user_progress["completed_modules"]
                user_score = 95 if is_completed else 0
                
                modules_with_progress.append({
                    **module,
                    "is_completed": is_completed,
                    "user_score": user_score,
                    "completion_date": (datetime.utcnow() - timedelta(days=module["id"] * 2)).isoformat() if is_completed else None
                })
            
            return modules_with_progress
        except Exception as e:
            logger.error("Error getting training modules", error=str(e), user_id=user_id)
            return []
    
    async def get_module_content(self, module_id: int) -> Optional[Dict[str, Any]]:
        """Get specific module content"""
        try:
            module = next((m for m in self.training_modules if m["id"] == module_id), None)
            return module
        except Exception as e:
            logger.error("Error getting module content", error=str(e), module_id=module_id)
            return None
    
    async def get_module_quiz(self, module_id: int) -> List[Dict[str, Any]]:
        """Get quiz questions for a specific module"""
        try:
            module = next((m for m in self.training_modules if m["id"] == module_id), None)
            if not module:
                return []
            
            quiz_questions = []
            for question_id in module.get("quiz_questions", []):
                question = next((q for q in self.quiz_questions if q["id"] == question_id), None)
                if question:
                    # Remove correct answer for quiz display
                    quiz_question = {
                        "id": question["id"],
                        "question": question["question"],
                        "options": question["options"]
                    }
                    quiz_questions.append(quiz_question)
            
            return quiz_questions
        except Exception as e:
            logger.error("Error getting module quiz", error=str(e), module_id=module_id)
            return []
    
    async def grade_quiz(self, module_id: int, user_answers: List[int]) -> Dict[str, Any]:
        """Grade a quiz and return results"""
        try:
            module = next((m for m in self.training_modules if m["id"] == module_id), None)
            if not module:
                return {"error": "Module not found"}
            
            correct_answers = 0
            total_questions = len(module.get("quiz_questions", []))
            detailed_results = []
            
            for i, question_id in enumerate(module.get("quiz_questions", [])):
                question = next((q for q in self.quiz_questions if q["id"] == question_id), None)
                if question and i < len(user_answers):
                    is_correct = user_answers[i] == question["correct_answer"]
                    if is_correct:
                        correct_answers += 1
                    
                    detailed_results.append({
                        "question": question["question"],
                        "user_answer": question["options"][user_answers[i]] if i < len(user_answers) else "Not answered",
                        "correct_answer": question["options"][question["correct_answer"]],
                        "is_correct": is_correct,
                        "explanation": question["explanation"]
                    })
            
            score = round((correct_answers / total_questions) * 100) if total_questions > 0 else 0
            passed = score >= module.get("passing_score", 80)
            
            return {
                "score": score,
                "passed": passed,
                "correct_answers": correct_answers,
                "total_questions": total_questions,
                "passing_score": module.get("passing_score", 80),
                "detailed_results": detailed_results,
                "certificate_eligible": passed
            }
        except Exception as e:
            logger.error("Error grading quiz", error=str(e), module_id=module_id)
            return {"error": "Failed to grade quiz"}
    
    async def complete_module(self, db: AsyncSession, user_id: int, module_id: int, score: int) -> Dict[str, Any]:
        """Mark a module as completed for a user"""
        try:
            # In a real implementation, this would update the training_progress table
            module = next((m for m in self.training_modules if m["id"] == module_id), None)
            if not module:
                return {"error": "Module not found"}
            
            passed = score >= module.get("passing_score", 80)
            
            # Send notification
            if passed:
                await notification_service.send_training_reminder(
                    user_id, 
                    f"Congratulations! You've completed '{module['title']}' with a score of {score}%"
                )
            
            # Generate certificate if passed
            certificate_url = None
            if passed:
                certificate_url = await self.generate_certificate(user_id, module_id, score)
            
            logger.info("Module completed", 
                       user_id=user_id, 
                       module_id=module_id, 
                       score=score, 
                       passed=passed)
            
            return {
                "success": True,
                "module_id": module_id,
                "score": score,
                "passed": passed,
                "certificate_url": certificate_url,
                "completion_date": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error("Error completing module", error=str(e), user_id=user_id, module_id=module_id)
            return {"error": "Failed to complete module"}
    
    async def generate_certificate(self, user_id: int, module_id: int, score: int) -> Optional[str]:
        """Generate a completion certificate"""
        try:
            # In a real implementation, this would generate a PDF certificate
            # For now, return a mock certificate URL
            certificate_id = f"cert_{user_id}_{module_id}_{datetime.utcnow().strftime('%Y%m%d')}"
            return f"/certificates/{certificate_id}.pdf"
        except Exception as e:
            logger.error("Error generating certificate", error=str(e), user_id=user_id, module_id=module_id)
            return None
    
    async def get_user_certificates(self, db: AsyncSession, user_id: int) -> List[Dict[str, Any]]:
        """Get user's training certificates"""
        try:
            # In a real implementation, this would query a certificates table
            # For now, return mock data
            return [
                {
                    "id": 1,
                    "module_title": "Phishing Awareness",
                    "completion_date": (datetime.utcnow() - timedelta(days=5)).isoformat(),
                    "score": 95,
                    "certificate_url": "/certificates/cert_1_1_20240110.pdf"
                },
                {
                    "id": 2,
                    "module_title": "Password Security",
                    "completion_date": (datetime.utcnow() - timedelta(days=3)).isoformat(),
                    "score": 88,
                    "certificate_url": "/certificates/cert_1_2_20240112.pdf"
                }
            ]
        except Exception as e:
            logger.error("Error getting user certificates", error=str(e), user_id=user_id)
            return []
    
    async def send_training_reminders(self, db: AsyncSession) -> None:
        """Send training reminders to users who haven't completed modules"""
        try:
            # In a real implementation, this would query users who need reminders
            # For now, this is a placeholder
            logger.info("Training reminders sent")
        except Exception as e:
            logger.error("Error sending training reminders", error=str(e))

# Global training service instance
training_service = TrainingService() 