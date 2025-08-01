import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';

interface TrainingModule {
  id: number;
  title: string;
  description: string;
  category: string;
  duration: number;
  difficulty: string;
  completed: boolean;
  score: number;
  content: string;
  quiz: QuizQuestion[];
}

interface QuizQuestion {
  id: number;
  question: string;
  options: string[];
  correct_answer: number;
  explanation: string;
}

const SecurityTraining: React.FC = () => {
  const { user } = useAuth();
  const [modules, setModules] = useState<TrainingModule[]>([]);
  const [selectedModule, setSelectedModule] = useState<TrainingModule | null>(null);
  const [currentQuiz, setCurrentQuiz] = useState<QuizQuestion[]>([]);
  const [currentQuestion, setCurrentQuestion] = useState(0);
  const [userAnswers, setUserAnswers] = useState<number[]>([]);
  const [showQuiz, setShowQuiz] = useState(false);
  const [quizCompleted, setQuizCompleted] = useState(false);
  const [loading, setLoading] = useState(true);

  const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

  useEffect(() => {
    fetchTrainingModules();
  }, []);

  const fetchTrainingModules = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('access_token');
      
      const response = await fetch(`${API_URL}/api/v1/user/training`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error('Failed to fetch training modules');
      }

      const data = await response.json();
      setModules(data.modules || getMockModules());
    } catch (err) {
      console.error('Error fetching training modules:', err);
      setModules(getMockModules());
    } finally {
      setLoading(false);
    }
  };

  const getMockModules = (): TrainingModule[] => [
    {
      id: 1,
      title: "Phishing Awareness",
      description: "Learn to identify and avoid phishing attacks",
      category: "Email Security",
      duration: 15,
      difficulty: "Beginner",
      completed: true,
      score: 95,
      content: "Phishing is a cyber attack that uses disguised email as a weapon. The goal is to trick the email recipient into believing that the message is something they want or need...",
      quiz: [
        {
          id: 1,
          question: "What is the most common indicator of a phishing email?",
          options: [
            "Urgent language demanding immediate action",
            "Professional company logo",
            "Correct spelling and grammar",
            "Familiar sender name"
          ],
          correct_answer: 0,
          explanation: "Phishing emails often use urgent language to create panic and pressure victims into acting quickly without thinking."
        },
        {
          id: 2,
          question: "What should you do if you receive a suspicious email?",
          options: [
            "Click on any links to verify",
            "Reply with your personal information",
            "Forward to IT security team",
            "Delete immediately without reporting"
          ],
          correct_answer: 2,
          explanation: "Always forward suspicious emails to your IT security team for investigation."
        }
      ]
    },
    {
      id: 2,
      title: "Password Security",
      description: "Best practices for creating and managing strong passwords",
      category: "Account Security",
      duration: 10,
      difficulty: "Beginner",
      completed: true,
      score: 88,
      content: "Strong passwords are your first line of defense against unauthorized access to your accounts...",
      quiz: []
    },
    {
      id: 3,
      title: "Social Engineering",
      description: "Recognize and defend against social engineering attacks",
      category: "Human Security",
      duration: 20,
      difficulty: "Intermediate",
      completed: false,
      score: 0,
      content: "Social engineering is the art of manipulating people to give up confidential information...",
      quiz: []
    },
    {
      id: 4,
      title: "Data Protection",
      description: "Understanding data classification and protection",
      category: "Data Security",
      duration: 25,
      difficulty: "Intermediate",
      completed: false,
      score: 0,
      content: "Data protection involves safeguarding important information from corruption, compromise, or loss...",
      quiz: []
    }
  ];

  const startModule = (module: TrainingModule) => {
    setSelectedModule(module);
    setShowQuiz(false);
    setQuizCompleted(false);
    setCurrentQuestion(0);
    setUserAnswers([]);
  };

  const startQuiz = () => {
    if (selectedModule) {
      setCurrentQuiz(selectedModule.quiz);
      setShowQuiz(true);
      setCurrentQuestion(0);
      setUserAnswers([]);
    }
  };

  const handleAnswerSelect = (answerIndex: number) => {
    const newAnswers = [...userAnswers];
    newAnswers[currentQuestion] = answerIndex;
    setUserAnswers(newAnswers);
  };

  const nextQuestion = () => {
    if (currentQuestion < currentQuiz.length - 1) {
      setCurrentQuestion(currentQuestion + 1);
    } else {
      completeQuiz();
    }
  };

  const completeQuiz = async () => {
    const correctAnswers = userAnswers.filter((answer, index) => 
      answer === currentQuiz[index].correct_answer
    ).length;
    
    const score = Math.round((correctAnswers / currentQuiz.length) * 100);
    
    try {
      const token = localStorage.getItem('access_token');
      await fetch(`${API_URL}/api/v1/user/training/${selectedModule?.id}/complete`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ score }),
      });
      
      setQuizCompleted(true);
      fetchTrainingModules(); // Refresh modules
    } catch (error) {
      console.error('Error completing quiz:', error);
    }
  };

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty.toLowerCase()) {
      case 'beginner': return 'text-green-400 bg-green-900/20';
      case 'intermediate': return 'text-yellow-400 bg-yellow-900/20';
      case 'advanced': return 'text-red-400 bg-red-900/20';
      default: return 'text-gray-400 bg-gray-900/20';
    }
  };

  const getProgressPercentage = () => {
    const completed = modules.filter(m => m.completed).length;
    return Math.round((completed / modules.length) * 100);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyber-accent"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-blue-900/20 to-purple-900/20 border border-cyber-accent/30 rounded-lg p-6">
        <h1 className="text-3xl font-bold text-white mb-2">📚 Security Training</h1>
        <p className="text-gray-400">
          Complete security awareness training modules to improve your cybersecurity knowledge.
        </p>
      </div>

      {/* Progress Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-4">
          <div className="text-2xl font-bold text-white">{modules.length}</div>
          <div className="text-gray-400">Total Modules</div>
        </div>
        <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-4">
          <div className="text-2xl font-bold text-green-400">
            {modules.filter(m => m.completed).length}
          </div>
          <div className="text-gray-400">Completed</div>
        </div>
        <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-4">
          <div className="text-2xl font-bold text-blue-400">{getProgressPercentage()}%</div>
          <div className="text-gray-400">Progress</div>
        </div>
        <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-4">
          <div className="text-2xl font-bold text-purple-400">
            {Math.round(modules.reduce((acc, m) => acc + m.score, 0) / modules.filter(m => m.completed).length) || 0}
          </div>
          <div className="text-gray-400">Avg Score</div>
        </div>
      </div>

      {/* Progress Bar */}
      <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-4">
        <div className="flex justify-between items-center mb-2">
          <span className="text-white font-medium">Overall Progress</span>
          <span className="text-gray-400">{getProgressPercentage()}%</span>
        </div>
        <div className="w-full bg-cyber-dark rounded-full h-2">
          <div 
            className="bg-gradient-to-r from-blue-500 to-purple-500 h-2 rounded-full transition-all duration-300"
            style={{ width: `${getProgressPercentage()}%` }}
          ></div>
        </div>
      </div>

      {!selectedModule && !showQuiz && (
        /* Module List */
        <div className="space-y-4">
          <h2 className="text-xl font-semibold text-white">Available Modules</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {modules.map((module) => (
              <div key={module.id} className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-6 hover:border-cyber-accent/50 transition-colors">
                <div className="flex items-start justify-between mb-4">
                  <div>
                    <h3 className="text-lg font-semibold text-white mb-2">{module.title}</h3>
                    <p className="text-gray-400 text-sm mb-3">{module.description}</p>
                    <div className="flex items-center space-x-4 text-sm">
                      <span className="text-gray-400">{module.category}</span>
                      <span className="text-gray-400">•</span>
                      <span className="text-gray-400">{module.duration} min</span>
                      <span className="text-gray-400">•</span>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getDifficultyColor(module.difficulty)}`}>
                        {module.difficulty}
                      </span>
                    </div>
                  </div>
                  <div className="text-right">
                    {module.completed ? (
                      <div className="text-green-400 text-sm font-medium">✓ Completed</div>
                    ) : (
                      <div className="text-orange-400 text-sm font-medium">⏳ Pending</div>
                    )}
                    {module.completed && (
                      <div className="text-blue-400 text-sm">{module.score}%</div>
                    )}
                  </div>
                </div>
                
                <div className="flex space-x-3">
                  <button
                    onClick={() => startModule(module)}
                    className="bg-cyber-accent hover:bg-cyber-accent/80 text-white px-4 py-2 rounded-lg transition-colors"
                  >
                    {module.completed ? 'Review' : 'Start'}
                  </button>
                  {module.completed && module.quiz.length > 0 && (
                    <button
                      onClick={() => { setSelectedModule(module); startQuiz(); }}
                      className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors"
                    >
                      Retake Quiz
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {selectedModule && !showQuiz && (
        /* Module Content */
        <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-2xl font-bold text-white">{selectedModule.title}</h2>
            <button
              onClick={() => setSelectedModule(null)}
              className="text-gray-400 hover:text-white"
            >
              ✕
            </button>
          </div>
          
          <div className="prose prose-invert max-w-none mb-6">
            <p className="text-gray-300 leading-relaxed">{selectedModule.content}</p>
          </div>
          
          <div className="flex space-x-4">
            <button
              onClick={() => setSelectedModule(null)}
              className="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-lg transition-colors"
            >
              Back to Modules
            </button>
            {selectedModule.quiz.length > 0 && (
              <button
                onClick={startQuiz}
                className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors"
              >
                Take Quiz
              </button>
            )}
          </div>
        </div>
      )}

      {showQuiz && currentQuiz.length > 0 && !quizCompleted && (
        /* Quiz Interface */
        <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-2xl font-bold text-white">Quiz: {selectedModule?.title}</h2>
            <div className="text-gray-400">
              Question {currentQuestion + 1} of {currentQuiz.length}
            </div>
          </div>
          
          <div className="mb-6">
            <h3 className="text-lg font-semibold text-white mb-4">
              {currentQuiz[currentQuestion].question}
            </h3>
            
            <div className="space-y-3">
              {currentQuiz[currentQuestion].options.map((option, index) => (
                <button
                  key={index}
                  onClick={() => handleAnswerSelect(index)}
                  className={`w-full text-left p-4 rounded-lg border transition-colors ${
                    userAnswers[currentQuestion] === index
                      ? 'border-cyber-accent bg-cyber-accent/20 text-white'
                      : 'border-cyber-accent/30 text-gray-300 hover:border-cyber-accent/50'
                  }`}
                >
                  {option}
                </button>
              ))}
            </div>
          </div>
          
          <div className="flex justify-between">
            <button
              onClick={() => setShowQuiz(false)}
              className="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-lg transition-colors"
            >
              Cancel Quiz
            </button>
            <button
              onClick={nextQuestion}
              disabled={userAnswers[currentQuestion] === undefined}
              className="bg-cyber-accent hover:bg-cyber-accent/80 disabled:bg-gray-600 text-white px-4 py-2 rounded-lg transition-colors"
            >
              {currentQuestion === currentQuiz.length - 1 ? 'Finish Quiz' : 'Next Question'}
            </button>
          </div>
        </div>
      )}

      {quizCompleted && (
        /* Quiz Results */
        <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-6 text-center">
          <div className="text-green-400 text-6xl mb-4">🎉</div>
          <h2 className="text-2xl font-bold text-white mb-4">Quiz Completed!</h2>
          <p className="text-gray-400 mb-6">
            Great job completing the quiz. Your progress has been saved.
          </p>
          
          <div className="flex justify-center space-x-4">
            <button
              onClick={() => { setShowQuiz(false); setSelectedModule(null); }}
              className="bg-cyber-accent hover:bg-cyber-accent/80 text-white px-6 py-2 rounded-lg transition-colors"
            >
              Back to Modules
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default SecurityTraining; 