# 🛡️ CyberShield Development Guide

## 🚀 **Getting Started**

Your CyberShield platform is now running with:
- **Frontend**: http://localhost:3000 (React)
- **Backend**: http://localhost:8000 (Python FastAPI)
- **Database**: PostgreSQL in Docker
- **Cache**: Redis in Docker

## 📱 **1. Browse the Frontend**

### **Main Interface (http://localhost:3000)**
- **Dashboard**: Overview of security metrics
- **Navigation**: Access different security modules
- **Components**: Modern React-based UI components

### **Key Frontend Features**
- **Responsive Design**: Works on all screen sizes
- **Real-time Updates**: Live data from backend
- **Interactive Elements**: Charts, forms, and dashboards

## 🔌 **2. Test API Endpoints**

### **Swagger Documentation (http://localhost:8000/docs)**
- **Interactive Testing**: Try endpoints directly in browser
- **Request/Response Examples**: See expected data formats
- **Authentication**: Test with different user roles

### **Available Endpoints**
- **Health Checks**: `/health`, `/api/v1/health`
- **Core API**: `/api/v1/*` endpoints
- **Documentation**: Auto-generated from code

## 🚀 **3. Start Developing**

### **Backend Development (Python)**
```bash
# Location: backend/ folder
# Main file: main-simple.py (simplified version)
# Auto-reload: Enabled by default

# Edit any Python file and save
# Server automatically restarts
```

### **Frontend Development (React)**
```bash
# Location: frontend/ folder
# Main file: src/App.tsx
# Auto-reload: Hot module replacement enabled

# Edit any React component and save
# Browser automatically refreshes
```

### **Database Development**
```bash
# PostgreSQL running in Docker
# Connection: localhost:5432
# Database: cybershield
# User: cybershield_user
# Password: cybershield_password
```

## 🧪 **4. Create Test Data**

### **Using the API**
1. **Open Swagger UI**: http://localhost:8000/docs
2. **Find an endpoint**: Browse available routes
3. **Click "Try it out"**: Test the endpoint
4. **Modify parameters**: Change request data
5. **Execute**: Send the request and see response

### **Example API Calls**
```bash
# Test health endpoint
curl http://localhost:8000/health

# Test root endpoint
curl http://localhost:8000/

# Test API health
curl http://localhost:8000/api/v1/health
```

## 🔧 **Development Workflow**

### **1. Make Changes**
- Edit files in `backend/` or `frontend/src/`
- Save the file
- Watch for auto-reload

### **2. Test Changes**
- Backend: Check terminal for errors
- Frontend: Check browser console
- API: Use Swagger UI to test endpoints

### **3. Debug Issues**
- **Backend Errors**: Check terminal output
- **Frontend Errors**: Check browser console
- **Database Issues**: Check Docker container logs

## 📁 **Project Structure**

```
cyber-cursor/
├── backend/                 # Python FastAPI backend
│   ├── main-simple.py      # Simplified main file
│   ├── app/                # Application modules
│   └── requirements.txt    # Python dependencies
├── frontend/               # React frontend
│   ├── src/                # Source code
│   ├── public/             # Static assets
│   └── package.json        # Node.js dependencies
├── docker-compose.db-only.yml  # Database services
└── scripts/                # Database initialization
```

## 🌐 **Available URLs**

| Service | URL | Purpose |
|---------|-----|---------|
| **Frontend** | http://localhost:3000 | Main application interface |
| **Backend API** | http://localhost:8000 | API root endpoint |
| **API Docs** | http://localhost:8000/docs | Interactive API testing |
| **Health Check** | http://localhost:8000/health | Service status |
| **PostgreSQL** | localhost:5432 | Database |
| **Redis** | localhost:6379 | Cache |

## 🚨 **Troubleshooting**

### **Backend Not Starting**
```bash
cd backend
python main-simple.py
# Check for error messages
```

### **Frontend Not Loading**
```bash
cd frontend
npm start
# Wait for compilation to complete
```

### **Database Connection Issues**
```bash
docker ps
# Check if containers are running
docker logs cybershield-postgres
# Check PostgreSQL logs
```

### **Port Conflicts**
- **8000**: Backend API
- **3000**: Frontend
- **5432**: PostgreSQL
- **6379**: Redis

## 🎯 **Next Steps**

1. **Explore the Frontend**: Navigate through different modules
2. **Test API Endpoints**: Use Swagger UI to understand the backend
3. **Make Small Changes**: Edit files and see auto-reload in action
4. **Build Features**: Add new security modules or enhance existing ones
5. **Test Integration**: Ensure frontend and backend work together

## 📚 **Resources**

- **FastAPI Documentation**: https://fastapi.tiangolo.com/
- **React Documentation**: https://reactjs.org/docs/
- **PostgreSQL Documentation**: https://www.postgresql.org/docs/
- **Docker Documentation**: https://docs.docker.com/

---

**Happy Coding! 🚀 Your CyberShield platform is ready for development!**
