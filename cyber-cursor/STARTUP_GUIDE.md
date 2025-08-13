# 🚀 CyberShield Startup Guide

## ✅ **Backend Status: READY**
The `main_unified.py` file is working correctly and all dependencies are installed.

## 🎯 **Step-by-Step Startup Instructions**

### **1. Start Backend (Terminal 1)**
```bash
# Navigate to backend directory
cd backend

# Activate virtual environment (if using one)
# On Windows:
. venv/Scripts/Activate.ps1

# Start the backend
python main_unified.py
```

**Expected Output:**
```
🚀 Starting CyberShield Unified Backend...
📚 API Documentation: http://localhost:8000/docs
🔍 ReDoc Documentation: http://localhost:8000/redoc
🌐 Health Check: http://localhost:8000/health
INFO: Uvicorn running on http://0.0.0.0:8000
```

### **2. Start Frontend (Terminal 2)**
```bash
# Navigate to frontend directory
cd frontend

# Install dependencies (if not already done)
npm install

# Start the React application
npm start
```

**Expected Output:**
```
Compiled successfully!
Local: http://localhost:3000
```

### **3. Verify Services Are Running**

#### **Backend Health Check:**
```bash
curl http://localhost:8000/health
```

#### **Frontend Check:**
Open browser and navigate to: `http://localhost:3000`

## 🔗 **Available Endpoints**

Once the backend is running, you can access:

- **API Documentation**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health
- **Authentication**: http://localhost:8000/api/v1/auth/*
- **User Management**: http://localhost:8000/api/v1/users/*
- **DAST**: http://localhost:8000/api/v1/dast/*
- **RASP**: http://localhost:8000/api/v1/rasp/*
- **Cloud Security**: http://localhost:8000/api/v1/cloud-security/*
- **Network Security**: http://localhost:8000/api/v1/network-security/*
- **Data Security**: http://localhost:8000/api/v1/data-security/*
- **Endpoint Security**: http://localhost:8000/api/v1/endpoint-antivirus-edr/*
- **Device Control**: http://localhost:8000/api/v1/device-control/*
- **Data Protection**: http://localhost:8000/api/v1/data-protection/*
- **Security Operations**: http://localhost:8000/api/v1/security/*
- **Monitoring**: http://localhost:8000/api/v1/monitoring/*
- **SIEM/SOAR**: http://localhost:8000/api/v1/siem-soar/*

## 🎨 **Integration Dashboard**

Once both services are running, you can access the **Backend Integration Status Dashboard** at:

`http://localhost:3000/integration-status`

This dashboard will show:
- ✅ Real-time status of all 15 backend endpoints
- 📊 Connection statistics and response times
- 🔍 Individual endpoint testing capabilities
- 📈 Overall system health status

## 🧪 **Testing the Integration**

### **1. Test Backend Health:**
```bash
curl http://localhost:8000/health
```

### **2. Test Authentication Endpoint:**
```bash
curl http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "test", "password": "test"}'
```

### **3. Test Frontend-Backend Connection:**
- Open http://localhost:3000 in your browser
- Navigate to the Integration Status Dashboard
- Verify all endpoints show as "connected"

## 🚨 **Troubleshooting**

### **Backend Won't Start:**
- Check if port 8000 is already in use
- Verify all dependencies are installed: `pip install -r requirements_unified.txt`
- Check database connection settings

### **Frontend Won't Start:**
- Check if port 3000 is already in use
- Verify Node.js and npm are installed
- Run `npm install` to install dependencies

### **Connection Issues:**
- Verify both services are running on correct ports
- Check CORS settings in backend
- Verify environment variables in frontend `.env.local`

## 🎉 **Success Indicators**

You'll know everything is working when:

1. ✅ Backend shows: "Uvicorn running on http://0.0.0.0:8000"
2. ✅ Frontend shows: "Compiled successfully!" and opens in browser
3. ✅ Integration Dashboard shows all endpoints as "connected"
4. ✅ API calls return proper responses instead of connection errors

## 🔧 **Next Steps After Startup**

1. **Test Individual Services**: Use the frontend to test each security service
2. **Monitor Performance**: Use the integration dashboard to track response times
3. **Explore Features**: Navigate through DAST, RASP, Cloud Security, etc.
4. **Create Test Data**: Set up sample projects and security scans

---

*The CyberShield platform is ready for full cybersecurity operations! 🛡️*
