# 🔐 RASP Application Login Guide

## 🚀 **Application Access Information**

The RASP (Runtime Application Self-Protection) application is now running and ready for use!

---

## 📍 **Access URLs**

### **1. API Documentation (Swagger UI)**
- **URL**: http://localhost:8000/docs
- **Description**: Interactive API documentation and testing interface
- **Features**: Test all endpoints directly from the browser

### **2. Alternative API Documentation (ReDoc)**
- **URL**: http://localhost:8000/redoc
- **Description**: Alternative API documentation format

### **3. Health Check**
- **URL**: http://localhost:8000/health
- **Description**: Application health status

---

## 👤 **Available User Accounts**

### **🔑 Admin User (Full Access)**
- **Email**: `admin@cybershield.com`
- **Username**: `admin`
- **Password**: `password`
- **Role**: `admin`
- **Permissions**: Full system access, user management, all features

### **🔑 Security Analyst (Analyst Access)**
- **Email**: `analyst@cybershield.com`
- **Username**: `analyst`
- **Password**: `password`
- **Role**: `analyst`
- **Permissions**: View security data, generate reports, limited admin access

### **🔑 Regular User (Basic Access)**
- **Email**: `user@cybershield.com`
- **Username**: `user`
- **Password**: `password`
- **Role**: `user`
- **Permissions**: Basic dashboard access, view own data

---

## 🔐 **How to Login**

### **Method 1: Using Swagger UI (Recommended)**

1. **Open your web browser**
2. **Navigate to**: http://localhost:8000/docs
3. **Click on the "Authorize" button** (🔒 icon in the top right)
4. **Enter credentials**:
   - **Username**: `admin@cybershield.com` (or any of the emails above)
   - **Password**: `password`
5. **Click "Authorize"**
6. **You're now logged in!** You can test all API endpoints

### **Method 2: Direct API Login**

1. **Open your browser or API client**
2. **Send POST request to**: http://localhost:8000/api/v1/auth/login
3. **Request body** (form data):
   ```
   username: admin@cybershield.com
   password: password
   ```
4. **You'll receive a JWT token** that you can use for authenticated requests

### **Method 3: Using curl**

```bash
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin@cybershield.com&password=password"
```

---

## 🎯 **Key Features to Explore**

### **📊 Dashboard & Analytics**
- **Endpoint**: `GET /api/v1/dashboard/overview`
- **Description**: System overview and metrics
- **Access**: All users

### **🛡️ RASP Security Features**
- **Agents**: `GET /api/v1/rasp/agents`
- **Attacks**: `GET /api/v1/rasp/attacks`
- **Rules**: `GET /api/v1/rasp/rules`
- **Alerts**: `GET /api/v1/rasp/alerts`
- **Dashboard**: `GET /api/v1/rasp/dashboard/overview`

### **👥 User Management (Admin Only)**
- **Users**: `GET /api/v1/users`
- **User Profile**: `GET /api/v1/auth/me`
- **Create User**: `POST /api/v1/users`

### **🔧 System Administration**
- **System Health**: `GET /api/v1/admin/health`
- **Admin Dashboard**: `GET /api/v1/admin/dashboard`
- **User Management**: `GET /api/v1/admin/users`

---

## 🚨 **Troubleshooting**

### **If you can't access the application:**

1. **Check if the server is running**:
   ```bash
   curl http://localhost:8000/health
   ```

2. **Verify the port is not blocked**:
   - Check if port 8000 is available
   - Ensure no firewall is blocking the connection

3. **Check server logs**:
   - Look for any error messages in the terminal where you started the server

### **If login fails:**

1. **Verify credentials**:
   - Use exactly: `admin@cybershield.com` / `password`
   - Check for typos in email or password

2. **Clear browser cache**:
   - Clear cookies and cache for localhost:8000

3. **Try different browser**:
   - Sometimes browser extensions can interfere

### **If you get CORS errors:**

1. **Check browser console** for CORS-related errors
2. **Try using the Swagger UI** at http://localhost:8000/docs
3. **Use a different browser** or incognito mode

---

## 📱 **API Testing Examples**

### **Get System Overview (No Auth Required)**
```bash
curl http://localhost:8000/api/v1/dashboard/overview
```

### **Login and Get Token**
```bash
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin@cybershield.com&password=password"
```

### **Use Token for Authenticated Request**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  http://localhost:8000/api/v1/auth/me
```

---

## 🎉 **Success Indicators**

When you successfully log in, you should see:

1. **Swagger UI**: The "Authorize" button shows you're logged in
2. **API Response**: You get a JWT token with user information
3. **Access**: You can now access protected endpoints
4. **User Info**: Your user profile shows your role and permissions

---

## 🔒 **Security Notes**

- **These are demo credentials** - change them in production
- **JWT tokens expire** after 30 minutes by default
- **Use HTTPS** in production environments
- **Implement proper password policies** for production use

---

## 📞 **Need Help?**

If you're still having trouble:

1. **Check the server logs** for error messages
2. **Verify the backend is running** on port 8000
3. **Try the health check endpoint**: http://localhost:8000/health
4. **Review the API documentation**: http://localhost:8000/docs

**🎯 You should now be able to successfully log into the RASP application!** 