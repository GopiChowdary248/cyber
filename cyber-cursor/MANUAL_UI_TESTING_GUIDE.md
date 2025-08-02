# Manual UI Testing Guide - Login/Logout Functionality

## 🎯 Testing Overview

This guide will help you manually test the login and logout functionality through the user interface. The application is currently running and accessible.

## 🌐 Application Access

- **Frontend URL**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs

## 📋 Pre-Test Checklist

- ✅ Application is running (confirmed)
- ✅ Backend is healthy (confirmed)
- ✅ Frontend is accessible (confirmed)
- ✅ Demo accounts are available

## 🔑 Demo Accounts for Testing

| Email | Password | Role | Purpose |
|-------|----------|------|---------|
| `admin@cybershield.com` | `password` | Admin | Full system access |
| `analyst@cybershield.com` | `password` | Analyst | Security analyst access |
| `user@cybershield.com` | `password` | User | Standard user access |

## 🧪 Test Scenarios

### Test Scenario 1: Basic Login Flow

#### Steps:
1. **Open Browser**: Navigate to http://localhost:3000
2. **Verify Landing Page**: Should see the CyberShield login page
3. **Test Admin Login**:
   - Enter: `admin@cybershield.com`
   - Enter: `password`
   - Click "Sign In"
4. **Expected Result**: 
   - Success message appears
   - Redirected to dashboard
   - User information displayed

#### Test Cases:
- [ ] Login page loads correctly
- [ ] Form validation works
- [ ] Admin login succeeds
- [ ] Redirect to dashboard works
- [ ] User role is displayed correctly

### Test Scenario 2: Multiple User Roles

#### Steps:
1. **Logout** (if logged in)
2. **Test Analyst Login**:
   - Enter: `analyst@cybershield.com`
   - Enter: `password`
   - Click "Sign In"
3. **Verify Role**: Check if analyst role is displayed
4. **Logout**
5. **Test User Login**:
   - Enter: `user@cybershield.com`
   - Enter: `password`
   - Click "Sign In"
6. **Verify Role**: Check if user role is displayed

#### Test Cases:
- [ ] Analyst login works
- [ ] User login works
- [ ] Role-based access works
- [ ] Different dashboards for different roles

### Test Scenario 3: Invalid Credentials

#### Steps:
1. **Test Invalid Email**:
   - Enter: `invalid@example.com`
   - Enter: `password`
   - Click "Sign In"
2. **Expected Result**: Error message appears
3. **Test Invalid Password**:
   - Enter: `admin@cybershield.com`
   - Enter: `wrongpassword`
   - Click "Sign In"
4. **Expected Result**: Error message appears

#### Test Cases:
- [ ] Invalid email shows error
- [ ] Invalid password shows error
- [ ] Error messages are clear
- [ ] Form doesn't submit with invalid data

### Test Scenario 4: Demo Login Buttons

#### Steps:
1. **Navigate to Login Page**
2. **Test Admin Demo Button**:
   - Click "Admin Demo" button
   - Verify auto-fill works
   - Click "Sign In"
3. **Test User Demo Button**:
   - Click "User Demo" button
   - Verify auto-fill works
   - Click "Sign In"

#### Test Cases:
- [ ] Demo buttons are visible
- [ ] Auto-fill works correctly
- [ ] Demo login succeeds
- [ ] Quick access is convenient

### Test Scenario 5: Logout Functionality

#### Steps:
1. **Login as Admin**
2. **Navigate to Dashboard**
3. **Find Logout Option**:
   - Look for logout button in navigation
   - Or user menu dropdown
4. **Click Logout**
5. **Verify Logout**:
   - Should be redirected to login page
   - Session should be cleared
   - Can't access protected pages

#### Test Cases:
- [ ] Logout button is accessible
- [ ] Logout works correctly
- [ ] Session is cleared
- [ ] Redirect to login page
- [ ] Protected pages are inaccessible

### Test Scenario 6: Session Persistence

#### Steps:
1. **Login as Admin**
2. **Close Browser Tab** (don't logout)
3. **Open New Tab**
4. **Navigate to**: http://localhost:3000
5. **Expected Result**: Should be logged in automatically

#### Test Cases:
- [ ] Session persists across tabs
- [ ] No need to re-login
- [ ] User data is maintained

### Test Scenario 7: Form Validation

#### Steps:
1. **Test Empty Fields**:
   - Leave email empty, enter password
   - Click "Sign In"
   - Expected: Validation error
2. **Test Invalid Email Format**:
   - Enter: `invalid-email`
   - Enter: `password`
   - Click "Sign In"
   - Expected: Email format error
3. **Test Short Password**:
   - Enter: `admin@cybershield.com`
   - Enter: `123`
   - Click "Sign In"
   - Expected: Password validation error

#### Test Cases:
- [ ] Empty field validation
- [ ] Email format validation
- [ ] Password length validation
- [ ] Real-time validation feedback

### Test Scenario 8: Responsive Design

#### Steps:
1. **Test Desktop View** (current)
2. **Test Mobile View**:
   - Open browser dev tools
   - Switch to mobile viewport
   - Test login form
3. **Test Tablet View**:
   - Switch to tablet viewport
   - Test login form

#### Test Cases:
- [ ] Desktop layout is correct
- [ ] Mobile layout is responsive
- [ ] Tablet layout works
- [ ] Touch interactions work
- [ ] Form is usable on all devices

### Test Scenario 9: Loading States

#### Steps:
1. **Open Network Tab** in dev tools
2. **Set Network to Slow 3G**
3. **Attempt Login**
4. **Observe Loading States**

#### Test Cases:
- [ ] Loading spinner appears
- [ ] Button is disabled during loading
- [ ] Form is not submittable during loading
- [ ] Loading state is clear to user

### Test Scenario 10: Error Handling

#### Steps:
1. **Disconnect Internet**
2. **Attempt Login**
3. **Observe Error Message**
4. **Reconnect Internet**
5. **Try Login Again**

#### Test Cases:
- [ ] Network errors are handled
- [ ] Error messages are user-friendly
- [ ] Recovery works after error
- [ ] No technical jargon in errors

## 📊 Test Results Template

### Test Session: [Date/Time]

| Test Scenario | Status | Notes |
|---------------|--------|-------|
| Basic Login Flow | ⬜ Pass / ⬜ Fail | |
| Multiple User Roles | ⬜ Pass / ⬜ Fail | |
| Invalid Credentials | ⬜ Pass / ⬜ Fail | |
| Demo Login Buttons | ⬜ Pass / ⬜ Fail | |
| Logout Functionality | ⬜ Pass / ⬜ Fail | |
| Session Persistence | ⬜ Pass / ⬜ Fail | |
| Form Validation | ⬜ Pass / ⬜ Fail | |
| Responsive Design | ⬜ Pass / ⬜ Fail | |
| Loading States | ⬜ Pass / ⬜ Fail | |
| Error Handling | ⬜ Pass / ⬜ Fail | |

### Overall Result: ⬜ Pass / ⬜ Fail

### Issues Found:
1. 
2. 
3. 

### Recommendations:
1. 
2. 
3. 

## 🔧 Troubleshooting

### Common Issues:

1. **Page Not Loading**:
   - Check if application is running: `docker-compose ps`
   - Restart if needed: `docker-compose restart`

2. **Login Fails**:
   - Verify demo credentials
   - Check browser console for errors
   - Check network connectivity

3. **Styling Issues**:
   - Clear browser cache
   - Try incognito/private mode
   - Check browser compatibility

4. **Session Issues**:
   - Clear browser storage
   - Check localStorage in dev tools
   - Verify token format

## 📱 Browser Compatibility

Test on the following browsers:
- [ ] Chrome (latest)
- [ ] Firefox (latest)
- [ ] Safari (latest)
- [ ] Edge (latest)
- [ ] Mobile Chrome
- [ ] Mobile Safari

## 🎯 Success Criteria

The login/logout functionality is considered successful if:
- ✅ All demo accounts can log in successfully
- ✅ Logout works and clears session
- ✅ Form validation prevents invalid submissions
- ✅ Error messages are clear and helpful
- ✅ UI is responsive on different screen sizes
- ✅ Loading states provide good user feedback
- ✅ Session persistence works across browser tabs

## 📝 Reporting

After completing the tests:
1. Fill out the test results template above
2. Document any issues found
3. Provide screenshots if needed
4. Note any performance issues
5. Suggest improvements

---

**Happy Testing! 🚀** 