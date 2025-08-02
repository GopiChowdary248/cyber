# Quick Manual Testing Checklist - Login/Logout

## 🚀 Ready to Test!

Your CyberShield application is running and ready for manual testing.

**Frontend URL**: http://localhost:3000

## ✅ Pre-Test Status
- [x] Application is running
- [x] Backend is healthy
- [x] Frontend is accessible
- [x] Demo accounts available

## 🔑 Demo Accounts
| Email | Password | Role |
|-------|----------|------|
| `admin@cybershield.com` | `password` | Admin |
| `analyst@cybershield.com` | `password` | Analyst |
| `user@cybershield.com` | `password` | User |

## 🧪 Quick Test Steps

### 1. Basic Login Test
- [ ] Open http://localhost:3000
- [ ] Enter: `admin@cybershield.com`
- [ ] Enter: `password`
- [ ] Click "Sign In"
- [ ] Verify: Success message and redirect to dashboard

### 2. Demo Button Test
- [ ] Go back to login page
- [ ] Click "Admin Demo" button
- [ ] Verify: Fields auto-fill
- [ ] Click "Sign In"
- [ ] Verify: Login succeeds

### 3. Invalid Credentials Test
- [ ] Go back to login page
- [ ] Enter: `invalid@example.com`
- [ ] Enter: `wrongpassword`
- [ ] Click "Sign In"
- [ ] Verify: Error message appears

### 4. Multiple Roles Test
- [ ] Logout (if logged in)
- [ ] Login as: `analyst@cybershield.com` / `password`
- [ ] Verify: Analyst role is displayed
- [ ] Logout
- [ ] Login as: `user@cybershield.com` / `password`
- [ ] Verify: User role is displayed

### 5. Logout Test
- [ ] Find logout button in navigation
- [ ] Click logout
- [ ] Verify: Redirected to login page
- [ ] Verify: Can't access protected pages

### 6. Form Validation Test
- [ ] Try to submit empty form
- [ ] Verify: Validation error appears
- [ ] Enter invalid email format
- [ ] Verify: Email validation error

### 7. Responsive Test
- [ ] Open browser dev tools
- [ ] Switch to mobile viewport
- [ ] Verify: Login form is usable on mobile
- [ ] Test touch interactions

## 📊 Test Results

| Test | Status | Notes |
|------|--------|-------|
| Basic Login | ⬜ Pass / ⬜ Fail | |
| Demo Buttons | ⬜ Pass / ⬜ Fail | |
| Invalid Credentials | ⬜ Pass / ⬜ Fail | |
| Multiple Roles | ⬜ Pass / ⬜ Fail | |
| Logout | ⬜ Pass / ⬜ Fail | |
| Form Validation | ⬜ Pass / ⬜ Fail | |
| Responsive Design | ⬜ Pass / ⬜ Fail | |

## 🎯 Success Criteria
- ✅ All demo accounts can log in
- ✅ Logout works and clears session
- ✅ Form validation prevents invalid submissions
- ✅ Error messages are clear
- ✅ UI is responsive
- ✅ Loading states work properly

## 🔧 If Issues Found

1. **Check browser console** for errors
2. **Clear browser cache** and try again
3. **Try incognito/private mode**
4. **Check network connectivity**
5. **Restart application**: `docker-compose restart`

## 📝 Report Issues

If you find any issues:
1. Note the exact steps to reproduce
2. Include browser and version
3. Screenshot the error if possible
4. Check browser console for error messages

---

**Start Testing Now! 🚀**

Open your browser and go to: **http://localhost:3000** 