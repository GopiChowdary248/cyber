# 🌐 **Browser Cache Clearing Guide**

## 🚨 **Why Clear Browser Cache?**

The API path error `/api/rasp/projects` suggests that your browser is still using cached JavaScript files that contain the old, incorrect API paths. Even though we've fixed the source code, the browser needs to download the new files.

## 🔧 **How to Clear Browser Cache**

### **Chrome/Edge (Chromium-based)**
1. **Hard Refresh**: Press `Ctrl + Shift + R` (Windows) or `Cmd + Shift + R` (Mac)
2. **Clear Cache Completely**:
   - Press `F12` to open DevTools
   - Right-click the refresh button
   - Select "Empty Cache and Hard Reload"
3. **Clear All Data**:
   - Go to `chrome://settings/clearBrowserData`
   - Select "Cached images and files"
   - Click "Clear data"

### **Firefox**
1. **Hard Refresh**: Press `Ctrl + Shift + R` (Windows) or `Cmd + Shift + R` (Mac)
2. **Clear Cache**:
   - Press `F12` to open DevTools
   - Go to Network tab
   - Right-click and select "Clear Browser Cache"
3. **Clear All Data**:
   - Go to `about:preferences#privacy`
   - Click "Clear Data" under Cookies and Site Data

### **Safari**
1. **Hard Refresh**: Press `Cmd + Option + R`
2. **Clear Cache**:
   - Go to Safari → Preferences → Advanced
   - Check "Show Develop menu in menu bar"
   - Go to Develop → Empty Caches

## 🧹 **Additional Steps**

### **1. Clear Service Worker Cache**
- Open DevTools (F12)
- Go to Application tab
- Select "Service Workers" on the left
- Click "Unregister" for any service workers
- Go to "Storage" → "Clear storage"

### **2. Clear Local Storage**
- Open DevTools (F12)
- Go to Application tab
- Select "Local Storage" on the left
- Right-click and "Clear"
- Do the same for "Session Storage"

### **3. Force Reload**
- Press `Ctrl + F5` (Windows) or `Cmd + Shift + R` (Mac)
- Or hold Shift and click the refresh button

## 🔍 **Verify the Fix**

After clearing cache:

1. **Check Browser Console** - No more API path errors
2. **Test RASP Module** - Projects page should load without 404 errors
3. **Check Network Tab** - All requests should go to `/api/v1/rasp/projects`

## 🚀 **If Issues Persist**

If you still see the wrong API paths after clearing cache:

1. **Run the Clear Cache Script**:
   ```powershell
   .\clear-cache-rebuild.ps1
   ```

2. **Check for Build Issues**:
   - Ensure frontend is rebuilt after code changes
   - Check if development server is running latest code

3. **Verify Backend Endpoints**:
   ```bash
   python test-rasp-endpoints.py
   ```

## 📝 **Prevention**

To avoid future caching issues:

1. **Always hard refresh** after code changes
2. **Use browser dev tools** to verify API calls
3. **Clear cache regularly** during development
4. **Use unique build hashes** in production

---

**Remember**: Browser caching is designed to improve performance, but during development it can hide code changes. Always clear cache when testing fixes!
