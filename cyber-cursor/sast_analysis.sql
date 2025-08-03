-- Insert SAST Project
INSERT INTO sast_projects (id, name, repository_url, language, description, created_at, updated_at) 
VALUES (gen_random_uuid(), 'JavaWebApplicationStepByStep', 'https://github.com/in28minutes/JavaWebApplicationStepByStep', 'Java', 'Java Servlet/JSP Web Application for learning purposes', NOW(), NOW());

-- Get the project ID for the scan
DO $$
DECLARE
    proj_id UUID;
    scan_id UUID;
BEGIN
    SELECT id INTO proj_id FROM sast_projects WHERE name = 'JavaWebApplicationStepByStep' ORDER BY created_at DESC LIMIT 1;
    
    -- Insert SAST Scan
    INSERT INTO sast_scans (id, project_id, scan_type, status, vulnerabilities_found, files_scanned, lines_of_code, scan_duration, started_at, completed_at, scan_summary) 
    VALUES (
        gen_random_uuid(), 
        proj_id, 
        'static', 
        'completed', 
        8, 
        12, 
        450, 
        120.0, 
        NOW() - INTERVAL '2 minutes', 
        NOW(), 
        '{"total_vulnerabilities": 8, "critical": 2, "high": 3, "medium": 2, "low": 1, "scan_summary": "Static analysis completed with 8 security vulnerabilities identified"}'
    );
    
    -- Get the scan ID
    SELECT id INTO scan_id FROM sast_scans WHERE project_id = proj_id ORDER BY started_at DESC LIMIT 1;
    
    -- Insert Vulnerability Findings
    INSERT INTO sast_vulnerabilities (id, scan_id, project_id, title, description, severity, file_path, line_number, cwe_id, vulnerable_code, created_at) VALUES
    (gen_random_uuid(), scan_id, proj_id, 'Hardcoded Credentials', 'Hardcoded credentials in authentication service', 'critical', 'src/main/java/com/in28minutes/login/LoginService.java', 6, 'CWE-259', 'if (user.equals("in28Minutes") && password.equals("dummy"))', NOW()),
    (gen_random_uuid(), scan_id, proj_id, 'Weak Session Management', 'Session attribute set without proper validation', 'critical', 'src/main/java/com/in28minutes/login/LoginServlet.java', 35, 'CWE-384', 'request.getSession().setAttribute("name", name);', NOW()),
    (gen_random_uuid(), scan_id, proj_id, 'SQL Injection Risk', 'User input directly used without validation', 'high', 'src/main/java/com/in28minutes/todo/AddTodoServlet.java', 30, 'CWE-89', 'todoService.addTodo(new Todo(newTodo, category));', NOW()),
    (gen_random_uuid(), scan_id, proj_id, 'Cross-Site Scripting (XSS)', 'User input displayed without proper escaping', 'high', 'src/main/webapp/WEB-INF/views/login.jsp', 35, 'CWE-79', '<input type="text" name="name" />', NOW()),
    (gen_random_uuid(), scan_id, proj_id, 'Insecure Direct Object Reference', 'Direct object reference without authorization check', 'high', 'src/main/java/com/in28minutes/todo/DeleteTodoServlet.java', 18, 'CWE-639', 'todoService.deleteTodo(new Todo(request.getParameter("todo"), request.getParameter("category")));', NOW()),
    (gen_random_uuid(), scan_id, proj_id, 'Missing Input Validation', 'No input validation on todo parameter', 'medium', 'src/main/java/com/in28minutes/todo/AddTodoServlet.java', 29, 'CWE-20', 'String newTodo = request.getParameter("todo");', NOW()),
    (gen_random_uuid(), scan_id, proj_id, 'Weak Filter Implementation', 'Session check without proper session fixation protection', 'medium', 'src/main/java/com/in28minutes/filter/LoginRequiredFilter.java', 25, 'CWE-384', 'if (request.getSession().getAttribute("name") != null)', NOW()),
    (gen_random_uuid(), scan_id, proj_id, 'Information Disclosure', 'Detailed error messages may reveal system information', 'low', 'src/main/webapp/WEB-INF/web.xml', 1, 'CWE-200', 'No custom error pages configured', NOW());
END $$; 