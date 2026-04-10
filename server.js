require('dotenv').config();
const AdmZip = require('adm-zip');
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_key';
const express = require('express');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const csv = require('csv-parser');
const db = require('./db');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/images', express.static(path.join(__dirname, 'images')));

// Multer setup for temporary CSV uploads & images
const upload = multer({ dest: 'uploads/' }); 

// Auto-create required folders so the server never crashes on a new PC
if (!fs.existsSync(path.join(__dirname, 'images'))) fs.mkdirSync(path.join(__dirname, 'images'));
if (!fs.existsSync(path.join(__dirname, 'uploads'))) fs.mkdirSync(path.join(__dirname, 'uploads'));

// ==========================================
// Middleware: Super Admin Security Check
// ==========================================
const superAdminAuth = (req, res, next) => {
    const key = req.headers['x-admin-key'];
    if (key === process.env.SUPER_ADMIN_PASSWORD) {
        next();
    } else {
        res.status(401).json({ error: "Unauthorized: Invalid Super Admin Password" });
    }
};

// ==========================================
// AUTHENTICATION ROUTE (Login with Anti-Brute Force)
// ==========================================

// In-memory tracker for failed login attempts
const failedLogins = new Map();
const MAX_ATTEMPTS = 5;
const LOCKOUT_TIME = 5 * 60 * 1000; // 5 minutes in milliseconds

app.post('/api/login', (req, res) => {
    const ip = req.ip || req.socket.remoteAddress;
    const { username, password } = req.body;
    
    // 1. Check if this IP is currently locked out
    const attemptData = failedLogins.get(ip) || { count: 0, lockoutUntil: 0 };
    if (Date.now() < attemptData.lockoutUntil) {
        const remainingMins = Math.ceil((attemptData.lockoutUntil - Date.now()) / 60000);
        return res.status(429).json({ error: `Security Lock: Too many failed attempts. Try again in ${remainingMins} minute(s).` });
    }

    if (!username || !password) return res.status(400).json({ error: "Please enter both fields." });

    // Helper function to handle failed logins
    const handleFailedLogin = () => {
        attemptData.count += 1;
        if (attemptData.count >= MAX_ATTEMPTS) {
            attemptData.lockoutUntil = Date.now() + LOCKOUT_TIME;
        }
        failedLogins.set(ip, attemptData);
        res.status(401).json({ error: `Invalid credentials. Attempt ${attemptData.count}/${MAX_ATTEMPTS}` });
    };

    // 2. Check Professor Table
    db.get(`SELECT id, name, is_active FROM Professors WHERE username = ? AND password = ?`, [username, password], (err, prof) => {
        if (err) return res.status(500).json({ error: "Database error" });
        
        if (prof) {
            if (prof.is_active === 0) return res.status(403).json({ error: "Account disabled. Contact Super Admin." });
            failedLogins.delete(ip); // Clear strikes on success
            const token = jwt.sign({ id: prof.id, role: 'professor', name: prof.name }, JWT_SECRET, { expiresIn: '8h' });
            return res.json({ success: true, token, role: 'professor', redirect: '/professor.html' });
        }

        // 3. Check Student Table
        db.get(`SELECT id, name, is_active FROM Students WHERE university_id = ? AND password = ?`, [username, password], (err, student) => {
            if (err) return res.status(500).json({ error: "Database error" });

            if (student) {
                if (student.is_active === 0) return res.status(403).json({ error: "Account disabled by Professor." });
                failedLogins.delete(ip); // Clear strikes on success
                const token = jwt.sign({ id: student.id, role: 'student', name: student.name }, JWT_SECRET, { expiresIn: '4h' });
                return res.json({ success: true, token, role: 'student', redirect: '/student.html' });
            }

            // 4. If neither matched, register a strike against the IP
            handleFailedLogin();
        });
    });
});

// ==========================================
// SUPER ADMIN ROUTES (Faculty Management)
// ==========================================

// 1. Get all professors
app.get('/api/super/professors', superAdminAuth, (req, res) => {
    db.all(`SELECT id, username, name, is_active FROM Professors`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

// 2. Add a single professor
app.post('/api/super/professors', superAdminAuth, (req, res) => {
    const { username, password, name } = req.body;
    db.run(`INSERT INTO Professors (username, password, name) VALUES (?, ?, ?)`, 
        [username, password, name], function(err) {
        if (err) return res.status(400).json({ error: "Error: Username might already exist." });
        res.json({ success: true, id: this.lastID });
    });
});

// 3. Delete a professor
app.delete('/api/super/professors/:id', superAdminAuth, (req, res) => {
    db.run(`DELETE FROM Professors WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// 4. Toggle Disable/Enable
app.post('/api/super/professors/:id/toggle', superAdminAuth, (req, res) => {
    db.run(`UPDATE Professors SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// 5. Bulk Import Professors via CSV
app.post('/api/super/import-professors', superAdminAuth, upload.single('csvfile'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    const results = [];
    fs.createReadStream(req.file.path)
        .pipe(csv({ mapHeaders: ({ header }) => header.replace(/^\uFEFF/, '').trim() }))
        .on('data', (data) => results.push(data))
        .on('end', () => {
            let completed = 0;
            if(results.length === 0) return res.json({ success: false, error: "Empty CSV" });

            results.forEach(row => {
                db.run(`INSERT OR IGNORE INTO Professors (username, password, name) VALUES (?, ?, ?)`, 
                [row.username, row.password, row.name], () => {
                    completed++;
                    if(completed === results.length) {
                        fs.unlinkSync(req.file.path);
                        res.json({ success: true, message: `Imported ${results.length} professors.` });
                    }
                });
            });
        });
});

// 6. Reset Professor Password
app.post('/api/super/professors/:id/reset-password', superAdminAuth, (req, res) => {
    const { newPassword } = req.body;
    if (!newPassword) return res.status(400).json({ error: "Password cannot be empty" });
    
    db.run(`UPDATE Professors SET password = ? WHERE id = ?`, [newPassword, req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});


// ==========================================
// Middleware: Professor Security Check
// ==========================================
const professorAuth = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: "Access Denied: No Token" });
    
    const token = authHeader.split(' ')[1]; // Format: "Bearer <token>"
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err || decoded.role !== 'professor') return res.status(403).json({ error: "Unauthorized" });
        req.user = decoded; // Contains { id, role, name }
        next();
    });
};

// Middleware: Student Security Check
const studentAuth = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ error: "No token provided" });

    const token = authHeader.split(' ')[1];
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err || decoded.role !== 'student') return res.status(401).json({ error: "Unauthorized access" });
        req.studentId = decoded.id; // Attach the student ID to the request
        next();
    });
};

// ==========================================
// PROFESSOR ROUTES (Groups & Students)
// ==========================================

// Get Results for a specific Exam
app.get('/api/prof/exams/:examId/results', professorAuth, (req, res) => {
    // This query joins the Results table with the Students table to get names and IDs
    const sql = `
        SELECT r.score, r.max_score, r.timestamp, s.name as student_name, s.university_id 
        FROM Results r
        JOIN Students s ON r.student_id = s.id
        WHERE r.exam_id = ?
        ORDER BY r.score DESC
    `;
    
    db.all(sql, [req.params.examId], (err, rows) => {
        if (err) return res.status(500).json({ error: "Failed to fetch results" });
        res.json(rows || []);
    });
});

// Get Groups
app.get('/api/prof/groups', professorAuth, (req, res) => {
    db.all(`SELECT id, group_name AS name FROM Groups WHERE professor_id = ?`, [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

// Add Group
app.post('/api/prof/groups', professorAuth, (req, res) => {
    const { name } = req.body;
    db.run(`INSERT INTO Groups (group_name, professor_id) VALUES (?, ?)`, [name, req.user.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, id: this.lastID });
    });
});

// Delete Group
app.delete('/api/prof/groups/:groupId', professorAuth, (req, res) => {
    db.run(`DELETE FROM Student_Groups WHERE group_id = ?`, [req.params.groupId], () => {
        db.run(`DELETE FROM Groups WHERE id = ? AND professor_id = ?`, [req.params.groupId, req.user.id], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        });
    });
});

// Get Students in Group
app.get('/api/prof/groups/:groupId/students', professorAuth, (req, res) => {
    const query = `
        SELECT s.id, s.university_id, s.name, s.is_active 
        FROM Students s 
        JOIN Student_Groups sg ON s.id = sg.student_id 
        WHERE sg.group_id = ?`;
    
    db.all(query, [req.params.groupId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

// Add Single Student
app.post('/api/prof/students', professorAuth, (req, res) => {
    const { university_id, password, name, group_id } = req.body;
    db.run(`INSERT OR IGNORE INTO Students (university_id, password, name) VALUES (?, ?, ?)`, 
        [university_id, password, name], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        
        db.get(`SELECT id FROM Students WHERE university_id = ?`, [university_id], (err, student) => {
            if (err || !student) return res.status(500).json({ error: "Database error" });
            db.run(`INSERT OR IGNORE INTO Student_Groups (student_id, group_id) VALUES (?, ?)`, [student.id, group_id], function(err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ success: true });
            });
        });
    });
});

// Remove Student from Group
app.delete('/api/prof/groups/:groupId/students/:studentId', professorAuth, (req, res) => {
    db.run(`DELETE FROM Student_Groups WHERE student_id = ? AND group_id = ?`, [req.params.studentId, req.params.groupId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// Toggle Student Status
app.post('/api/prof/students/:id/toggle', professorAuth, (req, res) => {
    db.run(`UPDATE Students SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// Reset Student Password
app.post('/api/prof/students/:id/reset-password', professorAuth, (req, res) => {
    const { newPassword } = req.body;
    db.run(`UPDATE Students SET password = ? WHERE id = ?`, [newPassword, req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// Import Students via CSV
app.post('/api/prof/import-students', professorAuth, upload.single('csvfile'), (req, res) => {
    const groupId = req.body.group_id;
    if (!req.file || !groupId) return res.status(400).json({ error: "Missing file or group selection" });

    const results = [];
    fs.createReadStream(req.file.path)
        .pipe(csv({ mapHeaders: ({ header }) => header.replace(/^\uFEFF/, '').trim() }))
        .on('data', (data) => results.push(data))
        .on('end', () => {
            let completed = 0;
            if(results.length === 0) return res.json({ success: false, error: "Empty CSV" });

            results.forEach(row => {
                db.run(`INSERT OR IGNORE INTO Students (university_id, password, name) VALUES (?, ?, ?)`, 
                [row.university_id, row.password, row.name], () => {
                    db.get(`SELECT id FROM Students WHERE university_id = ?`, [row.university_id], (err, student) => {
                        if (student) {
                            db.run(`INSERT OR IGNORE INTO Student_Groups (student_id, group_id) VALUES (?, ?)`, [student.id, groupId], () => { checkDone(); });
                        } else { checkDone(); }
                    });
                });
            });

            function checkDone() {
                completed++;
                if (completed === results.length) {
                    fs.unlinkSync(req.file.path);
                    res.json({ success: true, message: `Imported and linked ${results.length} students.` });
                }
            }
        });
});


// ==========================================
// PROFESSOR ROUTES (Exam & Question Builder)
// ==========================================

// 1. Get Exams
app.get('/api/prof/exams', professorAuth, (req, res) => {
    db.all(`SELECT e.*, g.group_name FROM Exams e JOIN Groups g ON e.group_id = g.id WHERE e.professor_id = ?`, [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

// 2. Create Exam
app.post('/api/prof/exams', professorAuth, (req, res) => {
    const { title, group_id, duration_minutes, q_display_count, shuffle_questions, shuffle_options } = req.body;
    db.run(`INSERT INTO Exams (professor_id, group_id, title, duration_minutes, q_display_count, shuffle_questions, shuffle_options) VALUES (?, ?, ?, ?, ?, ?, ?)`, 
    [req.user.id, group_id, title, duration_minutes, q_display_count || null, shuffle_questions ? 1 : 0, shuffle_options ? 1 : 0], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, id: this.lastID });
    });
});

// 3. Delete Exam (Fix: Clean hard drive for all questions in this exam)
app.delete('/api/prof/exams/:id', professorAuth, (req, res) => {
    db.all(`SELECT image_url FROM Questions WHERE exam_id = ? AND image_url IS NOT NULL`, [req.params.id], (err, rows) => {
        if (rows) {
            rows.forEach(row => {
                const imgPath = path.join(__dirname, row.image_url);
                if (fs.existsSync(imgPath)) fs.unlinkSync(imgPath);
            });
        }
        db.run(`DELETE FROM Questions WHERE exam_id = ?`, [req.params.id], () => {
            db.run(`DELETE FROM Exams WHERE id = ? AND professor_id = ?`, [req.params.id, req.user.id], function(err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ success: true });
            });
        });
    });
});

app.post('/api/prof/exams/:id/toggle', professorAuth, (req, res) => {
    db.run(`UPDATE Exams SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message }); res.json({ success: true });
    });
});

// 4. Get Questions
app.get('/api/prof/exams/:examId/questions', professorAuth, (req, res) => {
    db.all(`SELECT * FROM Questions WHERE exam_id = ?`, [req.params.examId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        const parsedRows = rows.map(r => ({ ...r, options: r.options ? JSON.parse(r.options) : [] }));
        res.json(parsedRows || []);
    });
});

// 5. Add Question (Supports image uploads and dynamic JSON options)
// 4. Add a Question to an Exam (Supports Multi-type & Images)
app.post('/api/prof/questions', professorAuth, upload.single('image'), (req, res) => {
    try {
        const { exam_id, q_type, question_text, options, correct_answer, points } = req.body;
        let imageUrl = null;

        if (req.file) {
            // Move file from 'uploads/' to 'images/' so it can actually be viewed
            const newPath = path.join(__dirname, 'images', req.file.filename);
            fs.renameSync(req.file.path, newPath);
            imageUrl = `/images/${req.file.filename}`;
        }

        const sql = `INSERT INTO Questions (exam_id, q_type, question_text, image_url, options, correct_answer, points) VALUES (?, ?, ?, ?, ?, ?, ?)`;
        const params = [exam_id, q_type || 'mcq', question_text, imageUrl, options, correct_answer, points || 1];

        db.run(sql, params, function(err) {
            if (err) {
                console.error("DATABASE ERROR:", err.message); // This will now show in your terminal!
                return res.status(500).json({ success: false, error: err.message });
            }
            res.json({ success: true, id: this.lastID });
        });
    } catch (e) {
        console.error("SERVER CRASH:", e.message);
        res.status(500).json({ success: false, error: e.message });
    }
});

// 5.5 Edit Question (Fix: Support image replacement & delete old image)
app.put('/api/prof/questions/:id', professorAuth, upload.single('image'), (req, res) => {
    const { q_type, question_text, option_a, option_b, option_c, option_d, correct_answer, points } = req.body;
    
    if (req.file) {
        // Move new image
        fs.renameSync(req.file.path, path.join(__dirname, 'images', req.file.filename));
        const imageUrl = `/images/${req.file.filename}`;
        
        // Find and delete the old image from hard drive
        db.get(`SELECT image_url FROM Questions WHERE id = ?`, [req.params.id], (err, row) => {
            if (row && row.image_url) {
                const oldPath = path.join(__dirname, row.image_url);
                if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
            }
            db.run(`UPDATE Questions SET q_type = ?, question_text = ?, image_url = ?, option_a = ?, option_b = ?, option_c = ?, option_d = ?, correct_answer = ?, points = ? WHERE id = ?`,
            [q_type || 'mcq', question_text, imageUrl, option_a, option_b, option_c, option_d, correct_answer, points, req.params.id], function(err) {
                res.json({ success: true });
            });
        });
    } else {
        db.run(`UPDATE Questions SET q_type = ?, question_text = ?, option_a = ?, option_b = ?, option_c = ?, option_d = ?, correct_answer = ?, points = ? WHERE id = ?`,
        [q_type || 'mcq', question_text, option_a, option_b, option_c, option_d, correct_answer, points, req.params.id], function(err) {
            res.json({ success: true });
        });
    }
});

// 5.5 Edit Question (Bulletproof & Verbose)
app.put('/api/prof/questions/:id', professorAuth, upload.single('image'), (req, res) => {
    try {
        const qId = req.params.id;
        const { q_type, question_text, options, correct_answer, points } = req.body;
        
        console.log(`[EDIT ATTEMPT] Question ID: ${qId}`);
        console.log(`[INCOMING TEXT]`, question_text);

        db.get(`SELECT image_url FROM Questions WHERE id = ?`, [qId], (err, oldRow) => {
            if (!oldRow) {
                console.error("Edit Failed: Question not found in DB.");
                return res.status(404).json({ success: false, error: "Question not found." });
            }
            
            let imageUrl = oldRow.image_url;

            if (req.file) {
                if (imageUrl) {
                    const oldPath = path.join(__dirname, imageUrl);
                    if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
                }
                const newPath = path.join(__dirname, 'images', req.file.filename);
                fs.renameSync(req.file.path, newPath);
                imageUrl = `/images/${req.file.filename}`;
            }

            const sql = `UPDATE Questions SET q_type=?, question_text=?, image_url=?, options=?, correct_answer=?, points=? WHERE id=?`;
            const params = [q_type || 'mcq', question_text, imageUrl, options, correct_answer, points || 1, qId];

            db.run(sql, params, function(err) {
                if (err) {
                    console.error("[SQL ERROR]", err.message);
                    return res.status(500).json({ success: false, error: err.message });
                }
                console.log(`[SUCCESS] Rows Updated: ${this.changes}`);
                res.json({ success: true });
            });
        });
    } catch (e) {
        console.error("[SERVER CRASH]", e.message);
        res.status(500).json({ success: false, error: e.message });
    }
});

// 6. Delete Question (Now with File Cleanup)
app.delete('/api/prof/questions/:id', professorAuth, (req, res) => {
    const qId = req.params.id;
    // Look for image before deleting
    db.get(`SELECT image_url FROM Questions WHERE id = ?`, [qId], (err, row) => {
        if (row && row.image_url) {
            const filePath = path.join(__dirname, row.image_url);
            if (fs.existsSync(filePath)) fs.unlinkSync(filePath); // Delete file from drive
        }
        db.run(`DELETE FROM Questions WHERE id = ?`, [qId], function(err) {
            if (err) return res.status(500).json({ error: err.message }); 
            res.json({ success: true });
        });
    });
});

// ZIP: Export Exam
app.get('/api/prof/exams/:id/export-zip', professorAuth, (req, res) => {
    db.all(`SELECT * FROM Questions WHERE exam_id = ?`, [req.params.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        const zip = new AdmZip();
        // Updated to match your database structure (option_a, option_b, etc.)
        let csvContent = "\uFEFFq_type,question_text,option_a,option_b,option_c,option_d,correct_answer,points,image_filename\n";
        
        rows.forEach(q => {
            const escapeCSV = (str) => `"${String(str || '').replace(/"/g, '""')}"`;
            const imgName = q.image_url ? q.image_url.split('/').pop() : '';
            
            csvContent += `${q.q_type || 'mcq'},${escapeCSV(q.question_text)},${escapeCSV(q.option_a)},${escapeCSV(q.option_b)},${escapeCSV(q.option_c)},${escapeCSV(q.option_d)},${escapeCSV(q.correct_answer)},${q.points},${imgName}\n`;
            
            if (q.image_url) {
                const imgPath = path.join(__dirname, q.image_url);
                if (fs.existsSync(imgPath)) zip.addFile(`images/${imgName}`, fs.readFileSync(imgPath));
            }
        });
        
        zip.addFile("questions.csv", Buffer.from(csvContent, "utf8"));
        res.set('Content-Type', 'application/zip');
        res.set('Content-Disposition', `attachment; filename=Exam_${req.params.id}_Export.zip`);
        res.send(zip.toBuffer());
    });
});

// 7. Download ZIP Template (Upgraded with 4 examples)
app.get('/api/prof/template-zip', professorAuth, (req, res) => {
    const zip = new AdmZip();
    // Proper CSV structure with escaped quotes for the Multiple Answer example
    const csvContent = 
`\uFEFFq_type,question_text,options_separated_by_pipe,correct_answer,points,image_filename
mcq,What is the capital of France?,Paris|London|Berlin|Madrid,Paris,1,
tf,Water boils at 100 degrees Celsius.,True|False,True,1,
fib,The matrix determinant of [blank] is [blank].,,"42, Matrix",2,
ma,Which of these are primary colors?,Red|Green|Blue|Yellow,"[""Red"",""Blue""]",2,sky.jpg`;

    zip.addFile("questions.csv", Buffer.from(csvContent, "utf8"));
    zip.addFile("images/sky.jpg", Buffer.from("fake image content")); // Dummy file to generate the folder
    
    res.set('Content-Type', 'application/zip');
    res.set('Content-Disposition', 'attachment; filename=Exam_Import_Template.zip');
    res.send(zip.toBuffer());
});

// 8. Export Exam to ZIP
app.get('/api/prof/exams/:id/export-zip', professorAuth, (req, res) => {
    db.all(`SELECT * FROM Questions WHERE exam_id = ?`, [req.params.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        
        const zip = new AdmZip();
        let csvContent = "\uFEFFq_type,question_text,options_separated_by_pipe,correct_answer,points,image_filename\n";

        rows.forEach(q => {
            let opts = "[]";
            try { opts = JSON.parse(q.options).join('|'); } catch(e) {}
            
            // Helper to escape commas and quotes for CSV formatting
            const escapeCSV = (str) => `"${String(str).replace(/"/g, '""')}"`;
            const imgName = q.image_url ? q.image_url.split('/').pop() : '';
            
            csvContent += `${q.q_type},${escapeCSV(q.question_text)},${escapeCSV(opts)},${escapeCSV(q.correct_answer)},${q.points},${imgName}\n`;

            // If there's an image, attach it physically to the zip
            if (q.image_url) {
                const imgPath = path.join(__dirname, q.image_url);
                if (fs.existsSync(imgPath)) zip.addFile(`images/${imgName}`, fs.readFileSync(imgPath));
            }
        });

        zip.addFile("questions.csv", Buffer.from(csvContent, "utf8"));
        res.set('Content-Type', 'application/zip');
        res.set('Content-Disposition', `attachment; filename=Exam_${req.params.id}_Export.zip`);
        res.send(zip.toBuffer());
    });
});

// 8. Edit Exam
app.put('/api/prof/exams/:id', professorAuth, (req, res) => {
    const { title, duration_minutes, q_display_count, shuffle_questions, shuffle_options } = req.body;
    db.run(`UPDATE Exams SET title = ?, duration_minutes = ?, q_display_count = ?, shuffle_questions = ?, shuffle_options = ? WHERE id = ? AND professor_id = ?`,
    [title, duration_minutes, q_display_count || null, shuffle_questions ? 1 : 0, shuffle_options ? 1 : 0, req.params.id, req.user.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// 9. Edit Question
app.put('/api/prof/questions/:id', professorAuth, upload.single('image'), (req, res) => {
    const { q_type, question_text, correct_answer, points } = req.body;
    let options = req.body.options || "[]";
    if (req.file) {
        const imageUrl = `/images/${req.file.filename}`;
        db.run(`UPDATE Questions SET q_type = ?, question_text = ?, image_url = ?, options = ?, correct_answer = ?, points = ? WHERE id = ?`,
        [q_type, question_text, imageUrl, options, correct_answer, points, req.params.id], function(err) {
            if (err) return res.status(500).json({ error: err.message }); res.json({ success: true });
        });
    } else {
        db.run(`UPDATE Questions SET q_type = ?, question_text = ?, options = ?, correct_answer = ?, points = ? WHERE id = ?`,
        [q_type, question_text, options, correct_answer, points, req.params.id], function(err) {
            if (err) return res.status(500).json({ error: err.message }); res.json({ success: true });
        });
    }
});

// 10. Import ZIP Exam
const { Readable } = require('stream');
app.post('/api/prof/exams/:examId/import-zip', professorAuth, upload.single('zipfile'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: "No zip file provided" });
    try {
        const zip = new AdmZip(req.file.path);
        const zipEntries = zip.getEntries();
        let csvContent = "";
        
        // Extract CSV and Images
        zipEntries.forEach(entry => {
            if (entry.entryName.toLowerCase() === 'questions.csv') {
                csvContent = entry.getData().toString('utf8');
            } else if (entry.entryName.startsWith('images/') && !entry.isDirectory) {
                fs.writeFileSync(path.join(__dirname, 'images', entry.name.replace('images/','')), entry.getData());
            }
        });
        
        if (!csvContent) return res.status(400).json({ error: "questions.csv not found in zip" });
        
        const results = [];
        Readable.from(csvContent)
            .pipe(csv({ mapHeaders: ({ header }) => header.replace(/^\uFEFF/, '').trim() }))
            .on('data', (data) => results.push(data))
            .on('end', () => {
                let completed = 0;
                if(results.length === 0) return res.json({ success: false, error: "Empty CSV" });

                results.forEach(row => {
                    const imgUrl = row.image_filename ? `/images/${row.image_filename}` : null;
                    const options = row.options_separated_by_pipe ? JSON.stringify(row.options_separated_by_pipe.split('|')) : "[]";
                    
                    db.run(`INSERT INTO Questions (exam_id, q_type, question_text, image_url, options, correct_answer, points) VALUES (?, ?, ?, ?, ?, ?, ?)`, 
                    [req.params.examId, row.q_type, row.question_text, imgUrl, options, row.correct_answer, row.points || 1], () => {
                        completed++;
                        if(completed === results.length) {
                            fs.unlinkSync(req.file.path);
                            res.json({ success: true, message: `Imported ${results.length} questions.` });
                        }
                    });
                });
            });
    } catch(e) {
        res.status(500).json({error: "Failed to parse zip: " + e.message});
    }
});

// ==========================================
// STUDENT API ROUTES
// ==========================================

// 1. Student Login
app.post('/api/student/login', (req, res) => {
    const { university_id, password } = req.body;
    
    db.get(`SELECT id, name, is_active FROM Students WHERE university_id = ? AND password = ?`, 
    [university_id, password], (err, student) => {
        if (err) return res.status(500).json({ success: false, error: "Database error" });
        if (!student) return res.status(401).json({ success: false, error: "Invalid ID or Password" });
        if (student.is_active === 0) return res.status(403).json({ success: false, error: "Account is deactivated" });

        // Generate a secure token just for this student
        const token = jwt.sign({ id: student.id, role: 'student' }, JWT_SECRET, { expiresIn: '4h' });
        res.json({ success: true, token, name: student.name });
    });
});

// 2. Get Active Exams for this Student
app.get('/api/student/exams', studentAuth, (req, res) => {
    // This complex query ensures a student ONLY sees active exams assigned to their specific group
    const sql = `
        SELECT e.id, e.title, e.duration_minutes, p.name as professor_name 
        FROM Exams e 
        JOIN Student_Groups sg ON e.group_id = sg.group_id 
        JOIN Professors p ON e.professor_id = p.id 
        WHERE sg.student_id = ? AND e.is_active = 1 AND e.is_closed = 0
    `;
    
    db.all(sql, [req.studentId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

// 3. Get Exam Details and Questions (SECURE: No answers included!)
app.get('/api/student/exam/:examId', studentAuth, (req, res) => {
    const examId = req.params.examId;
    const studentId = req.studentId;

    // First, verify the student is actually allowed to take this specific exam
    const verifySql = `
        SELECT e.* FROM Exams e
        JOIN Student_Groups sg ON e.group_id = sg.group_id
        WHERE e.id = ? AND sg.student_id = ? AND e.is_active = 1 AND e.is_closed = 0
    `;

    db.get(verifySql, [examId, studentId], (err, exam) => {
        if (err) return res.status(500).json({ success: false, error: "Database error" });
        if (!exam) return res.status(403).json({ success: false, error: "Exam not available or unauthorized." });

        // Fetch questions. Notice we DO NOT select the 'correct_answer' column!
        const qSql = `SELECT id, q_type, question_text, image_url, options, points FROM Questions WHERE exam_id = ?`;
        
        db.all(qSql, [examId], (err, questions) => {
            if (err) return res.status(500).json({ success: false, error: "Error fetching questions" });
            
            // Safely parse the options string back into an array for the frontend
            questions.forEach(q => {
                try { 
                    q.options = q.options ? JSON.parse(q.options) : []; 
                } catch (e) { 
                    q.options = []; 
                }
            });

            res.json({
                success: true,
                exam: { title: exam.title, duration_minutes: exam.duration_minutes },
                questions: questions
            });
        });
    });
});

// 4. Submit Exam and Auto-Grade
app.post('/api/student/exam/:examId/submit', studentAuth, (req, res) => {
    const examId = req.params.examId;
    const studentId = req.studentId;
    const studentAnswers = req.body.answers || {};

    // 1. Check if the student already submitted this exam (prevent double-submitting)
    db.get(`SELECT id FROM Results WHERE exam_id = ? AND student_id = ?`, [examId, studentId], (err, existingResult) => {
        if (err) return res.status(500).json({ success: false, error: "Database error" });
        if (existingResult) return res.status(400).json({ success: false, error: "You have already submitted this exam." });

        // 2. Fetch the correct answers from the database
        db.all(`SELECT id, q_type, correct_answer, points FROM Questions WHERE exam_id = ?`, [examId], (err, questions) => {
            if (err) return res.status(500).json({ success: false, error: "Error grading exam" });

            let totalScore = 0;
            let maxScore = 0;

            // 3. Auto-Grade each question
            questions.forEach(q => {
                maxScore += q.points;
                const studentAns = studentAnswers[q.id];

                if (!studentAns) return; // Student skipped the question, 0 points

                let isCorrect = false;

                if (q.q_type === 'fib') {
                    // Fill-in-the-blank: Case-insensitive match, ignore extra spaces
                    if (String(q.correct_answer).toLowerCase().trim() === String(studentAns).toLowerCase().trim()) isCorrect = true;
                } else if (q.q_type === 'ma') {
                    // Multiple Answer: Compare arrays (this requires parsing JSON or pipe strings depending on how you saved it)
                    // For safety, we compare them as lowercase strings
                    if (String(q.correct_answer).toLowerCase().trim() === String(studentAns).toLowerCase().trim()) isCorrect = true;
                } else {
                    // MCQ and True/False: Direct string match
                    if (String(q.correct_answer).trim() === String(studentAns).trim()) isCorrect = true;
                }

                if (isCorrect) totalScore += q.points;
            });

            // 4. Save to the Results table
            db.run(`INSERT INTO Results (exam_id, student_id, score, max_score, violations) VALUES (?, ?, ?, ?, ?)`,
            [examId, studentId, totalScore, maxScore, 0], function(err) {
                if (err) return res.status(500).json({ success: false, error: "Failed to save results" });
                
                res.json({ success: true, score: totalScore, maxScore: maxScore });
            });
        });
    });
});

// Start Server
const PORT = process.env.PORT || 80;
app.listen(PORT, () => console.log(`SLEP v3.0 Server running on port ${PORT}`));