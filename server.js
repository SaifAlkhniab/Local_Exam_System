require('dotenv').config();
const os = require('os');
const QRCode = require('qrcode');
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
// Redirect bare root to the student login portal
app.get('/', (req, res) => res.redirect('/student-login.html'));
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
const autosaveStore = new Map(); // In-memory backup of in-progress student answers
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

// Professor: Change Own Password
app.put('/api/prof/change-password', professorAuth, (req, res) => {
    const profId = req.user.id; // Extracted from the secure token
    const { newPassword } = req.body;

    if (!newPassword || newPassword.length < 4) {
        return res.status(400).json({ success: false, error: "Password must be at least 4 characters long." });
    }

    db.run(`UPDATE Professors SET password = ? WHERE id = ?`, [newPassword, profId], function(err) {
        if (err) {
            console.error("Password update error:", err.message);
            return res.status(500).json({ success: false, error: "Database error while updating password." });
        }
        res.json({ success: true, message: "Password updated successfully!" });
    });
});

// Get Results for a specific Exam
app.get('/api/prof/exams/:examId/results', professorAuth, (req, res) => {
    const examId = req.params.examId;

    // Fetch exam title — no professor_id guard so the results are never silently hidden
    db.get(`SELECT title FROM Exams WHERE id = ?`, [examId], (err, exam) => {
        if (err) {
            console.error(`[RESULTS] Exam title query error for exam ${examId}:`, err.message);
            return res.status(500).json({ error: "Database error" });
        }

        const examTitle = exam ? exam.title : ('Exam #' + examId);

        // LEFT JOIN: keep result rows even if the student account was deleted
        // Status filter: only return real submissions, not in-progress placeholders
        const sql = `
            SELECT r.score, r.max_score, r.timestamp, r.violations, r.status,
                   COALESCE(s.name, '[Deleted Student]') AS student_name,
                   COALESCE(s.university_id, 'N/A') AS university_id
            FROM Results r
            LEFT JOIN Students s ON r.student_id = s.id
            WHERE r.exam_id = ?
              AND r.status IN ('submitted', 'completed')
            ORDER BY r.score DESC
        `;
        db.all(sql, [examId], (err, rows) => {
            if (err) {
                console.error(`[RESULTS] Results query error for exam ${examId}:`, err.message);
                return res.status(500).json({ error: "Failed to fetch results" });
            }
            console.log(`[RESULTS] Exam ${examId} ("${examTitle}"): returning ${rows.length} submission(s) to professor ${req.user.id}`);
            res.json({ exam_title: examTitle, results: rows || [] });
        });
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
    const { title, group_id, duration_minutes, q_display_count, shuffle_questions, shuffle_options, prevent_backtracking } = req.body;
    db.run(`INSERT INTO Exams (professor_id, group_id, title, duration_minutes, q_display_count, shuffle_questions, shuffle_options, prevent_backtracking) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [req.user.id, group_id, title, duration_minutes, q_display_count || null, shuffle_questions ? 1 : 0, shuffle_options ? 1 : 0, prevent_backtracking ? 1 : 0], function(err) {
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


// 7. Download ZIP Template
app.get('/api/prof/template-zip', professorAuth, (req, res) => {
    const zip = new AdmZip();
    const csvContent = 
`\uFEFFq_type,question_text,options_separated_by_pipe,correct_answer,points,image_filename
mcq,What is the capital of France?,Paris|London|Berlin|Madrid,Paris,1,
tf,Water boils at 100 degrees Celsius.,True|False,True,1,
fib,The matrix determinant of [blank] is [blank].,,"42, Matrix",2,
ma,Which of these are primary colors?,Red|Green|Blue|Yellow,"[""Red"",""Blue""]",2,sky.jpg`;

    zip.addFile("questions.csv", Buffer.from(csvContent, "utf8"));
    zip.addFile("images/sky.jpg", Buffer.from("fake image content")); // Folder placeholder
    
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
                    
                    let finalOptions = "[]";
                    // 1. Check for the universal column
                    if (row.options_separated_by_pipe) {
                        finalOptions = JSON.stringify(row.options_separated_by_pipe.split('|').map(s => s.trim()));
                    } 
                    // 2. Fallback for old templates (option_a, b, etc.)
                    else if (row.option_a || row.option_b) {
                        const legacyArr = [row.option_a, row.option_b, row.option_c, row.option_d].filter(o => o && o.trim() !== "");
                        finalOptions = JSON.stringify(legacyArr);
                    }
                    // 3. Last fallback for direct exports
                    else if (row.options) {
                        finalOptions = row.options;
                    }
                    
                    db.run(`INSERT INTO Questions (exam_id, q_type, question_text, image_url, options, correct_answer, points) VALUES (?, ?, ?, ?, ?, ?, ?)`, 
                    [req.params.examId, row.q_type, row.question_text, imgUrl, finalOptions, row.correct_answer, row.points || 1], () => {
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
    db.get(`SELECT * FROM Students WHERE university_id = ? AND password = ?`, [university_id, password], (err, student) => {
        if (err || !student) return res.status(401).json({ success: false, error: "Invalid credentials" });
        
        // FIX: We MUST include the group_id in the token so they can see their assigned exams!
        const token = jwt.sign({ 
            id: student.id, 
            university_id: student.university_id,
            name: student.name,
            group_id: student.group_id, 
            role: 'student' 
        }, JWT_SECRET, { expiresIn: '4h' });
        
        res.json({ success: true, token, name: student.name });
    });
});

// Change Student Password
app.put('/api/student/change-password', studentAuth, (req, res) => {
    const studentId = req.studentId; // FIXED: Using correct token variable
    const { newPassword } = req.body;

    if (!newPassword || newPassword.length < 4) {
        return res.status(400).json({ success: false, error: "Password must be at least 4 characters long." });
    }

    db.run(`UPDATE Students SET password = ? WHERE id = ?`, [newPassword, studentId], function(err) {
        if (err) return res.status(500).json({ success: false, error: "Database error while updating password." });
        res.json({ success: true, message: "Password updated successfully!" });
    });
});

// 2. Get Active Exams for this Student
app.get('/api/student/exams', studentAuth, (req, res) => {
    const studentId = req.studentId; 

    // Returns active exams not yet submitted; in-progress exams still appear for resumption.
    const sql = `
        SELECT DISTINCT e.id, e.title, e.duration_minutes, p.name as professor_name,
            (SELECT status FROM Results WHERE exam_id = e.id AND student_id = ? LIMIT 1) as my_status
        FROM Exams e
        JOIN Professors p ON e.professor_id = p.id
        LEFT JOIN Student_Groups sg ON e.group_id = sg.group_id
        WHERE (sg.student_id = ? OR e.group_id IS NULL OR e.group_id = 0)
        AND e.is_active = 1
        AND e.id NOT IN (SELECT exam_id FROM Results WHERE student_id = ? AND status IN ('submitted', 'completed'))
    `;

    db.all(sql, [studentId, studentId, studentId], (err, exams) => {
        if (err) {
            console.error("Database Error:", err.message);
            return res.status(500).json({ error: "Failed to fetch exams" });
        }
        res.json(exams || []);
    });
});

// 3. Get Exam Details and Questions (With Shuffling and Selection)
app.get('/api/student/exam/:examId', studentAuth, (req, res) => {
    const examId = req.params.examId;
    const studentId = req.studentId;

    const verifySql = `
        SELECT e.* FROM Exams e
        JOIN Student_Groups sg ON e.group_id = sg.group_id
        WHERE e.id = ? AND sg.student_id = ? AND e.is_active = 1
    `;

    db.get(verifySql, [examId, studentId], (err, exam) => {
        if (err) return res.status(500).json({ success: false, error: "Database error" });
        if (!exam) return res.status(403).json({ success: false, error: "Exam not available." });

        // --- STRICT SESSION LOCK (runs before questions are served) ---
        db.get(
            `SELECT id, status, started_at FROM Results WHERE exam_id = ? AND student_id = ?`,
            [examId, studentId],
            (sessErr, session) => {
                if (sessErr) {
                    console.error('[GET EXAM] Session lookup error:', sessErr.message);
                    return res.status(500).json({ success: false, error: 'Database error checking session.' });
                }

                // Condition B: Already finalised — deny access
                if (session && (session.status === 'submitted' || session.status === 'completed')) {
                    return res.status(403).json({ success: false, error: 'You have already submitted this exam or were locked out for leaving the page.' });
                }

                const serveExam = (startTime, isResuming) => {
                    const qSql = `SELECT id, q_type, question_text, image_url, options, points FROM Questions WHERE exam_id = ?`;
                    db.all(qSql, [examId], (err, questions) => {
                        if (err) return res.status(500).json({ success: false, error: "Error fetching questions" });

                        // Shuffle questions if enabled
                        if (exam.shuffle_questions === 1) questions.sort(() => Math.random() - 0.5);

                        // Limit to display count
                        if (exam.q_display_count && exam.q_display_count > 0) {
                            questions = questions.slice(0, exam.q_display_count);
                        }

                        // Parse + shuffle options
                        questions.forEach(q => {
                            try {
                                q.options = q.options ? JSON.parse(q.options) : [];
                                if (exam.shuffle_options === 1 && q.q_type === 'mcq') {
                                    q.options.sort(() => Math.random() - 0.5);
                                }
                            } catch (e) { q.options = []; }
                        });

                        res.json({
                            success: true,
                            exam: {
                                title: exam.title,
                                duration_minutes: exam.duration_minutes,
                                prevent_backtracking: exam.prevent_backtracking || 0
                            },
                            questions,
                            start_time: startTime,
                            is_resuming: isResuming
                        });
                    });
                };

                if (session && session.status === 'in_progress') {
                    // Condition C: Resume — return original start_time, no new record
                    console.log(`[GET EXAM] Resuming session for student ${studentId}, exam ${examId}`);
                    serveExam(session.started_at, true);
                } else {
                    // Condition A: First visit — create in_progress record
                    db.run(
                        `INSERT INTO Results (exam_id, student_id, score, max_score, status, started_at) VALUES (?, ?, 0, 0, 'in_progress', datetime('now'))`,
                        [examId, studentId],
                        function(insertErr) {
                            if (insertErr) {
                                console.error('[GET EXAM] INSERT session error:', insertErr.message);
                                return res.status(500).json({ success: false, error: 'Failed to register session.' });
                            }
                            // Re-read the stored timestamp so the client gets exactly what SQLite stored
                            db.get(
                                `SELECT started_at FROM Results WHERE id = ?`,
                                [this.lastID],
                                (readErr, row) => {
                                    if (readErr || !row) {
                                        console.error('[GET EXAM] Re-read started_at error:', readErr && readErr.message);
                                        return res.status(500).json({ success: false, error: 'Failed to read session timestamp.' });
                                    }
                                    console.log(`[GET EXAM] New session created for student ${studentId}, exam ${examId}, started_at: ${row.started_at}`);
                                    serveExam(row.started_at, false);
                                }
                            );
                        }
                    );
                }
            }
        );
    });
});

// 4. Start Exam — session was already created by GET; just computes remaining time
app.post('/api/student/exam/:examId/start', studentAuth, (req, res) => {
    const examId = req.params.examId;
    const studentId = req.studentId;

    const sql = `
        SELECT e.duration_minutes, r.status, r.started_at
        FROM Exams e
        JOIN Results r ON r.exam_id = e.id AND r.student_id = ?
        WHERE e.id = ?
    `;
    db.get(sql, [studentId, examId], (err, row) => {
        if (err) {
            console.error('[START] Query error:', err.message);
            return res.status(500).json({ success: false, error: 'Database error.' });
        }
        if (!row) return res.status(404).json({ success: false, error: 'Session not found. Please reload the page.' });
        if (row.status === 'submitted' || row.status === 'completed') return res.status(400).json({ success: false, error: 'This exam has already been submitted.' });

        try {
            const startedMs = new Date((row.started_at || '').replace(' ', 'T') + 'Z').getTime();
            const elapsed = isNaN(startedMs) ? 0 : Math.floor((Date.now() - startedMs) / 1000);
            const remaining = Math.max(0, row.duration_minutes * 60 - elapsed);
            return res.json({ success: true, timeRemaining: remaining });
        } catch (e) {
            console.error('[START] Date parse error:', e.message);
            return res.json({ success: true, timeRemaining: row.duration_minutes * 60 });
        }
    });
});

// 5. Submit Exam and Auto-Grade (Corrected for Random Subsets)
app.post('/api/student/exam/:examId/submit', studentAuth, (req, res) => {
    const examId = req.params.examId;
    const studentId = req.studentId;
    const studentAnswers = req.body.answers || {};
    
    // NEW: The frontend should send the list of IDs the student actually saw
    // If your frontend doesn't send this yet, we will fallback to the IDs in studentAnswers
    const servedQuestionIds = req.body.servedQuestionIds || Object.keys(studentAnswers);

    db.get(`SELECT id, status FROM Results WHERE exam_id = ? AND student_id = ?`, [examId, studentId], (err, existingResult) => {
        if (existingResult && (existingResult.status === 'submitted' || existingResult.status === 'completed')) return res.status(400).json({ success: false, error: "Already submitted." });

        // Fetch ONLY the questions that were actually served to this student
        const placeholders = servedQuestionIds.map(() => '?').join(',');
        const sql = `SELECT id, q_type, correct_answer, points FROM Questions WHERE id IN (${placeholders}) AND exam_id = ?`;
        
        db.all(sql, [...servedQuestionIds, examId], (err, questions) => {
            if (err) return res.status(500).json({ error: "Grading error" });

            let totalScore = 0;
            let maxScore = 0;

            // --- IMPROVED GRADING LOGIC ---
            questions.forEach(q => {
                maxScore += q.points;
                const studentAns = studentAnswers[q.id];
                if (!studentAns) return;

                let isCorrect = false;

                if (q.q_type === 'fib') {
                    // 1. Handle FIB: Allow match against any comma-separated value
                    const studentClean = String(studentAns).toLowerCase().trim();
                    const acceptableAnswers = String(q.correct_answer).split(',').map(a => a.toLowerCase().trim());
                    
                    if (acceptableAnswers.includes(studentClean)) {
                        isCorrect = true;
                    }
                } 
                else if (q.q_type === 'ma') {
                    // 2. Handle Multiple Answer: Ensure arrays are sorted for comparison
                    // Student answer is already an array from student_exam.html
                    // Correct answer might be a JSON string like '["Opt A", "Opt B"]'
                    try {
                        let correctArr = JSON.parse(q.correct_answer);
                        if (Array.isArray(studentAns) && Array.isArray(correctArr)) {
                            const sSorted = studentAns.map(s => String(s).toLowerCase().trim()).sort().join('|');
                            const cSorted = correctArr.map(c => String(c).toLowerCase().trim()).sort().join('|');
                            if (sSorted === cSorted) isCorrect = true;
                        }
                    } catch (e) {
                        // Fallback for non-JSON strings
                        if (String(q.correct_answer).toLowerCase().trim() === String(studentAns).toLowerCase().trim()) isCorrect = true;
                    }
                } 
                else {
                    // 3. Handle MCQ and True/False: Standard direct match
                    if (String(q.correct_answer).toLowerCase().trim() === String(studentAns).toLowerCase().trim()) {
                        isCorrect = true;
                    }
                }

                if (isCorrect) totalScore += q.points;
            });

            const violations = req.body.violations || 0;
            if (existingResult) {
                // Update the in-progress placeholder record
                db.run(
                    `UPDATE Results SET score = ?, max_score = ?, violations = ?, status = 'submitted', timestamp = CURRENT_TIMESTAMP WHERE exam_id = ? AND student_id = ?`,
                    [totalScore, maxScore, violations, examId, studentId],
                    function(err) {
                        if (err) return res.status(500).json({ error: "Failed to save results." });
                        res.json({ success: true, score: totalScore, maxScore: maxScore });
                    }
                );
            } else {
                // Fallback: direct submit without prior session registration
                db.run(
                    `INSERT INTO Results (exam_id, student_id, score, max_score, violations, status) VALUES (?, ?, ?, ?, ?, 'submitted')`,
                    [examId, studentId, totalScore, maxScore, violations],
                    function(err) {
                        if (err) return res.status(500).json({ error: "Failed to save results." });
                        res.json({ success: true, score: totalScore, maxScore: maxScore });
                    }
                );
            }
        });
    });
});

// 5a. Beacon Submit — fires when navigator.sendBeacon() triggers on page hide
// Cannot use studentAuth (sendBeacon can't set custom headers); token arrives in body.
app.post('/api/student/exam/beacon-submit',
    express.text({ type: '*/*' }), // fallback: capture body if Content-Type wasn't application/json
    (req, res) => {
        // Parse payload: object if express.json() handled it, string if express.text() handled it
        let payload;
        try {
            payload = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
            if (!payload || typeof payload !== 'object') throw new Error('bad payload');
        } catch(e) {
            return res.status(400).end();
        }

        const { token, examId, answers, servedQuestionIds, violations: viol } = payload;
        if (!token || !examId) return res.status(400).end();

        // Verify JWT from payload
        let studentId;
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            if (decoded.role !== 'student') return res.status(403).end();
            studentId = decoded.id;
        } catch(e) {
            console.error('[BEACON] Invalid token:', e.message);
            return res.status(401).end();
        }

        const studentAnswers = answers || {};
        const questionIds = Array.isArray(servedQuestionIds) && servedQuestionIds.length
            ? servedQuestionIds
            : Object.keys(studentAnswers);
        const finalViolations = viol || 0;

        // Don't overwrite an already-final record
        db.get(`SELECT id, status FROM Results WHERE exam_id = ? AND student_id = ?`,
            [examId, studentId],
            (err, existing) => {
                if (err) { console.error('[BEACON] DB lookup error:', err.message); return res.status(500).end(); }
                if (existing && (existing.status === 'submitted' || existing.status === 'completed')) {
                    return res.status(200).end(); // already finalised — silently accept
                }

                const saveResult = (score, maxScore) => {
                    if (existing) {
                        db.run(
                            `UPDATE Results SET score=?, max_score=?, violations=?, status='completed', timestamp=CURRENT_TIMESTAMP WHERE exam_id=? AND student_id=?`,
                            [score, maxScore, finalViolations, examId, studentId],
                            (err) => { if (err) console.error('[BEACON] UPDATE error:', err.message); }
                        );
                    } else {
                        db.run(
                            `INSERT INTO Results (exam_id, student_id, score, max_score, violations, status) VALUES (?, ?, ?, ?, ?, 'completed')`,
                            [examId, studentId, score, maxScore, finalViolations],
                            (err) => { if (err) console.error('[BEACON] INSERT error:', err.message); }
                        );
                    }
                    console.log(`[BEACON] Forced submit — student ${studentId}, exam ${examId}, score ${score}/${maxScore}`);
                    res.status(200).end();
                };

                if (!questionIds.length) return saveResult(0, 0);

                const placeholders = questionIds.map(() => '?').join(',');
                db.all(
                    `SELECT id, q_type, correct_answer, points FROM Questions WHERE id IN (${placeholders}) AND exam_id = ?`,
                    [...questionIds, examId],
                    (err, questions) => {
                        if (err) { console.error('[BEACON] Grade query error:', err.message); return res.status(500).end(); }

                        let totalScore = 0, maxScore = 0;
                        (questions || []).forEach(q => {
                            maxScore += q.points;
                            const ans = studentAnswers[q.id];
                            if (!ans) return;
                            let ok = false;
                            if (q.q_type === 'fib') {
                                const clean = String(ans).toLowerCase().trim();
                                const acceptable = String(q.correct_answer).split(',').map(a => a.toLowerCase().trim());
                                if (acceptable.includes(clean)) ok = true;
                            } else if (q.q_type === 'ma') {
                                try {
                                    const correctArr = JSON.parse(q.correct_answer);
                                    if (Array.isArray(ans) && Array.isArray(correctArr)) {
                                        const ss = ans.map(s => String(s).toLowerCase().trim()).sort().join('|');
                                        const cs = correctArr.map(c => String(c).toLowerCase().trim()).sort().join('|');
                                        if (ss === cs) ok = true;
                                    }
                                } catch(e) {
                                    if (String(q.correct_answer).toLowerCase().trim() === String(ans).toLowerCase().trim()) ok = true;
                                }
                            } else {
                                if (String(q.correct_answer).toLowerCase().trim() === String(ans).toLowerCase().trim()) ok = true;
                            }
                            if (ok) totalScore += q.points;
                        });
                        saveResult(totalScore, maxScore);
                    }
                );
            }
        );
    }
);

// 5b. Auto-Save Endpoint (backs up in-progress answers to memory)
app.post('/api/student/autosave', studentAuth, (req, res) => {
    const { examId, answers, timeRemaining } = req.body;
    autosaveStore.set(req.studentId, { examId, answers, timeRemaining, savedAt: Date.now() });
    res.json({ success: true });
});

// ==========================================
// QR CODE LOBBY — HOST IP DETECTION
// ==========================================
function getLocalIP() {
    const interfaces = os.networkInterfaces();
    let fallbackIp = 'localhost';
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            // Only care about IPv4 and non-internal
            if (iface.family === 'IPv4' && !iface.internal) {
                // STRICTLY BAN VirtualBox (192.168.56.x) and APIPA (169.254.x.x)
                if (iface.address.startsWith('192.168.56.') || iface.address.startsWith('169.254.')) {
                    continue;
                }
                // If it's a Wi-Fi or Wireless adapter, return immediately
                if (name.toLowerCase().includes('wi-fi') || name.toLowerCase().includes('wlan') || name.toLowerCase().includes('wireless')) {
                    return iface.address;
                }
                // Otherwise, save it as a fallback just in case
                fallbackIp = iface.address;
            }
        }
    }
    return fallbackIp;
}

app.get('/api/get-host-ip', async (req, res) => {
    const ip = getLocalIP();
    const PORT_NUM = process.env.PORT || 80;
    const url = (PORT_NUM == 80)
        ? `http://${ip}/student-login.html`
        : `http://${ip}:${PORT_NUM}/student-login.html`;
    try {
        const qrDataUrl = await QRCode.toDataURL(url, {
            width: 400,
            margin: 2,
            color: { dark: '#1E1B4B', light: '#FFFFFF' }
        });
        res.json({ success: true, ip, url, qrDataUrl });
    } catch (err) {
        res.json({ success: false, ip, url, qrDataUrl: null, error: err.message });
    }
});

// Start Server
const PORT = process.env.PORT || 80;
app.listen(PORT, () => console.log(`SLEP v3.0 Server running on port ${PORT}`));