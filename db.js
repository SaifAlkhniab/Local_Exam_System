const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const db = new sqlite3.Database(path.join(__dirname, 'exam_system.db'), (err) => {
    if (err) console.error(err.message);
    else {
        console.log('Connected to the SQLite database (v3.0 Architecture).');
        db.run("PRAGMA foreign_keys = ON");
        db.serialize(() => {
            
            // 1. Professors Table
            db.run(`CREATE TABLE IF NOT EXISTS Professors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                name TEXT NOT NULL,
                is_active BOOLEAN DEFAULT 1
            )`);

            // 2. Students Table
            db.run(`CREATE TABLE IF NOT EXISTS Students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                university_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                password TEXT NOT NULL,
                is_active BOOLEAN DEFAULT 1
            )`);

            // 3. Groups Table
            db.run(`CREATE TABLE IF NOT EXISTS Groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                professor_id INTEGER NOT NULL,
                group_name TEXT NOT NULL,
                FOREIGN KEY(professor_id) REFERENCES Professors(id)
            )`);

            // 4. Student-Group Mapping (Many-to-Many)
            db.run(`CREATE TABLE IF NOT EXISTS Student_Groups (
                student_id INTEGER NOT NULL,
                group_id INTEGER NOT NULL,
                PRIMARY KEY (student_id, group_id),
                FOREIGN KEY(student_id) REFERENCES Students(id),
                FOREIGN KEY(group_id) REFERENCES Groups(id)
            )`);

            // 5. Policy Templates (Restored!)
            db.run(`CREATE TABLE IF NOT EXISTS Policies (
                id INTEGER PRIMARY KEY,
                title TEXT NOT NULL,
                rules_text TEXT NOT NULL
            )`);

            // 6. Exams Table (Added Shuffling and Display Counts)
            db.run(`CREATE TABLE IF NOT EXISTS Exams (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                professor_id INTEGER NOT NULL,
                group_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                duration_minutes INTEGER NOT NULL,
                q_display_count INTEGER DEFAULT NULL,
                shuffle_questions BOOLEAN DEFAULT 0,
                shuffle_options BOOLEAN DEFAULT 0,
                policy_id INTEGER,
                is_active BOOLEAN DEFAULT 0,
                is_closed BOOLEAN DEFAULT 0, 
                FOREIGN KEY(professor_id) REFERENCES Professors(id),
                FOREIGN KEY(group_id) REFERENCES Groups(id)
            )`);

            // 7. Questions Table (With CASCADE DELETE)
            db.run(`CREATE TABLE IF NOT EXISTS Questions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                exam_id INTEGER NOT NULL,
                q_type TEXT DEFAULT 'mcq', 
                question_text TEXT NOT NULL,
                image_url TEXT,
                options TEXT, 
                correct_answer TEXT NOT NULL,
                points INTEGER DEFAULT 1,
                FOREIGN KEY(exam_id) REFERENCES Exams(id) ON DELETE CASCADE
            )`, (err) => {
                if (!err) {
                    // MIGRATION: If the user has an old DB, the 'options' column might be missing.
                    // This code safely adds it if it doesn't exist.
                    db.run(`ALTER TABLE Questions ADD COLUMN options TEXT`, (err) => {
                        if (!err) console.log("Migration: Added 'options' column to Questions table.");
                    });
                }
            });

            // 8. Results Table
            db.run(`CREATE TABLE IF NOT EXISTS Results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                exam_id INTEGER NOT NULL,
                student_id INTEGER NOT NULL,
                score INTEGER NOT NULL,
                max_score INTEGER NOT NULL,
                violations INTEGER DEFAULT 0,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(exam_id) REFERENCES Exams(id),
                FOREIGN KEY(student_id) REFERENCES Students(id)
            )`);

            // Insert Default Policy
            const defaultPolicy = `1. Fullscreen Required. 2. No Tab Switching. 3. No Copy/Pasting. 4. Timer cannot be paused. 5. One device only.`;
            db.run(`INSERT OR IGNORE INTO Policies (id, title, rules_text) VALUES (1, 'Default Strict Policy', ?)`, [defaultPolicy]);
        });
    }
});

module.exports = db;