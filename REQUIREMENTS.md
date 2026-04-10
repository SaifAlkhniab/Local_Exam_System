# Secure LAN Exam Platform (SLEP) - Architecture Blueprint v2.0

## 1. System Overview
SLEP is a lightweight, offline-first, Multi-Tenant Learning Management System (LMS) designed specifically for university lab environments. It operates over a local network (LAN) without internet reliance. The system is designed to handle high concurrency from lab PCs while maintaining a tiny server footprint by heavily utilizing asynchronous queuing.

## 2. User Hierarchy & Access Control

### A. Super Admin (IT / System Manager)
* **Authentication:** Hidden URL (e.g., `/sys-admin-portal`). No database login; protected by a secure password stored in the server's `.env` file.
* **Scope:** Global Faculty Management. Isolated from academic data (cannot view exams or student grades) to keep the interface clean and fast.
* **Capabilities:**
    * Create, Read, Update, Delete (CRUD) Professor accounts.
    * Bulk Import: Upload CSV to create multiple Professor accounts instantly.
    * Bulk Export: Download current Professor roster as CSV.

### B. Professor (Faculty)
* **Authentication:** Standard portal login using credentials issued by the Super Admin.
* **Scope:** Complete Data Isolation. A Professor can only access their own students, groups, exams, and results.
* **Capabilities:**
    * **Student Management:** Add/Edit/Delete students individually or via CSV upload. Reset forgotten student passwords.
    * **Group Management:** Create logical groupings (e.g., "Network Security Lab A"). Assign students to these groups. *Note: A single student can belong to multiple groups under different professors.*
    * **Exam Management:** Create exams, add questions (Multiple Choice, Fill-in-the-Blank), upload reference images, and bulk-import questions via CSV.
    * **Deployment:** Activate exams for specific target Groups.
    * **Analytics:** View real-time active test-takers, review graded submissions, and export group results as CSV.

### C. Student
* **Authentication:** Standard portal login. First-time login uses a default password (e.g., their University ID) which they are prompted to change.
* **Scope:** Can only see exams assigned to their specific Groups by their Professors.
* **Capabilities:**
    * **Dashboard:** View active exams waiting for them.
    * **Test-Taking:** Enter the secure, full-screen exam environment (anti-cheat enabled).
    * **History:** View a list of past taken exams, dates, and finalized grades (grades appear only after the Professor officially closes the exam to prevent answer-sharing).
    * **Account:** Change personal password and log out.

### D. Planned Future Roles (Extendable Structure)
* **Coordinator:** A specialized role that has read-only access to specific groups across *multiple* professors. Designed for department heads to aggregate grades without needing manual CSVs from individual faculty members.

## 3. Core Engine Features

### A. Exam Execution & Anti-Cheating
* **Device Lock:** One session per student per exam.
* **Environment Lock:** Enforced full-screen browser. Tab-switching is logged as an academic violation. Right-click, text highlighting, and copy/paste are disabled.
* **Randomization:** Question order and MCQ option order (A, B, C, D) are uniquely shuffled for every individual student.
* **Auto-Submit:** If the time limit expires, current answers are automatically submitted.

### B. System Performance & Data Flow
* **Asynchronous Grading Queue:** To allow the system to run on hardware as humble as a standard laptop or Raspberry Pi, exam submissions are queued. When 100 students hit "Submit" simultaneously, the server instantly accepts the payload, closes their exam, and grades them sequentially in the background.
* **Relational Database Mapping:** Uses SQLite with bridge tables (e.g., `Student_Groups`) to cleanly handle many-to-many relationships without data duplication. 
* **Stateless Image Handling:** Images are served directly via static file routing, minimizing memory load on the Node.js application.

## 4. Tech Stack
* **Backend:** Node.js, Express.js.
* **Database:** SQLite (Self-contained, serverless database).
* **Frontend:** Vanilla HTML, CSS, JavaScript (Zero external CDN dependencies to ensure 100% offline functionality).
* **Middleware:** `multer` (file uploads), `csv-parser` (bulk data ingestion), `cors`.