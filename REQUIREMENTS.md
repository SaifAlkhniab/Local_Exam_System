# Secure LAN Exam Platform (SLEP) - Architecture Blueprint v3.0

## 1. System Overview
SLEP is a lightweight, offline-first, Multi-Tenant Learning Management System (LMS) designed specifically for university lab environments. It operates over a local network (LAN) without internet reliance. The system handles high concurrency from lab PCs while maintaining a tiny server footprint by heavily utilizing asynchronous queuing and stateless file routing.

## 2. User Hierarchy & Access Control

### A. Super Admin (IT / System Manager)
* **Authentication:** Accessed via `/superadmin.html`. Protected by a secure master password stored in the server's `.env` file via `x-admin-key` headers.
* **Scope:** Global Faculty Management. Isolated from academic data (cannot view exams or student grades) to keep the interface clean and secure.
* **Capabilities:** Create, Read, Update, Delete (CRUD) Professor accounts, and bulk CSV ingestion.

### B. Professor (Faculty)
* **Authentication:** Authenticates via `/api/login` and receives a secure JSON Web Token (JWT).
* **Scope:** Complete Data Isolation. A Professor can only access their own students, groups, exams, and results.
* **Capabilities:**
    * **Exam Management:** Create exams manually or via automated `.zip` ingestion (extracting CSVs and static images simultaneously).
    * **Student & Group Management:** Group mapping ensures exams are isolated to specific cohorts.

### C. Student (Examinee)
* **Authentication:** Authenticates via `/api/login` using credentials created by their Professor. Receives a secure JWT.
* **Scope:** Can only view and interact with "Active" exams assigned to their specific Group ID.

## 3. Core Engine Features

### A. Exam Execution & Anti-Cheating
* **Environment Lock:** Enforced full-screen browser. Tab-switching is logged as an academic violation. Right-click, text highlighting, and copy/paste are disabled.
* **Randomization:** Question order and MCQ option order are uniquely shuffled for every individual student.
* **Auto-Submit:** If the time limit expires, current answers are automatically submitted.

### B. System Performance & Data Flow
* **Relational Database Mapping:** Uses SQLite with bridge tables (e.g., `Student_Groups`) to cleanly handle many-to-many relationships without data duplication. 
* **Stateless Image Handling:** Images are served directly via static file routing, minimizing memory load on the Node.js application.

## 4. Tech Stack
* **Backend:** Node.js, Express.js.
* **Database:** SQLite (Self-contained, serverless database automatically built on initialization).
* **Frontend:** Vanilla HTML, CSS, JavaScript (Zero external dependencies).
* **Middleware:** `jsonwebtoken` (Auth), `multer` (file uploads), `csv-parser` (bulk data ingestion), `adm-zip` (archive extraction).