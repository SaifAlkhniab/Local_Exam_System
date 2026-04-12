# 🎓 SLEP v3.0 - Secure Local Exam Portal

SLEP is a lightweight, secure, and fully automated Role-Based Exam Management System built with Node.js and SQLite. It provides a seamless experience for administrators, professors, and students, allowing institutions to conduct, grade, and export digital exams locally without needing complex cloud infrastructure.

## ✨ Features

### 🛡️ Super Admin Portal
* **Professor Management:** Manually add professors or bulk-import them using CSV files.
* **Secure Access:** Protected by a dedicated master key defined in the `.env` file.

### 👨‍🏫 Professor Dashboard
* **Exam Creation:** Create Multiple Choice (MCQ), True/False, and Fill-in-the-blank exams.
* **Bulk Import:** Upload complete exams (Questions + Images) instantly using a formatted `.zip` template.
* **Group Management:** Assign students to specific groups so they only see exams meant for them.
* **Live Grading & Export:** System automatically grades exams upon submission. Export full results and analytics to CSV for Excel.
* **Account Security:** Professors can securely change their own passwords.

### 👨‍🎓 Student Portal
* **Assigned Exams:** Students only see "Active" exams assigned to their specific group.
* **Secure Testing:** Features a built-in timer, randomized grading logic, and automatic submission when time runs out.
* **Instant Feedback:** Students instantly see their final score upon submission.

## 🚀 Quick Start (One-Click Setup)

We have made running this server incredibly easy. **You do not need to configure databases or manually install dependencies on your first run.**

### Prerequisites
* You must have [Node.js](https://nodejs.org/) installed on your computer.

### Windows Users
1. Download or clone this repository.
2. Double-click the **`start.bat`** file.
3. The script will automatically install dependencies, create your `.env` file, and start the server.

### Mac / Linux Users
1. Download or clone this repository.
2. Open your terminal and navigate to the folder.
3. Run `chmod +x start.command` (only needed the first time).
4. Double-click **`start.command`** or run `./start.command`.

## 🔐 Default Configuration & First Login

When you run the system for the first time, it auto-generates an `.env` file with your security keys. 
* **Access the site:** `http://localhost`
* **Super Admin Setup:** Navigate to `http://localhost/superadmin.html` and enter the default Admin Key: `superadmin123` (Change this in your `.env` file for production!). Create your first Professor account to get started.