🎓 SLEP v3.0 - Secure Local Exam Portal
SLEP (Secure Local Exam Portal) is a robust, lightweight, and fully automated Role-Based Exam Management System. Built with Node.js and SQLite, it is designed for institutions that need to conduct high-stakes digital exams over a Local Area Network (LAN) without relying on internet connectivity or expensive cloud hosting.

✨ New in v3.0: High-Security "Kiosk Mode"
The latest version introduces military-grade exam integrity features:

Auto-Submit on Leave: If a student switches tabs, minimizes the browser, or attempts to navigate away, the exam is instantly submitted and locked.

Server-Side Timer Sync: The exam clock is tied to the server. Closing the browser or refreshing the page does not reset the timer.

Anti-Cheat Randomization: Fisher-Yates shuffling for both Question order and MCQ/Checkbox options ensures no two students have the same test layout.

Resumption Logic: If a student’s computer crashes, they can log back in and resume exactly where they left off—but only if the server-side timer hasn't expired.

👨‍🏫 Core Features
🛡️ Super Admin Portal
Professor Management: Manually add professors or bulk-import them using CSV files.

Master Security: Protected by a dedicated master key defined in the .env file.

👨‍🏫 Professor Dashboard
Exam Architect: Build MCQ, True/False, and Multi-Answer (Checkbox) exams.

Bulk Image Import: Upload complete exams (Questions + Images) instantly via .zip templates.

Result Analytics: Real-time grading with CSV export for Excel.

Violation Tracking: See exactly which students were flagged for attempting to leave the exam screen.

👨‍🎓 Student Portal
Group-Based Access: Students only see exams assigned to their specific group/class.

Optimized UI: Centered, high-resolution image support and clean, distraction-free testing interface.

🌐 Networking: Allowing Other Devices to Access
By default, Windows and Mac firewalls often block external devices from connecting to your local server. For students to access the exam from their own laptops/tablets:

Find your Local IP: Open Terminal/CMD and type ipconfig (Windows) or ifconfig (Mac). Look for the IPv4 Address (e.g., 192.168.1.15).

Firewall Exception: * Go to Windows Defender Firewall > Advanced Settings.

Create a new Inbound Rule.

Select Port, then enter 80 (or the port your server uses).

Select Allow the connection.

Student Access: Students will navigate to http://YOUR-IP-ADDRESS instead of localhost.

🚀 One-Click Setup
Prerequisites
Node.js (LTS Version recommended).

Windows
Double-click start.bat. It handles dependency installation, .env generation, and server startup automatically.

Mac / Linux
Open Terminal in the project folder.

Run chmod +x start.command.

Run ./start.command.

🔐 Security Configuration
On the first run, the system generates a .env file.

Default Admin Key: superadmin123 (Change this immediately for real exams!).

Database: Powered by SQLite (database.sqlite). No external SQL server required.