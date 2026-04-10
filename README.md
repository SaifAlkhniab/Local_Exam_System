# Secure LAN Exam Platform (SLEP)

## Overview
A secure, local-network-based examination platform designed for university environments. It operates completely offline via a local Wi-Fi router, ensuring maximum security and zero reliance on external internet.

## Core Features
* **Multi-Subject Support:** Dynamic exam creation for any academic subject.
* **Question Types:** Supports Multiple Choice (MCQ) and case-insensitive Fill-in-the-Blank.
* **Advanced Anti-Cheating:** - Enforced fullscreen mode.
  - Tab-switching detection and logging.
  - Disabled right-click, copy/paste, and text selection.
  - Device-locking via browser fingerprinting.
  - Question and Option randomization per student.
* **Pre-Exam Lobby & Practice:** Students must agree to academic policies before starting. A practice sandbox is available to test connections.
* **Automated & Fail-safe:** Auto-grades upon submission. Auto-submits if the timer expires. Safe queuing for high-traffic submissions (Raspberry Pi compatible).
* **Admin Dashboard:** Hidden portal for real-time monitoring, inline image uploads, CSV bulk question imports, and CSV grade exports.

## Installation & Setup
1. Ensure Node.js (v20+) is installed.
2. Run `npm install` to download dependencies.
3. Start the server: `npm run dev`
4. Access the system via the host machine's IP address on the LAN.
5. Admin Portal: `http://localhost/admin-k5y43z8-exam.html` (Update password in server configuration).