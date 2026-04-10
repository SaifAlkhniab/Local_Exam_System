const db = require('./db');

// We insert one general test question into the Questions table
const insertQuery = `
    INSERT INTO Questions (question_text, image_url, option_a, option_b, option_c, option_d, correct_answer)
    VALUES (?, ?, ?, ?, ?, ?, ?)
`;

const testQuestion = [
    "What is the standard resolution of a 4K display?", 
    null, // No image for this test question
    "1920 x 1080", 
    "2560 x 1440", 
    "3840 x 2160", 
    "7680 x 4320", 
    "option_c"
];

db.run(insertQuery, testQuestion, function(err) {
    if (err) {
        console.error("Error inserting question:", err.message);
    } else {
        console.log(`Success! Test question added with ID: ${this.lastID}`);
    }
    db.close(); // Close connection after inserting
});