const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;

// Serve frontend files from public folder
app.use(express.static('public'));

// Setup multer for file uploads (store in uploads folder temporarily)
const upload = multer({ dest: 'uploads/' });

// Upload endpoint
app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).send('No file uploaded');

  // Send back the file info and URL to download
  res.json({
    filename: req.file.filename,
    originalname: req.file.originalname,
    url: `/files/${req.file.filename}`
  });
});

// Download endpoint
app.get('/files/:filename', (req, res) => {
  const filePath = path.join(__dirname, 'uploads', req.params.filename);

  // Check if file exists
  fs.access(filePath, fs.constants.F_OK, (err) => {
    if (err) return res.status(404).send('File not found');

    // Send file for download
    res.download(filePath, (err) => {
      if (!err) {
        // Delete file after successful download
        fs.unlink(filePath, (err) => {
          if (err) console.error('Error deleting file:', err);
          else console.log(`Deleted file: ${req.params.filename}`);
        });
      }
    });
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
