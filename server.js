const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const session = require('express-session');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "http://localhost:3000", // Ensure this matches your frontend URL
        methods: ["GET", "POST"]
    }
});

const PORT = process.env.PORT || 3000;

// --- Middleware ---
app.use(bodyParser.json());
// Serve static files from the 'public' directory (where index.html and uploads will reside)
app.use(express.static(path.join(__dirname, 'public')));

// Ensure uploads directory exists
const UPLOADS_DIR = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) {
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

const sessionMiddleware = session({
    secret: 'a_very_secret_key_that_is_long_and_random_for_production', // **CHANGE THIS** to a strong, unique, random key
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24, // 1 day
        secure: process.env.NODE_ENV === 'production' // Set to true if serving over HTTPS
    }
});

app.use(sessionMiddleware);

// --- Multer Setup for File Uploads ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOADS_DIR);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB file size limit
    fileFilter: (req, file, cb) => {
        const allowedMimeTypes = [
            'image/jpeg', 'image/png', 'image/gif',
            'video/mp4', 'video/webm',
            'application/pdf',
            'audio/mpeg', 'audio/wav'
        ];
        if (allowedMimeTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('INVALID_FILE_TYPE')); // Custom error code for multer error handler
        }
    }
});

// --- Dummy User Data (REPLACE WITH REAL DATABASE AND PASSWORD HASHING!) ---
const users = []; // Stores { socketId, username, passwordHash, isOnline }

// --- In-memory Message Storage (REPLACE WITH REAL DATABASE) ---
// Each message object will now store its status. For simplicity, this status
// is updated globally for the message, not per recipient.
const publicMessages = []; // Array of message objects
const privateChatHistories = new Map(); // Map: 'user1_user2' -> [message objects]

// --- Helper Functions ---
const findUserByUsername = (username) => users.find(u => u.username === username);
const findUserBySocketId = (socketId) => users.find(u => u.socketId === socketId);

// Function to get a consistent chat key for private chats (sorted socket IDs)
const getPrivateChatKey = (user1SocketId, user2SocketId) => {
    const chatMembers = [user1SocketId, user2SocketId].sort();
    return `${chatMembers[0]}_${chatMembers[1]}`;
};

/**
 * Finds a message by its ID and sender's socket ID in either public or private chat histories.
 * Updates its status if found.
 * @param {string} messageId - The unique ID of the message.
 * @param {string} senderSocketId - The socket ID of the message sender.
 * @param {string} newStatus - The new status to set ('delivered' or 'seen').
 * @returns {object | null} The message object if found, otherwise null.
 */
const findMessageAndMarkStatus = (messageId, senderSocketId, newStatus) => {
    let message = null;

    // 1. Check public messages
    message = publicMessages.find(m => m.id === messageId && m.fromId === senderSocketId);
    if (message) {
        if (message.status !== 'seen' || newStatus === 'seen') { // 'seen' is final status
            message.status = newStatus;
        }
        return message;
    }

    // 2. Check private messages across all chat histories
    // We iterate through all known private chats because the message might be from/to different users
    for (const [chatKey, history] of privateChatHistories.entries()) {
        message = history.find(m => m.id === messageId && m.fromId === senderSocketId);
        if (message) {
            if (message.status !== 'seen' || newStatus === 'seen') {
                 message.status = newStatus;
            }
            return message;
        }
    }
    return null;
};

// --- ROUTES ---
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/check-auth', (req, res) => {
    if (req.session.user) {
        // Find the user in the global list to get their latest socketId and online status
        const userInList = findUserByUsername(req.session.user.username);
        if (userInList) {
            // Update session with current socketId if it's available (might be null if socket not yet connected)
            req.session.user.socketId = userInList.socketId;
        }
        res.json({ isAuthenticated: true, user: req.session.user });
    } else {
        res.json({ isAuthenticated: false });
    }
});

app.post('/signup', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }
    if (findUserByUsername(username)) {
        return res.status(409).json({ message: 'Username already exists.' });
    }
    const newUser = {
        socketId: null, // Will be set on socket connection
        username,
        passwordHash: password, // In real app, hash this!
        isOnline: false
    };
    users.push(newUser);
    req.session.user = { username: newUser.username }; // Store user in session
    console.log(`User ${username} signed up and logged in.`);
    res.status(201).json({ message: 'Signup successful! You are now logged in.', user: req.session.user });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }
    const user = findUserByUsername(username);
    if (!user || user.passwordHash !== password) { // In real app, compare hashed passwords!
        return res.status(401).json({ message: 'Invalid username or password.' });
    }
    req.session.user = { username: user.username };
    console.log(`User ${username} logged in.`);
    res.status(200).json({ message: 'Login successful!', user: req.session.user });
});

app.post('/logout', (req, res) => {
    if (req.session.user && req.session.user.username) {
        const userInList = findUserByUsername(req.session.user.username);
        if (userInList) {
            userInList.isOnline = false;
            // Find the socket and disconnect it
            const connectedSocket = io.sockets.sockets.get(userInList.socketId);
            if (connectedSocket) {
                console.log(`Disconnecting socket ${connectedSocket.id} for user ${userInList.username} on logout.`);
                connectedSocket.disconnect(true); // Disconnect client socket
            }
            userInList.socketId = null; // Clear socket ID on logout
        }
    }
    req.session.destroy(err => {
        if (err) {
            console.error('Session destruction error:', err);
            return res.status(500).json({ message: 'Logout failed.' });
        }
        res.status(200).json({ message: 'Logged out successfully.' });
        // Emit user list update after session is destroyed and socket is possibly disconnected
        io.emit('update_user_list', users.map(u => ({ socketId: u.socketId, username: u.username, isOnline: u.isOnline })));
    });
});

app.post('/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded or file type not allowed.' });
    }
    const fileUrl = `/uploads/${req.file.filename}`;
    res.status(200).json({
        message: 'File uploaded successfully',
        fileUrl: fileUrl,
        originalName: req.file.originalname,
        mimeType: req.file.mimetype,
        size: req.file.size
    });
}, (error, req, res, next) => { // Multer error handler
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ message: 'File too large. Max 10MB allowed.' });
        }
        console.error("Multer error:", error.message);
        return res.status(400).json({ message: error.message });
    } else if (error.message === 'INVALID_FILE_TYPE') {
        return res.status(400).json({ message: 'Invalid file type. Only JPG, PNG, GIF, MP4, PDF, MP3, WAV allowed.' });
    } else if (error) {
        console.error('File upload unexpected error:', error);
        return res.status(500).json({ message: 'An unexpected error occurred during file upload.' });
    }
    next(); // Pass to next middleware if no error handled here
});

// --- SOCKET.IO ---

// IMPORTANT: Socket.IO middleware to attach session to socket. This is more robust.
io.use((socket, next) => {
    // Wrap the express-session middleware to work with Socket.IO
    sessionMiddleware(socket.request, {}, next);
});

io.on('connection', (socket) => {
    console.log(`Socket connected: ${socket.id}`);

    // Access session data from socket.request.session (or now socket.session if preferred)
    // The sessionMiddleware above attaches it to socket.request.session
    if (!socket.request.session || !socket.request.session.user || !socket.request.session.user.username) {
        console.log(`Socket ${socket.id} tried to connect without active session. Disconnecting.`);
        socket.emit('auth_required'); // Tell client to re-authenticate
        socket.disconnect();
        return;
    }

    const connectedUsername = socket.request.session.user.username;
    let currentUserInList = findUserByUsername(connectedUsername);

    // If user is not found in the global 'users' array (e.g., server restart after session persists)
    if (!currentUserInList) {
        currentUserInList = {
            socketId: socket.id,
            username: connectedUsername,
            passwordHash: 'N/A_Dummy_SessionUser',
            isOnline: true
        };
        users.push(currentUserInList);
        console.warn(`Authenticated user ${connectedUsername} (from session) not found in user list, added temporarily.`);
    } else {
        currentUserInList.socketId = socket.id;
        currentUserInList.isOnline = true;
    }

    // Update session with current socket ID if it's the first connection or ID changed
    if (socket.request.session.user.socketId !== socket.id) {
        socket.request.session.user.socketId = socket.id;
        // No need to call save() here if it's just updating the socketId for the current session.
        // The session is typically saved automatically at the end of the request.
        // If you need to force save for some reason, uncomment: socket.request.session.save();
    }

    console.log(`User ${connectedUsername} (${socket.id}) connected.`);

    // Send the user's own current details (including current socket ID)
    socket.emit('current_user_info', {
        id: currentUserInList.socketId, // Use the socket.id
        username: currentUserInList.username
    });

    // Update all clients with the new user list
    io.emit('update_user_list', users.map(u => ({ socketId: u.socketId, username: u.username, isOnline: u.isOnline })));

    // --- Initial messages for new connection ---
    // Public messages are always sent to new connections
    socket.emit('init_messages', publicMessages);

    // --- Socket Event Listeners ---

    socket.on('chat message', (msgContent) => {
        const message = {
            id: Date.now().toString() + Math.random().toString(36).substring(2, 9), // Unique ID for tracking
            from: currentUserInList.username,
            fromId: currentUserInList.socketId,
            content: msgContent,
            type: 'public_text',
            timestamp: new Date().toISOString(),
            status: 'sent' // Initial status: only 'sent' from server's perspective
        };
        publicMessages.push(message);
        console.log(`Public message from ${message.from}: ${message.content} (ID: ${message.id})`);
        io.emit('chat message', message); // Broadcast to all, including sender for self-display
    });

    socket.on('private_message', (data) => {
        const { recipientSocketId, content } = data;

        if (!recipientSocketId || !content) {
            console.warn('Invalid private message data received.');
            return;
        }

        const recipientUser = findUserBySocketId(recipientSocketId);
        if (!recipientUser || !recipientUser.isOnline) {
            console.warn(`Recipient ${recipientSocketId} not found or offline for private message.`);
            socket.emit('private_message_status', { success: false, message: 'Recipient is offline or not found.' });
            return;
        }

        const message = {
            id: Date.now().toString() + Math.random().toString(36).substring(2, 9), // Unique ID
            from: currentUserInList.username,
            fromId: currentUserInList.socketId,
            toId: recipientSocketId, // Important for private message history
            content: content,
            type: 'private_text',
            timestamp: new Date().toISOString(),
            status: 'sent' // Initial status
        };

        const chatKey = getPrivateChatKey(currentUserInList.socketId, recipientSocketId);
        if (!privateChatHistories.has(chatKey)) {
            privateChatHistories.set(chatKey, []);
        }
        privateChatHistories.get(chatKey).push(message);
        console.log(`Private message from ${message.from} to ${recipientUser.username}: ${message.content} (ID: ${message.id})`);

        // Emit to recipient
        io.to(recipientSocketId).emit('private_message', message);
        // Emit back to sender immediately (status 'sent' for sender's display)
        socket.emit('private_message', message);
    });

    socket.on('file_message', (data) => {
        // Note: The file upload itself happens via HTTP POST, this event is just to
        // notify about the uploaded file and its URL.
        const { id, fileUrl, originalName, mimeType, size, recipientId } = data;

        // Try to find the existing temporary message object by ID and update it,
        // or create a new one if it's the first time server sees this ID.
        let fileMessage = findMessageAndMarkStatus(id, currentUserInList.socketId, 'sent'); // Pass 'sent' as initial status
        if (!fileMessage) { // If it's a completely new message (e.g., from history load)
            fileMessage = {
                id: id, // Use the ID generated by the client
                from: currentUserInList.username,
                fromId: currentUserInList.socketId,
                fileUrl: fileUrl,
                file_original_name: originalName,
                file_mime_type: mimeType,
                file_size: size,
                timestamp: new Date().toISOString(),
                status: 'sent' // Initial status
            };
        } else {
            // If message existed (e.g., temp message placeholder), update its file details
            fileMessage.fileUrl = fileUrl;
            fileMessage.file_original_name = originalName;
            fileMessage.file_mime_type = mimeType;
            fileMessage.file_size = size;
        }


        if (recipientId) {
            fileMessage.type = 'private_file';
            fileMessage.toId = recipientId; // Important for private message history

            const recipientUser = findUserBySocketId(recipientId);
            if (!recipientUser || !recipientUser.isOnline) {
                console.warn(`Recipient ${recipientId} not found or offline for private file message.`);
                socket.emit('file_message_status', { success: false, message: 'Recipient is offline or not found.' });
                return;
            }

            const chatKey = getPrivateChatKey(currentUserInList.socketId, recipientId);
            if (!privateChatHistories.has(chatKey)) {
                privateChatHistories.set(chatKey, []);
            }
            // Ensure we update the correct message if it's already a temp one, otherwise add
            const existingFileMsgIndex = privateChatHistories.get(chatKey).findIndex(m => m.id === id);
            if (existingFileMsgIndex > -1) {
                privateChatHistories.get(chatKey)[existingFileMsgIndex] = fileMessage;
            } else {
                privateChatHistories.get(chatKey).push(fileMessage);
            }

            console.log(`Private file from ${fileMessage.from} to ${recipientUser.username}: ${fileMessage.file_original_name} (ID: ${fileMessage.id})`);
            io.to(recipientId).emit('file_message', fileMessage);
            socket.emit('file_message', fileMessage); // Send to sender for display
        } else {
            fileMessage.type = 'public_file';
            // Ensure we update the correct message if it's already a temp one, otherwise add
            const existingFileMsgIndex = publicMessages.findIndex(m => m.id === id);
            if (existingFileMsgIndex > -1) {
                publicMessages[existingFileMsgIndex] = fileMessage;
            } else {
                publicMessages.push(fileMessage);
            }
            console.log(`Public file from ${fileMessage.from}: ${fileMessage.file_original_name} (ID: ${fileMessage.id})`);
            io.emit('file_message', fileMessage); // Broadcast to all
        }
    });

    socket.on('request_private_history', (otherUserId) => {
        const chatKey = getPrivateChatKey(currentUserInList.socketId, otherUserId);
        const history = privateChatHistories.get(chatKey) || [];
        console.log(`Sending private history for ${currentUserInList.username} with ${otherUserId}. Messages: ${history.length}`);
        socket.emit('private_history', { otherUserId, history });
    });

    // --- Delivery and Seen Receipts ---
    socket.on('message_delivered', (messageId, senderSocketId) => {
        // Find the message and update its status
        const message = findMessageAndMarkStatus(messageId, senderSocketId, 'delivered');

        if (message) {
            console.log(`Message ${messageId} by ${senderSocketId} marked as delivered by ${socket.id}.`);
            // Emit status update only to the sender's specific socket
            io.to(senderSocketId).emit('message_status_update', {
                messageId: messageId,
                newStatus: message.status // Use the status from the updated message object
            });
        } else {
            console.warn(`Could not find message ${messageId} from sender ${senderSocketId} to mark as delivered.`);
        }
    });

    socket.on('message_seen', (messageId, senderSocketId) => {
        // Find the message and update its status
        const message = findMessageAndMarkStatus(messageId, senderSocketId, 'seen');

        if (message) {
            console.log(`Message ${messageId} by ${senderSocketId} marked as seen by ${socket.id}.`);
            // Emit status update only to the sender's specific socket
            io.to(senderSocketId).emit('message_status_update', {
                messageId: messageId,
                newStatus: message.status // Use the status from the updated message object
            });
        } else {
            console.warn(`Could not find message ${messageId} from sender ${senderSocketId} to mark as seen.`);
        }
    });

    socket.on('disconnect', (reason) => {
        console.log(`Socket disconnected: ${socket.id}. Reason: ${reason}`);
        const disconnectedUser = findUserBySocketId(socket.id);
        if (disconnectedUser) {
            disconnectedUser.isOnline = false;
            disconnectedUser.socketId = null; // Clear socket ID when disconnected
            console.log(`User ${disconnectedUser.username} went offline.`);
        }
        // Always update user list to reflect changes
        io.emit('update_user_list', users.map(u => ({ socketId: u.socketId, username: u.username, isOnline: u.isOnline })));
    });
});

// Start the server
server.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
