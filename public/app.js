const chatList = document.getElementById('chat-list');
const messagesDiv = document.getElementById('messages');
const messageForm = document.getElementById('message-form');
const messageInput = document.getElementById('message-input');
const fileInput = document.getElementById('file-input');
const chatHeader = document.getElementById('chat-header');
const toggleThemeBtn = document.getElementById('toggle-theme');

let currentChat = 'default-chat';

// Simple message store (for demo)
const messages = {
  [currentChat]: []
};

// Light/dark theme toggle
toggleThemeBtn.addEventListener('click', () => {
  document.body.classList.toggle('dark-theme');
  toggleThemeBtn.textContent = document.body.classList.contains('dark-theme') ? '☀️' : '🌙';
});

// Display messages
function renderMessages() {
  messagesDiv.innerHTML = '';
  (messages[currentChat] || []).forEach(msg => {
    const div = document.createElement('div');
    div.classList.add('message');
    div.classList.add(msg.self ? 'self' : 'other');

    if (msg.type === 'text') {
      div.textContent = msg.text;
    } else if (msg.type === 'file') {
      const link = document.createElement('a');
      link.href = msg.url;
      link.textContent = `📎 ${msg.filename}`;
      link.className = 'file-link';
      link.setAttribute('download', msg.filename);
      div.appendChild(link);
    }

    messagesDiv.appendChild(div);
  });

  messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

// Handle sending messages and files
messageForm.addEventListener('submit', async e => {
  e.preventDefault();

  if (fileInput.files.length > 0) {
    const file = fileInput.files[0];
    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch('/upload', {
        method: 'POST',
        body: formData
      });
      const data = await res.json();

      if (!messages[currentChat]) messages[currentChat] = [];
      messages[currentChat].push({
        type: 'file',
        filename: data.originalname,
        url: data.url,
        self: true
      });
      renderMessages();
      fileInput.value = '';
    } catch (err) {
      alert('File upload failed');
    }
  }

  if (messageInput.value.trim()) {
    if (!messages[currentChat]) messages[currentChat] = [];
    messages[currentChat].push({
      type: 'text',
      text: messageInput.value.trim(),
      self: true
    });
    renderMessages();
    messageInput.value = '';
  }
});

// Initial render
renderMessages();
