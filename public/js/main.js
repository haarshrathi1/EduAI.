/**
 * main.js - Updated version with conversation title update and improved file upload behavior
 */

document.addEventListener('DOMContentLoaded', () => {
  checkNavBarLinks();
  setupLogoutButton();
  setupDarkModeToggle();

  // Smooth scrolling for anchor links (e.g. index.html)
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
      e.preventDefault();
      const target = document.querySelector(this.getAttribute('href'));
      if (target) target.scrollIntoView({ behavior: 'smooth' });
    });
  });

  // ========== HOME PAGE "Ask a Question" Button ==========
  const askQuestionBtn = document.getElementById('askQuestionBtn');
  if (askQuestionBtn) {
    askQuestionBtn.addEventListener('click', () => {
      window.location.href = '/ai-interface.html';
    });
  }

  // ========== NAV BAR: "Back to Home" Button in Chat Page ==========
  const backToHomeBtn = document.getElementById('backToHomeBtn');
  if (backToHomeBtn) {
    backToHomeBtn.addEventListener('click', () => {
      window.location.href = '/index.html';
    });
  }

  // ========== SIGNUP FORM ==========
  const signupForm = document.getElementById('signupForm');
  if (signupForm) {
    signupForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('fullName').value.trim();
      const email = document.getElementById('email').value.trim();
      const password = document.getElementById('password').value.trim();
      const confirmPassword = document.getElementById('confirmPassword').value.trim();

      if (!username || !email || !password || !confirmPassword) {
        return showToast('Please fill in all fields.', 'warning');
      }
      if (password !== confirmPassword) {
        return showToast('Passwords do not match.', 'warning');
      }

      try {
        // Example server call
        const res = await fetch('/signup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, email, password }),
        });
        const data = await res.json();
        if (res.ok) {
          showToast('OTP sent to email. Please verify.', 'success');
          localStorage.setItem('signupDetails', JSON.stringify({ username, email, password }));
          window.location.href = '/otp.html';
        } else {
          showToast(data.error || 'Signup failed.', 'error');
        }
      } catch (err) {
        console.error(err);
        showToast('Error during signup.', 'error');
      }
    });
  }

  // ========== OTP FORM ==========
  const otpForm = document.getElementById('otpForm');
  if (otpForm) {
    otpForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const stored = localStorage.getItem('signupDetails');
      if (!stored) {
        return showToast('No signup details found.', 'error');
      }
      const { username, email, password } = JSON.parse(stored);
      const otp = document.getElementById('otp').value.trim();
      if (!otp) {
        return showToast('Please enter the OTP.', 'warning');
      }

      try {
        // Example server call
        const res = await fetch('/verify-otp', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, email, password, otp }),
        });
        const data = await res.json();
        if (res.ok) {
          showToast('OTP verified! You can now log in.', 'success');
          localStorage.removeItem('signupDetails');
          window.location.href = '/login.html';
        } else {
          showToast(data.error || 'OTP verification failed.', 'error');
        }
      } catch (err) {
        console.error(err);
        showToast('Error verifying OTP.', 'error');
      }
    });
  }

  // ========== LOGIN FORM ==========
  const loginForm = document.getElementById('loginForm');
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('email').value.trim();
      const password = document.getElementById('password').value.trim();

      if (!email || !password) {
        return showToast('Please enter email and password.', 'warning');
      }

      try {
        // Example server call
        const res = await fetch('/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password }),
        });
        const data = await res.json();
        if (res.ok) {
          localStorage.setItem('token', data.token);
          localStorage.setItem('refreshToken', data.refreshToken);
          showToast('Login successful!', 'success');
          setTimeout(() => {
            window.location.href = '/ai-interface.html';
          }, 1000);
        } else {
          showToast(data.error || 'Login failed.', 'error');
        }
      } catch (err) {
        console.error(err);
        showToast('Error during login.', 'error');
      }
    });
  }

  // ========== FORGOT PASSWORD FORM ==========
  const forgotPasswordForm = document.getElementById('forgotPasswordForm');
  if (forgotPasswordForm) {
    forgotPasswordForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('email').value.trim();
      if (!email) return showToast('Please enter your email.', 'warning');
      try {
        const res = await fetch('/forgot-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email }),
        });
        const data = await res.json();
        if (res.ok) {
          showToast('Recovery email sent if account exists.', 'success');
        } else {
          showToast(data.error || 'Error during password recovery.', 'error');
        }
      } catch (err) {
        console.error(err);
        showToast('Error during password recovery.', 'error');
      }
    });
  }

  // ========== AI Chat Interface ==========
  const sendBtn = document.getElementById('sendBtn');
  const voiceBtn = document.getElementById('voiceBtn');
  const uploadBtn = document.getElementById('uploadBtn');
  const fileInput = document.getElementById('fileInput');
  const fileNameEl = document.getElementById('fileName');
  const questionInput = document.getElementById('questionInput');
  const chatDisplay = document.getElementById('chatDisplay');
  const typingIndicator = document.getElementById('typingIndicator');
  const loadingSpinner = document.getElementById('loadingSpinner');
  const chatTitle = document.getElementById('chatTitle');
  const userCategory = document.getElementById('userCategory');

  // Sidebar & Conversation Management
  const newConversationBtn = document.getElementById('newConversationBtn');
  const conversationList = document.getElementById('conversationList');

  // Load or initialize conversation data
  let conversations = JSON.parse(localStorage.getItem('conversations') || '[]');
  let currentConversationId = localStorage.getItem('currentConversationId') || null;

  // ====== Setup Sidebar ======
  if (conversationList && newConversationBtn) {
    // Render existing conversations
    renderConversationList();

    // Create a new conversation
    newConversationBtn.addEventListener('click', () => {
      const newId = Date.now().toString();
      const newConv = {
        id: newId,
        title: "Untitled Conversation",
        messages: []
      };
      conversations.push(newConv);
      currentConversationId = newId;
      saveConversations();
      renderConversationList();
      renderCurrentConversation();
      showToast('New conversation created', 'success');
    });
  }

  /**
   * Renders the list of conversations in the sidebar
   * and attaches event listeners (select, rename, delete).
   */
  function renderConversationList() {
    if (!conversationList) return;
    conversationList.innerHTML = '';

    conversations.forEach((conv) => {
      // Outer container for each conversation entry
      const listItem = document.createElement('div');
      listItem.classList.add('list-group-item', 'd-flex', 'justify-content-between', 'align-items-center');
      listItem.style.cursor = 'pointer';

      // Conversation title (click to switch conversation)
      const titleSpan = document.createElement('span');
      titleSpan.textContent = conv.title || 'Untitled';
      titleSpan.addEventListener('click', () => {
        currentConversationId = conv.id;
        saveConversations();
        renderCurrentConversation();
      });

      // Double-click to rename
      titleSpan.addEventListener('dblclick', () => {
        const newTitle = prompt('Rename conversation:', conv.title);
        if (newTitle !== null && newTitle.trim() !== '') {
          conv.title = newTitle.trim();
          saveConversations();
          renderConversationList();
          if (conv.id === currentConversationId) {
            renderCurrentConversation();
          }
        }
      });

      // Delete button (trash icon)
      const deleteBtn = document.createElement('button');
      deleteBtn.classList.add('btn', 'btn-sm', 'btn-outline-danger');
      deleteBtn.innerHTML = '<i class="fas fa-trash-alt"></i>';
      deleteBtn.title = 'Delete conversation';
      deleteBtn.addEventListener('click', (e) => {
        e.stopPropagation(); // prevent switching conversation
        Swal.fire({
          title: 'Delete Conversation?',
          text: 'Are you sure you want to remove this conversation?',
          icon: 'warning',
          showCancelButton: true,
          confirmButtonColor: '#d33',
          cancelButtonColor: '#aaa',
          confirmButtonText: 'Yes, Delete'
        }).then((result) => {
          if (result.isConfirmed) {
            deleteConversation(conv.id);
          }
        });
      });

      // Append title & delete button
      listItem.appendChild(titleSpan);
      listItem.appendChild(deleteBtn);

      // Finally, append listItem to the conversationList
      conversationList.appendChild(listItem);
    });
  }

  /**
   * Deletes a conversation by ID and updates the interface.
   */
  function deleteConversation(conversationId) {
    // Filter out from array
    conversations = conversations.filter((c) => c.id !== conversationId);

    // If current conversation is the one deleted, reset
    if (currentConversationId === conversationId) {
      currentConversationId = null;
    }

    saveConversations();
    renderConversationList();

    // Clear the chat display if no current conversation
    if (!currentConversationId && chatDisplay) {
      chatDisplay.innerHTML = '';
      chatTitle.textContent = 'EduAI Chat';
    }

    showToast('Conversation deleted.', 'success');
  }

  // Render the current conversation's messages into the chat display
  function renderCurrentConversation() {
    if (!currentConversationId || !chatDisplay) return;
    const conv = conversations.find((c) => c.id === currentConversationId);
    if (!conv) return;

    // Update chat title
    chatTitle.textContent = conv.title || "EduAI Chat";

    // Clear chat display
    chatDisplay.innerHTML = '';

    // Display existing messages
    conv.messages.forEach((msg) => {
      appendChatMessage(msg.sender, msg.content, msg.allowTTS);
    });

    autoScrollChat();
  }

  // Save the conversation list to localStorage
  function saveConversations() {
    localStorage.setItem('conversations', JSON.stringify(conversations));
    localStorage.setItem('currentConversationId', currentConversationId);
  }

  // On page load, render the current conversation if it exists
  if (chatDisplay && conversationList) {
    renderCurrentConversation();
  }

  // ====== Send message logic ======
  if (sendBtn && questionInput && chatDisplay) {
    sendBtn.addEventListener('click', async () => {
      if (!currentConversationId) {
        showToast('Please create or select a conversation first.', 'info');
        return;
      }

      const question = questionInput.value.trim();
      if (!question) return showToast('Please enter a question.', 'info');

      // Get user category selection
      const category = userCategory ? userCategory.value : 'Normal Person';

      // If current conversation title is still default, update it based on the question
      const conv = conversations.find(c => c.id === currentConversationId);
      if (conv && (conv.title === "Untitled Conversation" || conv.title.trim() === "")) {
        conv.title = generateTitleFromQuestion(question);
        renderConversationList();
        chatTitle.textContent = conv.title;
        saveConversations();
      }

      // Append user's message
      appendChatMessage('user', escapeHtml(question));
      addMessageToConversation(currentConversationId, 'user', escapeHtml(question), false);

      questionInput.value = '';
      typingIndicator.style.display = 'block';
      showLoadingSpinner(true);

      const token = localStorage.getItem('token');
      if (!token) {
        showToast('Login required.', 'error');
        typingIndicator.style.display = 'none';
        showLoadingSpinner(false);
        return (window.location.href = '/login.html');
      }

      try {
        // Updated API call to include user category
        const res = await fetch('/api/ask', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`
          },
          body: JSON.stringify({ question, category }),
        });
        const data = await res.json();
        typingIndicator.style.display = 'none';
        showLoadingSpinner(false);

        if (!res.ok) {
          return showToast(data.error || 'Error from server.', 'error');
        }

        // Convert AI's Markdown to HTML
        const formatted = markdownToHtml(data.answer);
        appendChatMessage('ai', formatted, true);
        addMessageToConversation(currentConversationId, 'ai', formatted, true);
        autoScrollChat();
      } catch (err) {
        console.error(err);
        typingIndicator.style.display = 'none';
        showLoadingSpinner(false);
        showToast('Error sending question.', 'error');
      }
    });

    // Press Enter => send
    questionInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        sendBtn.click();
      }
    });
  }

  // ====== Voice recognition ======
  if (voiceBtn && 'webkitSpeechRecognition' in window) {
    const recognition = new webkitSpeechRecognition();
    recognition.continuous = false;
    recognition.interimResults = false;
    recognition.lang = 'en-US';

    recognition.onresult = (event) => {
      questionInput.value = event.results[0][0].transcript;
    };
    recognition.onerror = () => {
      showToast('Voice recognition error.', 'error');
    };
    voiceBtn.addEventListener('click', () => {
      recognition.start();
      showToast('Listening...', 'info');
    });
  } else {
    if (voiceBtn) {
      voiceBtn.style.display = 'none';
    }
  }

  // ====== Upload file for analysis (Improved) ======
  if (uploadBtn && fileInput && fileNameEl) {
    // When a file is selected, display the filename
    fileInput.addEventListener('change', () => {
      if (fileInput.files && fileInput.files.length > 0) {
        fileNameEl.textContent = fileInput.files[0].name;
      } else {
        fileNameEl.textContent = '';
      }
    });

    // On clicking upload, if no file is selected, open file dialog;
    // otherwise, proceed with file analysis.
    uploadBtn.addEventListener('click', async () => {
      if (!fileInput.files || fileInput.files.length === 0) {
        fileInput.click();
        return;
      }
      if (!currentConversationId) {
        return showToast('Please create or select a conversation first.', 'info');
      }
      const token = localStorage.getItem('token');
      if (!token) {
        showToast('Login required.', 'error');
        return (window.location.href = '/login.html');
      }
      showLoadingSpinner(true);

      try {
        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        // Add user category to the file analysis request
        const category = userCategory ? userCategory.value : 'Normal Person';
        formData.append('category', category);

        // Example server call
        const res = await fetch('/api/analyze', {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}` },
          body: formData,
        });
        showLoadingSpinner(false);

        if (!res.ok) {
          const errData = await res.json();
          return showToast(errData.error || 'Error analyzing file.', 'error');
        }
        const data = await res.json();
        const formatted = markdownToHtml(data.analysis);

        appendChatMessage('ai', formatted, true);
        addMessageToConversation(currentConversationId, 'ai', formatted, true);
        autoScrollChat();
      } catch (err) {
        console.error(err);
        showLoadingSpinner(false);
        showToast('File analysis error.', 'error');
      }
    });
  }

  // ====== Conversation & Chat Helpers ======
  function addMessageToConversation(convId, sender, content, allowTTS) {
    const conv = conversations.find((c) => c.id === convId);
    if (!conv) return;
    conv.messages.push({ sender, content, allowTTS });
    saveConversations();
  }

  function appendChatMessage(sender, htmlContent, allowTTS = false) {
    const msgDiv = document.createElement('div');
    msgDiv.classList.add('message', sender, 'mb-2', 'p-2', 'rounded');
    if (sender === 'user') {
      msgDiv.classList.add('user-message');
      msgDiv.innerHTML = htmlContent;
    } else {
      msgDiv.classList.add('ai-message');

      // Create message content container
      const contentContainer = document.createElement('div');
      contentContainer.classList.add('message-content');
      contentContainer.innerHTML = htmlContent;
      msgDiv.appendChild(contentContainer);

      // Create button container
      const btnContainer = document.createElement('div');
      btnContainer.classList.add('message-buttons');

      // Share button (only for AI messages)
      const shareBtn = document.createElement('button');
      shareBtn.classList.add('share-btn', 'btn', 'btn-sm', 'btn-outline-secondary');
      shareBtn.innerHTML = '<i class="fas fa-share-alt"></i>';
      shareBtn.title = 'Share response';
      shareBtn.addEventListener('click', () => shareAIResponse(contentContainer.textContent));
      btnContainer.appendChild(shareBtn);

      // TTS button
      if (allowTTS) {
        const speakBtn = document.createElement('button');
        speakBtn.classList.add('speak-btn', 'btn', 'btn-sm', 'btn-outline-secondary', 'ms-1');
        speakBtn.innerHTML = '<i class="fas fa-volume-up"></i>';
        speakBtn.title = 'Speak message';
        speakBtn.addEventListener('click', () => speakText(contentContainer.textContent));
        btnContainer.appendChild(speakBtn);
      }

      msgDiv.appendChild(btnContainer);
    }

    chatDisplay.appendChild(msgDiv);
  }

  function autoScrollChat() {
    chatDisplay.scrollTop = chatDisplay.scrollHeight;
  }

  // ====== Utility Functions ======
  function showLoadingSpinner(show) {
    if (loadingSpinner) {
      loadingSpinner.style.display = show ? 'inline-block' : 'none';
    }
  }

  function speakText(message) {
    if (!window.speechSynthesis) {
      showToast('No TTS support in this browser.', 'info');
      return;
    }
    const utter = new SpeechSynthesisUtterance(message);
    utter.rate = 1.0;
    speechSynthesis.speak(utter);
  }

  function markdownToHtml(md) {
    let safe = escapeHtml(md);
    // Basic replacements for headings
    safe = safe.replace(/^###\s+(.*)$/gm, '<h3>$1</h3>');
    safe = safe.replace(/^##\s+(.*)$/gm, '<h2>$1</h2>');
    safe = safe.replace(/^#\s+(.*)$/gm, '<h1>$1</h1>');

    // bullet points
    const lines = safe.split('\n');
    let inList = false;
    let html = '';
    for (let line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('- ')) {
        if (!inList) {
          html += '<ul>';
          inList = true;
        }
        html += `<li>${trimmed.substring(2)}</li>`;
      } else {
        if (inList) {
          html += '</ul>';
          inList = false;
        }
        if (trimmed) {
          html += `<p>${trimmed}</p>`;
        }
      }
    }
    if (inList) {
      html += '</ul>';
    }

    return html;
  }

  function escapeHtml(text) {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function showToast(msg, icon = 'info') {
    Swal.fire({
      toast: true,
      position: 'top-end',
      showConfirmButton: false,
      timer: 2500,
      icon,
      title: msg,
    });
  }

  function checkNavBarLinks() {
    const token = localStorage.getItem('token');
    const loginNavLink = document.getElementById('loginNavLink');
    const signupNavLink = document.getElementById('signupNavLink');
    const logoutNavBtn = document.getElementById('logoutNavBtn');

    if (!token) {
      if (loginNavLink) loginNavLink.style.display = 'inline-block';
      if (signupNavLink) signupNavLink.style.display = 'inline-block';
      if (logoutNavBtn) logoutNavBtn.style.display = 'none';
    } else {
      if (loginNavLink) loginNavLink.style.display = 'none';
      if (signupNavLink) signupNavLink.style.display = 'none';
      if (logoutNavBtn) logoutNavBtn.style.display = 'inline-block';
    }
  }

  function setupLogoutButton() {
    const logoutNavBtn = document.getElementById('logoutNavBtn');
    if (logoutNavBtn) {
      logoutNavBtn.addEventListener('click', async () => {
        const refreshToken = localStorage.getItem('refreshToken');
        if (refreshToken) {
          await fetch('/logout', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: refreshToken }),
          });
        }
        localStorage.removeItem('token');
        localStorage.removeItem('refreshToken');
        localStorage.removeItem('conversations');
        localStorage.removeItem('currentConversationId');
        showToast('Logged out.', 'info');
        setTimeout(() => {
          window.location.href = '/index.html';
        }, 800);
      });
    }
  }

  function setupDarkModeToggle() {
    const toggle = document.getElementById('darkModeToggle');
    if (!toggle) return;
    // Check if user had dark mode on previously
    const darkModeOn = localStorage.getItem('darkMode') === 'true';
    if (darkModeOn) {
      document.body.classList.add('dark-mode');
      toggle.checked = true;
    }
    toggle.addEventListener('change', () => {
      if (toggle.checked) {
        document.body.classList.add('dark-mode');
        localStorage.setItem('darkMode', 'true');
      } else {
        document.body.classList.remove('dark-mode');
        localStorage.setItem('darkMode', 'false');
      }
    });
  }
});

// ========= Helper: Generate Title from User Question =========
function generateTitleFromQuestion(question) {
  let title = question.trim();
  // Optionally, take only the first sentence
  const periodIndex = title.indexOf('.');
  if (periodIndex !== -1) {
    title = title.substring(0, periodIndex + 1);
  }
  // Limit the title length to 30 characters
  if (title.length > 30) {
    title = title.substring(0, 30) + '...';
  }
  return title;
}

// ========== UPDATED appendChatMessage: Add Share Buttons ==========
function appendChatMessage(sender, htmlContent, allowTTS = false) {
  const msgDiv = document.createElement('div');
  msgDiv.classList.add('message', sender, 'mb-2', 'p-2', 'rounded');

  if (sender === 'user') {
    msgDiv.classList.add('user-message');
    msgDiv.innerHTML = htmlContent;
  } else {
    msgDiv.classList.add('ai-message');

    // Create message content container
    const contentContainer = document.createElement('div');
    contentContainer.classList.add('message-content');
    contentContainer.innerHTML = htmlContent;
    msgDiv.appendChild(contentContainer);

    // Create button container
    const btnContainer = document.createElement('div');
    btnContainer.classList.add('message-buttons');

    // Share button (only for AI messages)
    const shareBtn = document.createElement('button');
    shareBtn.classList.add('share-btn', 'btn', 'btn-sm', 'btn-outline-secondary');
    shareBtn.innerHTML = '<i class="fas fa-share-alt"></i>';
    shareBtn.title = 'Share response';
    shareBtn.addEventListener('click', () => shareAIResponse(contentContainer.textContent));
    btnContainer.appendChild(shareBtn);

    // TTS button
    if (allowTTS) {
      const speakBtn = document.createElement('button');
      speakBtn.classList.add('speak-btn', 'btn', 'btn-sm', 'btn-outline-secondary', 'ms-1');
      speakBtn.innerHTML = '<i class="fas fa-volume-up"></i>';
      speakBtn.title = 'Speak message';
      speakBtn.addEventListener('click', () => speakText(contentContainer.textContent));
      btnContainer.appendChild(speakBtn);
    }

    msgDiv.appendChild(btnContainer);
  }

  chatDisplay.appendChild(msgDiv);
}

// ========== NEW: Social Media Sharing ==========
function shareAIResponse(text) {
  // Create a share dialog with options
  Swal.fire({
    title: 'Share This Response',
    html: `
      <div class="share-container">
        <p class="mb-3">Share this AI response on your favorite platform:</p>
        <div class="d-flex justify-content-center gap-3">
          <button class="btn btn-twitter share-twitter">
            <i class="fab fa-twitter"></i> Twitter
          </button>
          <button class="btn btn-facebook share-facebook">
            <i class="fab fa-facebook-f"></i> Facebook
          </button>
          <button class="btn btn-linkedin share-linkedin">
            <i class="fab fa-linkedin-in"></i> LinkedIn
          </button>
        </div>
      </div>
    `,
    showConfirmButton: false,
    showCloseButton: true,
    didOpen: () => {
      // Truncate text if too long
      const truncatedText = text.length > 280 ? text.substring(0, 277) + '...' : text;

      // Twitter/X
      document.querySelector('.share-twitter').addEventListener('click', () => {
        const twitterUrl = `https://twitter.com/intent/tweet?text=${encodeURIComponent(truncatedText)}&via=EduAI`;
        window.open(twitterUrl, '_blank');
        Swal.close();
      });

      // Facebook
      document.querySelector('.share-facebook').addEventListener('click', () => {
        const facebookUrl = `https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(window.location.href)}&quote=${encodeURIComponent(truncatedText)}`;
        window.open(facebookUrl, '_blank');
        Swal.close();
      });

      // LinkedIn
      document.querySelector('.share-linkedin').addEventListener('click', () => {
        const linkedinUrl = `https://www.linkedin.com/shareArticle?mini=true&url=${encodeURIComponent(window.location.href)}&title=EduAI%20Response&summary=${encodeURIComponent(truncatedText)}`;
        window.open(linkedinUrl, '_blank');
        Swal.close();
      });
    }
  });
}
