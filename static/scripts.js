/*global fetch*/
/*global localStorage*/
const pineconeApiKeyInput = document.getElementById("pinecone_api_key");
const pineconeEnvInput = document.getElementById("pinecone_env");
const pineconeIndexNameInput = document.getElementById("pinecone_index_name");

if (pineconeApiKeyInput && pineconeEnvInput && pineconeIndexNameInput) {
  pineconeApiKeyInput.value = localStorage.getItem("pinecone_api_key") || '059d7f02-0a2b-426d-bd4d-dac65525637d';
  pineconeEnvInput.value = localStorage.getItem("pinecone_env") || 'us-east4-gcp';
  pineconeIndexNameInput.value = localStorage.getItem("pinecone_index") || 'mrn-chatbot';

  // Add these lines to the end of the file
  pineconeApiKeyInput.addEventListener("input", () => {
    localStorage.setItem("pinecone_api_key", pineconeApiKeyInput.value);
  });

  pineconeEnvInput.addEventListener("input", () => {
    localStorage.setItem("pinecone_env", pineconeEnvInput.value);
  });

  pineconeIndexNameInput.addEventListener("input", () => {
    localStorage.setItem("pinecone_index", pineconeIndexNameInput.value);
  });
}

const messagesDiv = document.getElementById("messages");
const userInput = document.getElementById("user-input");
const sendBtn = document.getElementById("send-btn");
const typingDiv = document.getElementById('typing');

// Fetch and set a UUID as the session ID
let sessionId;
(async () => {
    sessionId = await fetchUUID();
})();


sendBtn.addEventListener("click", async () => {
  const userText = userInput.value;
  userInput.value = "";

  if (!userText.trim()) return; // Ignore empty messages

  addMessage(userText, false); // Display user's message
  disableInput(true); // Disable input while waiting for AI's response

  // Show the typing animation
  document.getElementById("typing").classList.remove("hidden");

  const pineconeApiKey = document.getElementById("pinecone_api_key").value;
  const pineconeEnv = document.getElementById("pinecone_env").value;
  const pineconeIndexName = document.getElementById("pinecone_index_name").value;

  try {
    const response = await fetch("http://194.233.91.95:5000/chat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        user_input: userText,
        session_id: sessionId,
        pinecone_api_key: pineconeApiKey,
        pinecone_env: pineconeEnv,
        pinecone_index_name: pineconeIndexName,
      }),
    });

    const jsonResponse = await response.json();

    // Hide the typing animation
    document.getElementById("typing").classList.add("hidden");

    addMessage(jsonResponse.response, true); // Display chatbot's response
  } catch (error) {
    console.error("Error:", error);
  } finally {
    disableInput(false); // Enable input after AI's response
  }
});


function disableInput(disabled) {
    userInput.disabled = disabled;
    sendBtn.disabled = disabled;
}

userInput.addEventListener("keypress", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    sendBtn.click();
  }
});

function addMessage(text, isChatbot) {
    const p = document.createElement('p');
    p.textContent = text;
    if (isChatbot) {
        p.classList.add('chatbot-message');
    } else {
        p.classList.add('user-message');
    }
    messagesDiv.appendChild(p);
    messagesDiv.scrollTop = messagesDiv.scrollHeight; // Scroll to the bottom
}

// Fetch UUID function
async function fetchUUID() {
    try {
        const response = await fetch('https://www.uuidtools.com/api/generate/v4');
        const uuidArray = await response.json();
        return uuidArray[0];
    } catch (error) {
        console.error('Error fetching UUID:', error);
        return null;
    }
}

// Change file upload input fields depending on selected file type
function updateInputFields() {
    const fileType = document.getElementById("file_type").value;
    const fileInputWrapper = document.getElementById("file-input-wrapper");

    if (fileType === "javascript_website") {
        fileInputWrapper.innerHTML = `
            <label for="urls">Enter the URLs (comma-separated):</label>
            <input type="text" id="urls" name="urls">
        `;
    } else if (fileType === "html_website") {
        fileInputWrapper.innerHTML = `
            <label for="urls">Enter the URL:</label>
            <input type="text" id="url" name="url">
        `;
    } else {
        fileInputWrapper.innerHTML = `
            <label for="file">Upload your file:</label>
            <input type="file" id="file" name="file">
        `;
    }
}

function submitForm(event) {
    event.preventDefault();

    const form = document.getElementById('upload-form');
    const formData = new FormData(form);
    const messageDiv = document.getElementById('message');
    const spinnerElement = document.getElementById('uploading-spinner');

    // Show the spinner
    spinnerElement.classList.remove('hidden');

    fetch('/upload', {
        method: 'POST',
        body: formData,
    })
        .then((response) => response.json())
        .then((data) => {
            if (data.success) {
                messageDiv.textContent = 'Upload Success';
                messageDiv.classList.add('success');
                messageDiv.classList.remove('error');
            } else if (data.error) {
                messageDiv.textContent = 'Upload Error: ' + data.error;
                messageDiv.classList.add('error');
                messageDiv.classList.remove('success');
            }
            // Hide the spinner
            spinnerElement.classList.add('hidden');
        })
        .catch((error) => {
            console.error('Error:', error);
            messageDiv.textContent = 'Upload Error';
            messageDiv.classList.add('error');
            messageDiv.classList.remove('success');
            // Hide the spinner
            spinnerElement.classList.add('hidden');
        });
}

