/*global fetch*/
/*global localStorage*/

const messagesDiv = document.getElementById("messages");
const userInput = document.getElementById("user-input");
const sendBtn = document.getElementById("send-btn");
const typingDiv = document.getElementById("typing");

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

  try {
    const response = await fetch(`${window.location.pathname}send-message/`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        user_input: userText,
        session_id: sessionId,
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
    event.preventDefault(); // Prevent default form submission
    const form = document.getElementById('upload-form');
    const formData = new FormData(form);
    const messageDiv = document.getElementById('message');
    const spinnerElement = document.getElementById('uploading-spinner');

    // Show the spinner
    spinnerElement.classList.remove('hidden');

    fetch(form.action, { // Use the form.action instead of the hardcoded URL
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

