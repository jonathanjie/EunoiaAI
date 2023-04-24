document.getElementById('copyPasswordSetupLink').addEventListener('click', function() {
    const passwordResetUrl = document.getElementById('passwordResetUrl');
    passwordResetUrl.style.display = 'block'; // Make the input field visible to enable selection
    passwordResetUrl.select(); // Select the text in the input field
    passwordResetUrl.setSelectionRange(0, 99999); // For mobile devices
    document.execCommand('copy'); // Copy the selected text to clipboard
    passwordResetUrl.style.display = 'none'; // Hide the input field again

    // Optionally, show a message to indicate the link was copied successfully
    alert('Password Setup Link copied to clipboard');
});
