const copyToClipboard = (text) => {
  const el = document.createElement('textarea');
  el.value = text;
  el.setAttribute('readonly', '');
  el.style.position = 'absolute';
  el.style.left = '-9999px';
  document.body.appendChild(el);
  el.select();
  document.execCommand('copy');
  document.body.removeChild(el);
};

const deleteKey = async (keyId, btn) => {
  // Make an AJAX call to deactivate the key
  const response = await fetch(`/manage_keys/${keyId}/delete/`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': getCsrfToken(),
    },
  });

  if (response.ok) {
    // Remove the key row from the table
    const row = btn.closest('tr');
    row.remove();
  } else {
    console.error('Error deleting key:', response.statusText);
  }
};

async function createKey() {
  const response = await fetch('/manage_keys/create_key/', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': getCsrfToken(),
    },
  });

  if (response.ok) {
    const data = await response.json();
    addKeyToTable(data.key);
  } else {
    console.error('Error creating new API key:', response.statusText);
  }
}

function addKeyToTable(key) {
  const table = document.getElementById('keys-table');
  const newRow = table.insertRow();

  // Key column
  const keyCell = newRow.insertCell(0);
  const keyText = document.createElement('span');
  keyText.textContent = '••••••••••';
  keyText.classList.add('key-text');
  keyCell.appendChild(keyText);
  
  const keyHidden = document.createElement('span');
  keyHidden.textContent = key;
  keyHidden.classList.add('key-hidden');
  keyHidden.style.display = 'none';
  keyCell.appendChild(keyHidden);

  keyCell.addEventListener('mouseover', () => {
    keyText.style.display = 'none';
    keyHidden.style.display = 'inline';
  });

  keyCell.addEventListener('mouseout', () => {
    keyText.style.display = 'inline';
    keyHidden.style.display = 'none';
  });

  // Actions cell
  const actionsCell = newRow.insertCell(1);

  // Copy Key button
  const copyKeyBtn = document.createElement('button');
  copyKeyBtn.classList.add('copy-btn');
  copyKeyBtn.textContent = 'Copy Key';
  copyKeyBtn.addEventListener('click', () => {
    copyToClipboard(key);
  });
  actionsCell.appendChild(copyKeyBtn);

  // Delete button
  const deleteBtn = document.createElement('button');
  deleteBtn.classList.add('delete-btn');
  deleteBtn.textContent = 'Delete';
  deleteBtn.addEventListener('click', () => {
    deleteKey(key, deleteBtn);
  });
  actionsCell.appendChild(deleteBtn);
}

function getCsrfToken() {
  const cookieValue = document.cookie.match('(^|;)\\s*' + 'csrftoken' + '\\s*=\\s*([^;]+)');
  return cookieValue ? cookieValue.pop() : '';
}

// Add the event listener for the create-key-btn
document.getElementById('create-key-btn').addEventListener('click', createKey);