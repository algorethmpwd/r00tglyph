// Main JavaScript file for R00tGlyph Platform

document.addEventListener('DOMContentLoaded', function() {
    // Enable Bootstrap tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
    });

    // Add event listeners for challenge-specific functionality
    setupChallengeListeners();

    // Setup flag submission
    setupFlagSubmission();

    // Setup theme switcher
    setupThemeSwitcher();

    // Setup XSS detection
    setupXSSDetection();

    // Setup challenge description popup
    setupChallengeDescriptionPopup();

    // Setup flag submission popup
    setupFlagSubmissionPopup();
});

function setupChallengeListeners() {
    // Check if we're on the vulnerabilities page
    const vulnerabilitiesPage = document.querySelector('.accordion-button');
    if (vulnerabilitiesPage) {
        // Add hover effect for challenge items
        const challengeItems = document.querySelectorAll('.list-group-item-action');
        challengeItems.forEach(item => {
            item.addEventListener('mouseenter', function() {
                this.classList.add('active');
            });
            item.addEventListener('mouseleave', function() {
                this.classList.remove('active');
            });
        });
    }

    // Check if we're on a challenge level with user input
    const userInputField = document.getElementById('user_input');
    if (userInputField) {
        // Add character counter
        userInputField.addEventListener('input', function() {
            const charCount = this.value.length;
            let counterElem = document.getElementById('char-counter');

            if (!counterElem) {
                counterElem = document.createElement('div');
                counterElem.id = 'char-counter';
                counterElem.className = 'form-text text-muted';
                this.parentNode.appendChild(counterElem);
            }

            counterElem.textContent = `Characters: ${charCount}`;
        });
    }

    // Add DOM-based XSS functionality for level 2
    setupDOMXSS();
}

function setupDOMXSS() {
    // This function is specifically for the DOM XSS challenge
    if (window.location.pathname.includes('/xss/level2')) {
        function setColor() {
            const urlParams = new URLSearchParams(window.location.search);
            const color = urlParams.get('color');

            if (color) {
                // Vulnerable line - directly inserting user input into the DOM
                document.getElementById('colorBox').style = "background-color: " + color;
            }
        }

        // Call the function when the page loads
        setColor();
    }
}

function setupFlagSubmission() {
    const flagForm = document.getElementById('flag-submission-form');
    if (flagForm) {
        flagForm.addEventListener('submit', function(e) {
            e.preventDefault();

            const challengeId = this.querySelector('[name="challenge_id"]').value;
            const flag = this.querySelector('[name="flag"]').value;

            // Submit the flag via AJAX
            fetch('/submit-flag', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `challenge_id=${encodeURIComponent(challengeId)}&flag=${encodeURIComponent(flag)}`
            })
            .then(response => response.json())
            .then(data => {
                const resultElement = document.getElementById('flag-result');

                if (data.success) {
                    resultElement.className = 'alert alert-success mt-3';
                    resultElement.innerHTML = `<i class="bi bi-check-circle-fill me-2"></i>${data.message}`;

                    // Disable the form after successful submission
                    this.querySelector('button[type="submit"]').disabled = true;
                    this.querySelector('[name="flag"]').disabled = true;
                } else {
                    resultElement.className = 'alert alert-danger mt-3';
                    resultElement.innerHTML = `<i class="bi bi-x-circle-fill me-2"></i>${data.message}`;
                }

                resultElement.style.display = 'block';
            })
            .catch(error => {
                console.error('Error:', error);
                const resultElement = document.getElementById('flag-result');
                resultElement.className = 'alert alert-danger mt-3';
                resultElement.innerHTML = `<i class="bi bi-exclamation-triangle-fill me-2"></i>An error occurred. Please try again.`;
                resultElement.style.display = 'block';
            });
        });
    }
}

function setupThemeSwitcher() {
    const themeLinks = document.querySelectorAll('[href*="/change-theme/"]');
    themeLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            // No need to prevent default as we want the link to work normally
            // This is just for visual feedback
            const theme = this.getAttribute('href').split('/').pop();
            document.documentElement.setAttribute('data-bs-theme', theme);
        });
    });
}

function setupXSSDetection() {
    // Override the alert function to detect when XSS challenges are completed
    const originalAlert = window.alert;
    window.alert = function(message) {
        // Call the original alert function
        originalAlert(message);

        // Check if this is a challenge completion message
        if (message && typeof message === 'string') {
            const level = getCurrentXSSLevel();
            const expectedMessage = `XSS Level ${level} Completed!`;

            if (message === expectedMessage) {
                console.log(`Challenge completed: ${expectedMessage}`);
                revealFlag();
            }
        }
    };
}

function getCurrentXSSLevel() {
    // Extract the level number from the URL
    const path = window.location.pathname;
    const match = path.match(/\/xss\/level(\d+)/);
    return match ? match[1] : null;
}

function revealFlag() {
    // Show the flag container
    const flagDisplay = document.getElementById('flag-display');
    if (flagDisplay) {
        flagDisplay.style.display = 'block';

        // Add a success message
        const resultElement = document.getElementById('flag-result');
        if (resultElement) {
            resultElement.className = 'alert alert-success mt-3';
            resultElement.innerHTML = `<i class="bi bi-check-circle-fill me-2"></i>Congratulations! You've solved the challenge. Here's your flag:`;
            resultElement.style.display = 'block';
        }

        // Scroll to the flag
        flagDisplay.scrollIntoView({ behavior: 'smooth', block: 'center' });

        // Show the flag icon if it's hidden
        const flagIcon = document.getElementById('flag-submission-icon');
        if (flagIcon) {
            flagIcon.style.display = 'block';
        }
    }
}

function setupChallengeDescriptionPopup() {
    // Check if we're on a challenge page
    if (window.location.pathname.includes('/xss/level')) {
        // Create modal for challenge description
        const challengeDescription = document.querySelector('.challenge-description');
        if (challengeDescription) {
            // Create modal container
            const modal = document.createElement('div');
            modal.className = 'modal fade';
            modal.id = 'challengeDescriptionModal';
            modal.tabIndex = '-1';
            modal.setAttribute('aria-labelledby', 'challengeDescriptionModalLabel');
            modal.setAttribute('aria-hidden', 'true');

            // Create modal content
            modal.innerHTML = `
                <div class="modal-dialog modal-dialog-centered modal-lg">
                    <div class="modal-content">
                        <div class="modal-header bg-dark text-white">
                            <h5 class="modal-title" id="challengeDescriptionModalLabel">
                                <i class="bi bi-info-circle-fill me-2"></i>Challenge Description
                            </h5>
                            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            ${challengeDescription.innerHTML}
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-primary" data-bs-dismiss="modal">
                                <i class="bi bi-check-circle-fill me-2"></i>Got it! Let's Hack
                            </button>
                        </div>
                    </div>
                </div>
            `;

            // Add modal to body
            document.body.appendChild(modal);

            // Hide the original challenge description
            challengeDescription.style.display = 'none';

            // Create a button to show the description again
            const descriptionButton = document.createElement('button');
            descriptionButton.className = 'btn btn-sm btn-outline-info mb-3';
            descriptionButton.innerHTML = '<i class="bi bi-info-circle-fill me-2"></i>Show Challenge Description';
            descriptionButton.setAttribute('data-bs-toggle', 'modal');
            descriptionButton.setAttribute('data-bs-target', '#challengeDescriptionModal');

            // Insert the button before the first card in the challenge
            const firstCard = document.querySelector('.card');
            if (firstCard && firstCard.parentNode) {
                firstCard.parentNode.insertBefore(descriptionButton, firstCard);
            }

            // Show the modal automatically when the page loads
            const bsModal = new bootstrap.Modal(modal);
            bsModal.show();
        }
    }
}

function setupFlagSubmissionPopup() {
    // Check if we're on a challenge page
    if (window.location.pathname.includes('/xss/level')) {
        // Create flag submission icon
        const flagIcon = document.createElement('div');
        flagIcon.id = 'flag-submission-icon';
        flagIcon.className = 'flag-icon';
        flagIcon.innerHTML = '<i class="bi bi-flag-fill"></i>';
        flagIcon.setAttribute('data-bs-toggle', 'tooltip');
        flagIcon.setAttribute('data-bs-placement', 'left');
        flagIcon.setAttribute('title', 'Submit Flag');

        // Add styles for the flag icon
        const style = document.createElement('style');
        style.textContent = `
            .flag-icon {
                position: fixed;
                right: 20px;
                bottom: 20px;
                width: 50px;
                height: 50px;
                background-color: #198754;
                color: white;
                border-radius: 50%;
                display: flex;
                justify-content: center;
                align-items: center;
                cursor: pointer;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
                z-index: 1000;
                transition: transform 0.2s, background-color 0.2s;
            }

            .flag-icon:hover {
                transform: scale(1.1);
                background-color: #146c43;
            }

            .flag-icon i {
                font-size: 24px;
            }

            .flag-popup {
                position: fixed;
                right: 20px;
                bottom: 80px;
                width: 300px;
                background-color: white;
                border-radius: 8px;
                box-shadow: 0 4px 16px rgba(0, 0, 0, 0.2);
                z-index: 999;
                padding: 15px;
                display: none;
            }

            .flag-popup.show {
                display: block;
                animation: slideIn 0.3s forwards;
            }

            @keyframes slideIn {
                from { transform: translateY(20px); opacity: 0; }
                to { transform: translateY(0); opacity: 1; }
            }
        `;

        document.head.appendChild(style);

        // Create flag submission popup
        const flagPopup = document.createElement('div');
        flagPopup.id = 'flag-submission-popup';
        flagPopup.className = 'flag-popup';

        // Get challenge ID from URL
        const path = window.location.pathname;
        const match = path.match(/\/xss\/level(\d+)/);
        const challengeId = match ? match[1] : '1';

        // Populate popup content
        flagPopup.innerHTML = `
            <div class="d-flex justify-content-between align-items-center mb-2">
                <h5 class="mb-0"><i class="bi bi-flag-fill me-2 text-success"></i>Submit Flag</h5>
                <button type="button" class="btn-close" id="close-flag-popup"></button>
            </div>
            <p class="small">Enter the flag you've captured from this challenge:</p>
            <form id="popup-flag-form">
                <input type="hidden" name="challenge_id" value="${challengeId}">
                <div class="input-group mb-2">
                    <span class="input-group-text"><i class="bi bi-key-fill"></i></span>
                    <input type="text" class="form-control" name="flag" placeholder="R00T{...}" required>
                </div>
                <button type="submit" class="btn btn-success w-100">
                    <i class="bi bi-check-circle-fill me-2"></i>Submit Flag
                </button>
            </form>
            <div id="popup-flag-result" class="mt-2" style="display: none;"></div>
        `;

        // Add elements to the body
        document.body.appendChild(flagIcon);
        document.body.appendChild(flagPopup);

        // Initialize tooltip
        new bootstrap.Tooltip(flagIcon);

        // Toggle popup when flag icon is clicked
        flagIcon.addEventListener('click', function() {
            flagPopup.classList.toggle('show');
        });

        // Close popup when close button is clicked
        document.getElementById('close-flag-popup').addEventListener('click', function() {
            flagPopup.classList.remove('show');
        });

        // Handle flag submission from popup
        document.getElementById('popup-flag-form').addEventListener('submit', function(e) {
            e.preventDefault();

            const challengeId = this.querySelector('[name="challenge_id"]').value;
            const flag = this.querySelector('[name="flag"]').value;

            // Submit the flag via AJAX
            fetch('/submit-flag', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `challenge_id=${encodeURIComponent(challengeId)}&flag=${encodeURIComponent(flag)}`
            })
            .then(response => response.json())
            .then(data => {
                const resultElement = document.getElementById('popup-flag-result');

                if (data.success) {
                    resultElement.className = 'alert alert-success small';
                    resultElement.innerHTML = `<i class="bi bi-check-circle-fill me-2"></i>${data.message}`;

                    // Disable the form after successful submission
                    this.querySelector('button[type="submit"]').disabled = true;
                    this.querySelector('[name="flag"]').disabled = true;

                    // Update the main page flag submission form if it exists
                    const mainForm = document.getElementById('flag-submission-form');
                    if (mainForm) {
                        mainForm.querySelector('button[type="submit"]').disabled = true;
                        mainForm.querySelector('[name="flag"]').disabled = true;

                        const mainResultElement = document.getElementById('flag-result');
                        if (mainResultElement) {
                            mainResultElement.className = 'alert alert-success mt-3';
                            mainResultElement.innerHTML = `<i class="bi bi-check-circle-fill me-2"></i>${data.message}`;
                            mainResultElement.style.display = 'block';
                        }
                    }
                } else {
                    resultElement.className = 'alert alert-danger small';
                    resultElement.innerHTML = `<i class="bi bi-x-circle-fill me-2"></i>${data.message}`;
                }

                resultElement.style.display = 'block';
            })
            .catch(error => {
                console.error('Error:', error);
                const resultElement = document.getElementById('popup-flag-result');
                resultElement.className = 'alert alert-danger small';
                resultElement.innerHTML = `<i class="bi bi-exclamation-triangle-fill me-2"></i>An error occurred. Please try again.`;
                resultElement.style.display = 'block';
            });
        });

        // Always show the flag icon
        flagIcon.style.display = 'flex';
    }
}
