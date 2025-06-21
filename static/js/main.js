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
        console.log("Setting up DOM XSS for Level 2");

        // Get the color box element
        const colorBox = document.getElementById('colorBox');
        if (!colorBox) {
            console.error("colorBox element not found");
            return;
        }

        // Get the color input and apply button
        const colorInput = document.getElementById('colorInput');
        const applyColorBtn = document.getElementById('applyColorBtn');

        // Function to apply color (intentionally vulnerable)
        function applyColor(color) {
            if (!color) return;

            console.log("Applying color:", color);

            try {
                // VULNERABLE CODE: Directly using user input without sanitization
                // This is intentional for the XSS challenge
                colorBox.style = "background-color: " + color + "; height: 100%; display: flex; align-items: center; justify-content: center;";

                // Update URL without page reload
                const url = new URL(window.location.href);
                url.searchParams.set('color', color);
                history.pushState({}, '', url.toString());

                console.log("Color applied successfully");
            } catch (error) {
                console.error("Error applying color:", error);
            }
        }

        // Set up event listeners for the color input and button
        if (applyColorBtn && colorInput) {
            applyColorBtn.addEventListener('click', function() {
                applyColor(colorInput.value);
            });

            colorInput.addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    applyColor(colorInput.value);
                }
            });
        }

        // Set up event listeners for the preset color buttons
        const colorPresets = document.querySelectorAll('.color-preset');
        colorPresets.forEach(button => {
            button.addEventListener('click', function() {
                const color = this.getAttribute('data-color');
                if (colorInput) colorInput.value = color;
                applyColor(color);
            });
        });

        // Check if there's a color in the URL and apply it
        const urlParams = new URLSearchParams(window.location.search);
        const color = urlParams.get('color');

        if (color) {
            if (colorInput) colorInput.value = color;
            applyColor(color);
        }
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
        console.log("Alert triggered with message:", message);

        // Check if this is a challenge completion message
        if (message && typeof message === 'string') {
            const level = getCurrentXSSLevel();
            console.log("Current XSS level:", level);

            const expectedMessage = `XSS Level ${level} Completed!`;
            console.log("Expected message:", expectedMessage);

            if (message === expectedMessage) {
                console.log(`Challenge completed: ${expectedMessage}`);

                // For level 2 specifically, we need to handle it differently
                if (level === "2") {
                    console.log("Level 2 completed, special handling");

                    // Call the original alert function after we've processed the message
                    originalAlert(message);

                    // Prevent default behavior for javascript: URLs
                    if (window.event) {
                        window.event.preventDefault();
                        window.event.stopPropagation();
                    }

                    // Immediately mark as completed on the server side
                    let url = new URL(window.location.href);
                    url.searchParams.set('success', 'true');

                    // Use fetch instead of redirecting to avoid interrupting the flow
                    fetch(url.toString(), {
                        method: 'GET',
                        headers: {
                            'X-Requested-With': 'XMLHttpRequest'
                        }
                    }).then(response => response.json())
                    .then(data => {
                        console.log("Server notified of completion, response:", data);

                        // Display the flag in the DOM without reloading
                        if (data.flag) {
                            const flagContainer = document.getElementById('flag-container');
                            if (flagContainer) {
                                flagContainer.innerHTML = `
                                    <div class="alert alert-success mt-3">
                                        <i class="bi bi-flag-fill me-2"></i>
                                        <strong>Challenge completed!</strong> Your flag is: <code>${data.flag}</code>
                                    </div>
                                `;
                                flagContainer.style.display = 'block';
                            }

                            // Also update the colorBox to show completion
                            const colorBox = document.getElementById('colorBox');
                            if (colorBox) {
                                colorBox.innerHTML = `
                                    <div class="alert alert-success m-0">
                                        <i class="bi bi-check-circle-fill me-2"></i>
                                        XSS Level 2 Completed!
                                    </div>
                                `;
                            }
                        }

                        // Update URL without reloading
                        history.pushState({}, '', url.toString());
                    }).catch(error => {
                        console.error("Error notifying server:", error);
                        originalAlert("Error completing challenge. Please try again.");
                    });

                    // Return early to prevent the default alert behavior
                    return;
                } else {
                    // For other levels, use the original behavior
                    // Call the original alert function
                    originalAlert(message);

                    // Reveal the flag
                    revealFlag();

                    // Reload the page with success parameter if not already present
                    if (!window.location.href.includes('success=true')) {
                        // Add a small delay to ensure the alert is seen
                        setTimeout(() => {
                            let url = new URL(window.location.href);
                            url.searchParams.set('success', 'true');
                            window.location.href = url.toString();
                        }, 1000);
                    } else {
                        // If success=true is already in the URL, force a page reload
                        // This ensures the flag banner is displayed
                        setTimeout(() => {
                            window.location.reload();
                        }, 1000);
                    }
                }
            } else {
                // Not a challenge completion message, just show the alert
                originalAlert(message);
            }
        } else {
            // Not a string message, just show the alert
            originalAlert(message);
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
    // Check if we're on Level 2 and need special handling
    if (window.location.pathname.includes('/xss/level2')) {
        // Check for the flag-container (used by AJAX responses)
        const flagContainer = document.getElementById('flag-container');
        if (flagContainer) {
            flagContainer.style.display = 'block';
        }

        // For javascript: URLs, prevent page navigation
        const urlParams = new URLSearchParams(window.location.search);
        const color = urlParams.get('color');

        if (color && color.toLowerCase().startsWith('javascript:')) {
            console.log("Preventing navigation for javascript: URL in revealFlag");

            // Update URL to include success=true without reloading
            if (!window.location.href.includes('success=true')) {
                let url = new URL(window.location.href);
                url.searchParams.set('success', 'true');
                history.pushState({}, '', url.toString());
            }
        }
    }

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

        // Get the flag value
        const flagValue = document.getElementById('flag-value')?.textContent;

        if (flagValue) {
            // Show a popup with the flag
            const flagPopup = document.createElement('div');
            flagPopup.style.position = 'fixed';
            flagPopup.style.top = '50%';
            flagPopup.style.left = '50%';
            flagPopup.style.transform = 'translate(-50%, -50%)';
            flagPopup.style.backgroundColor = 'white';
            flagPopup.style.padding = '20px';
            flagPopup.style.borderRadius = '10px';
            flagPopup.style.boxShadow = '0 0 10px rgba(0,0,0,0.5)';
            flagPopup.style.zIndex = '2000';
            flagPopup.style.maxWidth = '90%';
            flagPopup.style.textAlign = 'center';

            const title = document.createElement('h3');
            title.textContent = 'Challenge Completed!';
            title.style.marginBottom = '15px';
            title.style.color = '#28a745';
            flagPopup.appendChild(title);

            const flagText = document.createElement('p');
            flagText.textContent = 'Here\'s your flag:';
            flagText.style.marginBottom = '10px';
            flagPopup.appendChild(flagText);

            const flagCode = document.createElement('div');
            flagCode.textContent = flagValue;
            flagCode.style.padding = '10px';
            flagCode.style.backgroundColor = '#f8f9fa';
            flagCode.style.border = '1px solid #dee2e6';
            flagCode.style.borderRadius = '4px';
            flagCode.style.fontFamily = 'monospace';
            flagCode.style.marginBottom = '15px';
            flagCode.style.wordBreak = 'break-all';
            flagPopup.appendChild(flagCode);

            const copyButton = document.createElement('button');
            copyButton.textContent = 'Copy Flag';
            copyButton.className = 'btn btn-primary';
            copyButton.onclick = () => {
                navigator.clipboard.writeText(flagValue);
                copyButton.textContent = 'Copied!';
                setTimeout(() => copyButton.textContent = 'Copy Flag', 2000);
            };
            flagPopup.appendChild(copyButton);

            const closeButton = document.createElement('button');
            closeButton.textContent = 'Close';
            closeButton.className = 'btn btn-secondary ms-2';
            closeButton.onclick = () => document.body.removeChild(flagPopup);
            flagPopup.appendChild(closeButton);

            document.body.appendChild(flagPopup);

            // Create a flag banner at the top of the page
            let flagBanner = document.getElementById('flag-banner');
            if (!flagBanner) {
                flagBanner = document.createElement('div');
                flagBanner.id = 'flag-banner';
                flagBanner.className = 'alert alert-success';
                flagBanner.style.position = 'sticky';
                flagBanner.style.top = '0';
                flagBanner.style.zIndex = '1000';
                flagBanner.style.textAlign = 'center';
                flagBanner.style.fontWeight = 'bold';
                flagBanner.style.fontSize = '1.2rem';
                flagBanner.style.padding = '15px';
                flagBanner.style.margin = '0';
                flagBanner.style.borderRadius = '0';
                flagBanner.style.boxShadow = '0 2px 10px rgba(0, 0, 0, 0.1)';

                // Add the flag to the banner
                flagBanner.innerHTML = `<i class="bi bi-trophy-fill me-2"></i>Flag: <code>${flagValue}</code>`;

                // Insert at the top of the body
                document.body.insertBefore(flagBanner, document.body.firstChild);
            }
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
    // Check if we're on a challenge page (XSS, SQLi, Command Injection, SSRF, or CSRF)
    if (window.location.pathname.includes('/xss/level') || window.location.pathname.includes('/sqli/level') || window.location.pathname.includes('/cmdi/level') || window.location.pathname.includes('/ssrf/level') || window.location.pathname.includes('/csrf/level')) {
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

            // Get challenge type and level from URL
            const path = window.location.pathname;
            let challengeType = 'Challenge';
            if (path.includes('/xss/')) {
                challengeType = 'XSS';
            } else if (path.includes('/sqli/')) {
                challengeType = 'SQL Injection';
            } else if (path.includes('/cmdi/')) {
                challengeType = 'Command Injection';
            } else if (path.includes('/ssrf/')) {
                challengeType = 'SSRF';
            }

            // Create modal content
            modal.innerHTML = `
                <div class="modal-dialog modal-dialog-centered modal-lg">
                    <div class="modal-content">
                        <div class="modal-header bg-dark text-white">
                            <h5 class="modal-title" id="challengeDescriptionModalLabel">
                                <i class="bi bi-info-circle-fill me-2"></i>${challengeType} Challenge Description
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
            descriptionButton.className = 'btn btn-info mb-3';
            descriptionButton.innerHTML = '<i class="bi bi-info-circle-fill me-2"></i>View Challenge Description';
            descriptionButton.setAttribute('data-bs-toggle', 'modal');
            descriptionButton.setAttribute('data-bs-target', '#challengeDescriptionModal');

            // Insert the button at the appropriate location
            // For SQLi and CSRF challenges, we want it at the top of the content
            if (window.location.pathname.includes('/sqli/level') || window.location.pathname.includes('/csrf/level')) {
                const contentDiv = document.querySelector('.row > .col-md-10, .row > .col-md-8');
                if (contentDiv) {
                    // Insert at the beginning of the content div, after any success alerts
                    const firstAlert = contentDiv.querySelector('.alert');
                    if (firstAlert) {
                        contentDiv.insertBefore(descriptionButton, firstAlert.nextSibling);
                    } else {
                        contentDiv.insertBefore(descriptionButton, contentDiv.firstChild);
                    }
                }
            } else {
                // For XSS challenges, keep the existing behavior
                const firstCard = document.querySelector('.card');
                if (firstCard && firstCard.parentNode) {
                    firstCard.parentNode.insertBefore(descriptionButton, firstCard);
                }
            }

            // Show the modal automatically only on first visit, not after form submissions
            const bsModal = new bootstrap.Modal(modal);

            // Check if this is a fresh page load or a form submission
            const isFormSubmission = document.referrer &&
                                    document.referrer.includes(window.location.pathname) &&
                                    performance.navigation.type !== 1; // Not a page refresh

            // Only show on first visit or page refresh, not after form submissions
            if (!isFormSubmission) {
                bsModal.show();
            }
        }
    }
}

function setupFlagSubmissionPopup() {
    // Check if we're on a challenge page (XSS, SQLi, Command Injection, SSRF, or CSRF)
    if (window.location.pathname.includes('/xss/level') || window.location.pathname.includes('/sqli/level') || window.location.pathname.includes('/cmdi/level') || window.location.pathname.includes('/ssrf/level') || window.location.pathname.includes('/csrf/level')) {
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
        let challengeId = '1';

        // Extract challenge ID based on challenge type
        if (path.includes('/xss/level')) {
            const match = path.match(/\/xss\/level(\d+)/);
            challengeId = match ? match[1] : '1';
        } else if (path.includes('/sqli/level')) {
            const match = path.match(/\/sqli\/level(\d+)/);
            challengeId = match ? match[1] : '1';
        } else if (path.includes('/cmdi/level')) {
            const match = path.match(/\/cmdi\/level(\d+)/);
            challengeId = match ? match[1] : '1';
        } else if (path.includes('/ssrf/level')) {
            const match = path.match(/\/ssrf\/level(\d+)/);
            challengeId = match ? match[1] : '1';
        } else if (path.includes('/csrf/level')) {
            const match = path.match(/\/csrf\/level(\d+)/);
            challengeId = match ? match[1] : '1';
        }

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
