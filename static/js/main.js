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
