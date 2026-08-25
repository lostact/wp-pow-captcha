/**
 * WP PoW Captcha — Solver Script
 *
 * Handles two contexts:
 * 1. Challenge page mode (URL protection) — reads inline global variables.
 * 2. Form mode — reads data attributes from .pow-captcha elements.
 */

(function () {
    'use strict';

    /**
     * Convert a hex string to a readable hex string (identity, for clarity).
     */
    function hexEncode(str) {
        return str;
    }

    /**
     * Spawn a Web Worker and solve the challenge.
     *
     * @param {string} workerUrl   URL to the worker script.
     * @param {string} challenge   The challenge hex string.
     * @param {number} difficulty  The difficulty level.
     * @param {function} onSolve   Callback receiving the solution string.
     */
    function solve(workerUrl, challenge, difficulty, onSolve) {
        var worker = new Worker(workerUrl);
        worker.onmessage = function (e) {
            onSolve(e.data);
            worker.terminate();
        };
        worker.onerror = function (e) {
            console.error('PoW Worker error:', e);
        };
        worker.postMessage({ challenge: challenge, difficulty: difficulty });
    }

    /**
     * Set a cookie with SameSite=Strict and conditionally Secure.
     */
    function setCookie(name, value, maxAge) {
        var cookieStr = name + '=' + value + '; path=/; max-age=' + maxAge + '; SameSite=Strict';
        if (location.protocol === 'https:') {
            cookieStr += '; Secure';
        }
        document.cookie = cookieStr;
    }

    document.addEventListener('DOMContentLoaded', function () {

        // ---- Challenge Page Mode (URL Protection) ----
        if (typeof powChallenge !== 'undefined') {
            var statusEl = document.getElementById('pow-status');
            if (statusEl) {
                statusEl.textContent = 'Solving security challenge…';
            }

            var workerUrl = (typeof powWorkerUrl !== 'undefined')
                ? powWorkerUrl
                : (typeof powConfig !== 'undefined' ? powConfig.workerUrl : null);

            if (!workerUrl) {
                if (statusEl) {
                    statusEl.textContent = 'Error: Worker URL not configured.';
                }
                return;
            }

            solve(workerUrl, powChallenge, powDifficulty, function (solution) {
                var cookieValue = powChallenge + ':' + powExpires + ':' + powDifficulty + ':' + powSig + ':' + solution;
                setCookie('pow_solution', cookieValue, 60);

                if (statusEl) {
                    statusEl.textContent = 'Check complete! Redirecting…';
                }

                // Brief delay so the user sees the success message.
                setTimeout(function () {
                    location.reload();
                }, 300);
            });

            return; // Don't run form mode.
        }

        // ---- Form Mode ----
        var captchaElements = document.querySelectorAll('.pow-captcha');
        if (captchaElements.length === 0) {
            return;
        }

        var workerUrl = (typeof powConfig !== 'undefined') ? powConfig.workerUrl : null;
        if (!workerUrl) {
            console.error('PoW Captcha: powConfig.workerUrl is not defined.');
            return;
        }

        // For each .pow-captcha element, spawn a worker and solve.
        captchaElements.forEach(function (el) {
            var challenge  = el.getAttribute('data-challenge');
            var difficulty = parseInt(el.getAttribute('data-difficulty'), 10);
            var expires    = el.getAttribute('data-expires');
            var sig        = el.getAttribute('data-sig');

            var solutionField = el.querySelector('input[name="_pow_solution"]');
            var statusParagraph = el.querySelector('.pow-status');

            if (!challenge || isNaN(difficulty) || !solutionField) {
                return;
            }

            // Mark this element as being solved.
            el.setAttribute('data-pow-solving', 'true');

            solve(workerUrl, challenge, difficulty, function (solution) {
                // Write solution into the hidden field.
                solutionField.value = solution;

                // Update status.
                if (statusParagraph) {
                    statusParagraph.textContent = 'Security check passed ✓';
                }

                el.setAttribute('data-pow-solved', 'true');
                el.removeAttribute('data-pow-solving');

                // If the form was waiting to submit, submit it now.
                if (el.getAttribute('data-pow-pending-submit') === 'true') {
                    el.removeAttribute('data-pow-pending-submit');
                    var form = el.closest('form');
                    if (form) {
                        form.submit();
                    }
                }
            });
        });

        // Intercept form submissions if solution is not yet ready.
        document.addEventListener('submit', function (event) {
            var form = event.target;
            if (!form || !form.querySelector) {
                return;
            }

            var captcha = form.querySelector('.pow-captcha');
            if (!captcha) {
                return;
            }

            var solutionField = captcha.querySelector('input[name="_pow_solution"]');
            if (!solutionField) {
                return;
            }

            // If solution is empty, the worker hasn't finished yet.
            if (solutionField.value === '') {
                event.preventDefault();

                var statusParagraph = captcha.querySelector('.pow-status');
                if (statusParagraph) {
                    statusParagraph.textContent = 'Please wait, security check in progress…';
                }

                // Mark that we need to submit once solving completes.
                captcha.setAttribute('data-pow-pending-submit', 'true');
            }
        }, true); // Use capture phase to intercept before other handlers.
    });
})();
