/**
 * WP PoW Captcha — browser solver controller.
 */
(function () {
    'use strict';

    function formatNumber(value) {
        return Math.max(0, Math.round(value || 0)).toLocaleString();
    }

    function formatRate(rate) {
        if (!isFinite(rate) || rate <= 0) {
            return 'measuring…';
        }
        if (rate >= 1000000) {
            return (rate / 1000000).toFixed(2) + ' MH/s';
        }
        if (rate >= 1000) {
            return (rate / 1000).toFixed(1) + ' kH/s';
        }
        return Math.round(rate) + ' H/s';
    }

    function formatElapsed(milliseconds) {
        var seconds = Math.max(0, milliseconds || 0) / 1000;
        return seconds < 10 ? seconds.toFixed(1) + 's' : Math.round(seconds) + 's';
    }

    function solve(workerUrl, challenge, difficulty, version, callbacks) {
        var worker;
        try {
            worker = new Worker(workerUrl);
        } catch (error) {
            callbacks.onError(error.message || 'Unable to start the security worker.');
            return null;
        }

        worker.onmessage = function (event) {
            var data = event.data || {};
            if (data.type === 'progress') {
                callbacks.onProgress(data);
                return;
            }
            if (data.type === 'solution') {
                callbacks.onSolve(data);
                worker.terminate();
                return;
            }
            if (data.type === 'error') {
                callbacks.onError(data.message || 'The security check could not run.');
                worker.terminate();
            }
        };
        worker.onerror = function () {
            callbacks.onError('The security check encountered a browser error. Please reload and try again.');
            worker.terminate();
        };
        worker.postMessage({
            challenge: challenge,
            difficulty: difficulty,
            version: version
        });
        return worker;
    }

    function updateTelemetry(statusEl, detailsEl, data) {
        var elapsed = Number(data.elapsed || 0);
        var attempts = Number(data.attempts || 0);
        var rate = elapsed > 0 ? attempts / (elapsed / 1000) : 0;
        if (statusEl) {
            statusEl.textContent = 'Security check in progress…';
        }
        if (detailsEl) {
            detailsEl.textContent = formatNumber(attempts) + ' attempts · ' + formatRate(rate) + ' · ' + formatElapsed(elapsed);
        }
    }

    function setState(container, state) {
        if (!container) {
            return;
        }
        container.setAttribute('data-pow-state', state);
        var progress = container.querySelector('.pow-progress');
        if (progress) {
            progress.setAttribute('aria-busy', state === 'solving' ? 'true' : 'false');
        }
    }

    function setCookie(name, value, maxAge) {
        var cookie = name + '=' + value + '; path=/; max-age=' + maxAge + '; SameSite=Strict';
        if (location.protocol === 'https:') {
            cookie += '; Secure';
        }
        document.cookie = cookie;
    }

    function runChallengePage() {
        if (typeof window.powChallenge === 'undefined') {
            return false;
        }

        var container = document.querySelector('.pow-container');
        var status = document.getElementById('pow-status');
        var details = document.getElementById('pow-details');
        var workerUrl = typeof window.powWorkerUrl !== 'undefined'
            ? window.powWorkerUrl
            : (window.powConfig ? window.powConfig.workerUrl : null);

        if (!workerUrl) {
            if (status) {
                status.textContent = 'Error: security worker is not configured.';
            }
            setState(container, 'error');
            return true;
        }

        setState(container, 'solving');
        solve(workerUrl, window.powChallenge, Number(window.powDifficulty), Number(window.powVersion || 1), {
            onProgress: function (data) {
                updateTelemetry(status, details, data);
            },
            onSolve: function (data) {
                var value = [
                    window.powChallenge,
                    window.powExpires,
                    window.powDifficulty,
                    window.powVersion || 1,
                    window.powAlgorithm || 'sha256',
                    window.powSig,
                    data.solution
                ].join(':');
                setCookie('pow_solution', value, 60);
                setState(container, 'solved');
                if (status) {
                    status.textContent = 'Security check complete. Redirecting…';
                }
                if (details) {
                    updateTelemetry(null, details, data);
                }
                setTimeout(function () { location.reload(); }, 300);
            },
            onError: function (message) {
                setState(container, 'error');
                if (status) {
                    status.textContent = message;
                }
            }
        });
        return true;
    }

    function runFormCaptcha(element, workerUrl) {
        var challenge = element.getAttribute('data-challenge');
        var difficulty = parseInt(element.getAttribute('data-difficulty'), 10);
        var version = parseInt(element.getAttribute('data-version') || '1', 10);
        var solutionField = element.querySelector('input[name="_pow_solution"]');
        var status = element.querySelector('.pow-status');
        var details = element.querySelector('.pow-details');

        if (!challenge || isNaN(difficulty) || !solutionField) {
            return;
        }

        element.setAttribute('data-pow-solving', 'true');
        setState(element, 'solving');
        solve(workerUrl, challenge, difficulty, version, {
            onProgress: function (data) {
                updateTelemetry(status, details, data);
            },
            onSolve: function (data) {
                solutionField.value = data.solution;
                if (status) {
                    status.textContent = 'Security check passed ✓';
                }
                if (details) {
                    updateTelemetry(null, details, data);
                }
                setState(element, 'solved');
                element.setAttribute('data-pow-solved', 'true');
                element.removeAttribute('data-pow-solving');

                if (element.getAttribute('data-pow-pending-submit') === 'true') {
                    element.removeAttribute('data-pow-pending-submit');
                    var form = element.closest('form');
                    if (form) {
                        form.submit();
                    }
                }
            },
            onError: function (message) {
                setState(element, 'error');
                element.removeAttribute('data-pow-solving');
                if (status) {
                    status.textContent = message;
                }
            }
        });
    }

    document.addEventListener('DOMContentLoaded', function () {
        if (runChallengePage()) {
            return;
        }

        var captchas = document.querySelectorAll('.pow-captcha');
        if (!captchas.length) {
            return;
        }

        var workerUrl = window.powConfig ? window.powConfig.workerUrl : null;
        if (!workerUrl) {
            captchas.forEach(function (captcha) {
                setState(captcha, 'error');
                var status = captcha.querySelector('.pow-status');
                if (status) {
                    status.textContent = 'Security worker is not configured.';
                }
            });
            return;
        }

        captchas.forEach(function (captcha) {
            runFormCaptcha(captcha, workerUrl);
        });

        document.addEventListener('submit', function (event) {
            var form = event.target;
            var captcha = form && form.querySelector ? form.querySelector('.pow-captcha') : null;
            var solution = captcha ? captcha.querySelector('input[name="_pow_solution"]') : null;
            if (!captcha || !solution || solution.value !== '') {
                return;
            }

            event.preventDefault();
            captcha.setAttribute('data-pow-pending-submit', 'true');
            var status = captcha.querySelector('.pow-status');
            if (status) {
                status.textContent = captcha.getAttribute('data-pow-state') === 'error'
                    ? 'Security check failed. Reload the page and try again.'
                    : 'Please wait; the security check is still running…';
            }
        }, true);
    });
}());
