/**
 * Proof-of-Work Firewall — browser solver controller.
 */
(function () {
    'use strict';

    function translate(key, fallback) {
        return window.powFirewallI18n && typeof window.powFirewallI18n[key] === 'string' ? window.powFirewallI18n[key] : fallback;
    }

    function formatNumber(value) {
        return Math.max(0, Math.round(value || 0)).toLocaleString();
    }

    function formatRate(rate) {
        if (!isFinite(rate) || rate <= 0) {
            return translate('measuring', 'measuring…');
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
            callbacks.onError(translate('workerStartError', 'Unable to start the security worker.'));
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
                callbacks.onError(translate('checkRunError', 'The security check could not run.'));
                worker.terminate();
            }
        };
        worker.onerror = function () {
            callbacks.onError(translate('browserError', 'The security check encountered a browser error. Please reload and try again.'));
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
            statusEl.textContent = translate('inProgress', 'Security check in progress…');
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

    function interactionMode(value) {
        return value === 'mouse' || value === 'checkbox' ? value : 'automatic';
    }

    function debugProgressEnabled() {
        if (typeof window.powFirewallDebugProgress !== 'undefined') {
            return window.powFirewallDebugProgress === true;
        }
        return Boolean(window.powFirewallConfig && window.powFirewallConfig.debugProgress === true);
    }

    function configureProgressDetails(details) {
        if (details) {
            details.hidden = !debugProgressEnabled();
        }
    }

    function showProgress(container) {
        var progress = container ? container.querySelector('.pow-progress') : null;
        if (progress) {
            progress.hidden = false;
        }
    }

    function waitForInteraction(container, mode, status, details, callback) {
        mode = interactionMode(mode);
        if (mode === 'automatic') {
            callback();
            return;
        }

        setState(container, 'waiting');
        if (mode === 'mouse') {
            if (status) {
                status.textContent = translate('moveMouse', 'Move your mouse to begin the security check.');
            }
            if (details) {
                details.textContent = translate('waitingInteraction', 'Waiting for genuine user interaction…');
            }
            var onMouseMove = function (event) {
                if (!event.isTrusted) {
                    return;
                }
                document.removeEventListener('mousemove', onMouseMove);
                callback();
            };
            document.addEventListener('mousemove', onMouseMove, { passive: true });
            return;
        }

        if (status) {
            status.textContent = '';
            status.hidden = true;
        }
        if (details) {
            details.textContent = translate('startsAfterConfirmation', 'The proof-of-work check starts after confirmation.');
        }
        var label = document.createElement('label');
        label.className = 'pow-interaction-check';
        var checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.setAttribute('aria-label', translate('verifyHuman', 'Verify you are human'));
        var text = document.createElement('span');
        text.textContent = translate('verifyHuman', 'Verify you are human');
        label.appendChild(checkbox);
        label.appendChild(text);
        var progress = container ? container.querySelector('.pow-progress') : null;
        if (container) {
            container.insertBefore(label, progress || null);
        }
        checkbox.addEventListener('change', function (event) {
            if (!event.isTrusted || !checkbox.checked) {
                return;
            }
            checkbox.disabled = true;
            label.hidden = true;
            if (status) {
                status.hidden = false;
            }
            callback();
        });
    }

    function runChallengePage() {
        if (typeof window.powFirewallChallenge === 'undefined') {
            return false;
        }

        var container = document.querySelector('.pow-container');
        var status = document.getElementById('pow-status');
        var details = document.getElementById('pow-details');
        configureProgressDetails(details);
        var workerUrl = typeof window.powFirewallWorkerUrl !== 'undefined'
            ? window.powFirewallWorkerUrl
            : (window.powFirewallConfig ? window.powFirewallConfig.workerUrl : null);

        if (!workerUrl) {
            if (status) {
                status.textContent = translate('workerNotConfigured', 'Error: security worker is not configured.');
            }
            setState(container, 'error');
            return true;
        }

        waitForInteraction(container, window.powFirewallInteractionMode, status, details, function () {
            showProgress(container);
            setState(container, 'solving');
            if (status) {
                status.textContent = translate('startingCheck', 'Starting security check…');
            }
            if (details) {
                details.textContent = translate('startingWorker', 'Starting secure worker…');
            }
            solve(workerUrl, window.powFirewallChallenge, Number(window.powFirewallDifficulty), Number(window.powFirewallVersion || 1), {
                onProgress: function (data) {
                    updateTelemetry(status, details, data);
                },
                onSolve: function (data) {
                    var value = [
                        window.powFirewallChallenge,
                        window.powFirewallExpires,
                        window.powFirewallDifficulty,
                        window.powFirewallVersion || 1,
                        window.powFirewallAlgorithm || 'sha256',
                        window.powFirewallSig,
                        data.solution
                    ].join(':');
                    setCookie('pow_firewall_solution', value, 60);
                    setState(container, 'solved');
                    if (status) {
                        status.textContent = translate('completeRedirecting', 'Security check complete. Redirecting…');
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
        });
        return true;
    }

    function populateChallengeFields(element, challenge) {
        var fields = {
            '_pow_firewall_challenge': challenge.challenge,
            '_pow_firewall_expires': challenge.expires,
            '_pow_firewall_difficulty': challenge.difficulty,
            '_pow_firewall_version': challenge.version,
            '_pow_firewall_algorithm': challenge.algorithm,
            '_pow_firewall_sig': challenge.signature
        };

        Object.keys(fields).forEach(function (name) {
            var field = element.querySelector('input[name="' + name + '"]');
            if (field) {
                field.value = fields[name];
            }
        });
    }

    function runFormCaptcha(element, workerUrl, challenge) {
        var solutionField = element.querySelector('input[name="_pow_firewall_firewall_solution"]');
        var status = element.querySelector('.pow-status');
        var details = element.querySelector('.pow-details');
        configureProgressDetails(details);

        if (!challenge || !challenge.challenge || !solutionField) {
            throw new Error('Invalid challenge response.');
        }

        populateChallengeFields(element, challenge);
        element.setAttribute('data-pow-solving', 'true');
        showProgress(element);
        setState(element, 'solving');
        solve(workerUrl, challenge.challenge, Number(challenge.difficulty), Number(challenge.version), {
            onProgress: function (data) {
                updateTelemetry(status, details, data);
            },
            onSolve: function (data) {
                solutionField.value = data.solution;
                if (status) {
                    status.textContent = translate('passed', 'Security check passed');
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

    function requestFormChallenge(element, workerUrl, challengeUrl) {
        var status = element.querySelector('.pow-status');
        var details = element.querySelector('.pow-details');
        var separator = challengeUrl.indexOf('?') === -1 ? '?' : '&';
        var url = challengeUrl + separator + '_pow_firewall_cache_bust=' + encodeURIComponent(Date.now() + '-' + Math.random());

        setState(element, 'loading');
        if (status) {
            status.textContent = translate('preparing', 'Preparing security check…');
        }
        if (details) {
            details.textContent = translate('requestingChallenge', 'Requesting a fresh challenge…');
        }

        fetch(url, {
            method: 'GET',
            credentials: 'same-origin',
            cache: 'no-store',
            headers: { 'Accept': 'application/json' }
        }).then(function (response) {
            if (!response.ok) {
                throw new Error('Challenge request failed with HTTP ' + response.status + '.');
            }
            return response.json();
        }).then(function (payload) {
            if (!payload || payload.success !== true || !payload.data) {
                throw new Error('Invalid challenge response.');
            }
            runFormCaptcha(element, workerUrl, payload.data);
        }).catch(function () {
            setState(element, 'error');
            if (status) {
                status.textContent = translate('unableToStart', 'Unable to start the security check. Reload the page and try again.');
            }
            if (details) {
                details.textContent = translate('challengeRequestFailed', 'The fresh challenge request failed.');
            }
        });
    }

    document.addEventListener('DOMContentLoaded', function () {
        if (runChallengePage()) {
            return;
        }

        var captchas = document.querySelectorAll('.pow-firewall');
        if (!captchas.length) {
            return;
        }

        var workerUrl = window.powFirewallConfig ? window.powFirewallConfig.workerUrl : null;
        var challengeUrl = window.powFirewallConfig ? window.powFirewallConfig.challengeUrl : null;
        if (!workerUrl || !challengeUrl) {
            captchas.forEach(function (captcha) {
                setState(captcha, 'error');
                var status = captcha.querySelector('.pow-status');
                if (status) {
                    status.textContent = translate('serviceNotConfigured', 'Security challenge service is not configured.');
                }
            });
            return;
        }

        captchas.forEach(function (captcha) {
            configureProgressDetails(captcha.querySelector('.pow-details'));
            waitForInteraction(
                captcha,
                window.powFirewallConfig ? window.powFirewallConfig.interactionMode : 'automatic',
                captcha.querySelector('.pow-status'),
                captcha.querySelector('.pow-details'),
                function () { requestFormChallenge(captcha, workerUrl, challengeUrl); }
            );
        });

        document.addEventListener('submit', function (event) {
            var form = event.target;
            var captcha = form && form.querySelector ? form.querySelector('.pow-firewall') : null;
            var solution = captcha ? captcha.querySelector('input[name="_pow_firewall_firewall_solution"]') : null;
            if (!captcha || !solution || solution.value !== '') {
                return;
            }

            event.preventDefault();
            captcha.setAttribute('data-pow-pending-submit', 'true');
            var status = captcha.querySelector('.pow-status');
            if (status) {
                status.textContent = captcha.getAttribute('data-pow-state') === 'error'
                    ? translate('failedReload', 'Security check failed. Reload the page and try again.')
                    : translate('stillPreparing', 'Please wait; the security check is still preparing or running…');
            }
        }, true);
    });
}());
