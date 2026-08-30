/**
 * WP PoW Captcha — admin benchmark and difficulty calculator.
 */
(function () {
    'use strict';

    function translate(key, fallback) {
        return window.powAdminI18n && typeof window.powAdminI18n[key] === 'string' ? window.powAdminI18n[key] : fallback;
    }

    function interpolate(template) {
        var values = Array.prototype.slice.call(arguments, 1);
        return values.reduce(function (text, value, index) {
            return text.replace(new RegExp('%' + (index + 1) + '\\$s', 'g'), value);
        }, template);
    }

    var STORAGE_KEY = 'wpPowCaptchaHashRateV2';
    var worker = null;
    var rejectActiveSolve = null;
    var cancelled = false;
    var measuredRate = readStoredRate();

    function expectedHashes(difficulty) {
        return Math.pow(2, 10 + clampDifficulty(difficulty) / 10);
    }

    function clampDifficulty(value) {
        return Math.max(0, Math.min(140, Math.round(Number(value) || 0)));
    }

    function formatInteger(value) {
        return Math.round(value).toLocaleString();
    }

    function formatRate(rate) {
        if (!isFinite(rate) || rate <= 0) {
            return translate('notMeasured', 'Not measured');
        }
        if (rate >= 1000000) {
            return (rate / 1000000).toFixed(2) + ' MH/s';
        }
        if (rate >= 1000) {
            return (rate / 1000).toFixed(1) + ' kH/s';
        }
        return Math.round(rate) + ' H/s';
    }

    function formatDuration(seconds) {
        if (!isFinite(seconds)) {
            return '—';
        }
        if (seconds < 0.001) {
            return '<1 ms';
        }
        if (seconds < 1) {
            return Math.round(seconds * 1000) + ' ms';
        }
        if (seconds < 10) {
            return seconds.toFixed(2) + ' s';
        }
        if (seconds < 60) {
            return seconds.toFixed(1) + ' s';
        }
        return Math.floor(seconds / 60) + 'm ' + Math.round(seconds % 60) + 's';
    }

    function readStoredRate() {
        try {
            var value = Number(localStorage.getItem(STORAGE_KEY));
            return isFinite(value) && value > 0 ? value : 0;
        } catch (error) {
            return 0;
        }
    }

    function storeRate(rate) {
        try {
            localStorage.setItem(STORAGE_KEY, String(rate));
        } catch (error) {
            // Storage can be unavailable in privacy modes; the live result still works.
        }
    }

    function randomChallenge() {
        var bytes = new Uint8Array(16);
        crypto.getRandomValues(bytes);
        return Array.prototype.map.call(bytes, function (byte) {
            return byte.toString(16).padStart(2, '0');
        }).join('');
    }

    function setBusy(card, busy) {
        card.setAttribute('data-busy', busy ? 'true' : 'false');
        document.getElementById('pow-run-benchmark').disabled = busy;
        document.getElementById('pow-run-solves').disabled = busy;
        document.getElementById('pow-cancel-test').disabled = !busy;
    }

    function terminateWorker() {
        if (worker) {
            worker.terminate();
            worker = null;
        }
    }

    function updateDifficultyControls() {
        document.querySelectorAll('[data-pow-difficulty-control]').forEach(function (control) {
            var range = control.querySelector('input[type="range"]');
            var number = control.querySelector('input[type="number"]');
            var preview = control.querySelector('.pow-work-preview');

            function update(source) {
                var value = clampDifficulty(source.value);
                range.value = value;
                number.value = value;
                var text = interpolate(translate('expectedHashesPreview', '≈ %1$s expected hashes'), formatInteger(expectedHashes(value)));
                if (measuredRate > 0) {
                    text += ' · ' + interpolate(translate('onThisBrowser', '%1$s on this browser'), formatDuration(expectedHashes(value) / measuredRate));
                }
                preview.textContent = text;
            }

            range.addEventListener('input', function () { update(range); });
            number.addEventListener('input', function () { update(number); });
            update(number);
        });
    }

    function renderEstimateTable(difficulty) {
        var body = document.querySelector('#pow-estimate-table tbody');
        if (!body) {
            return;
        }

        var work = expectedHashes(difficulty);
        var profiles = [];
        if (measuredRate > 0) {
            profiles.push({ name: translate('thisBrowser', 'This browser (measured)'), rate: measuredRate, measured: true });
        }
        profiles.push(
            { name: translate('lowEndMobile', 'Low-end mobile'), rate: 25000 },
            { name: translate('typicalMobile', 'Typical mobile'), rate: 75000 },
            { name: translate('typicalLaptop', 'Typical laptop'), rate: 200000 },
            { name: translate('fastDesktop', 'Fast desktop'), rate: 500000 }
        );

        body.innerHTML = '';
        profiles.forEach(function (profile) {
            var mean = work / profile.rate;
            var row = document.createElement('tr');
            if (profile.measured) {
                row.className = 'pow-measured-row';
            }
            [
                profile.name,
                formatRate(profile.rate),
                formatInteger(work),
                formatDuration(mean * Math.log(2)),
                formatDuration(mean),
                formatDuration(mean * -Math.log(0.05))
            ].forEach(function (value) {
                var cell = document.createElement('td');
                cell.textContent = value;
                row.appendChild(cell);
            });
            body.appendChild(row);
        });
    }

    function runBenchmark(card, status) {
        terminateWorker();
        cancelled = false;
        setBusy(card, true);
        status.textContent = translate('benchmarkingThroughput', 'Benchmarking SHA-256 throughput…');
        worker = new Worker(card.getAttribute('data-worker-url'));
        worker.onmessage = function (event) {
            var data = event.data || {};
            if (data.type === 'benchmark-progress') {
                status.textContent = interpolate(translate('benchmarkingHashes', 'Benchmarking… %1$s hashes sampled'), formatInteger(data.attempts));
            } else if (data.type === 'benchmark-result') {
                measuredRate = Number(data.hashRate) || 0;
                storeRate(measuredRate);
                status.textContent = interpolate(translate('browserMeasured', 'This browser measured %1$s across %2$s hashes.'), formatRate(measuredRate), formatInteger(data.attempts));
                terminateWorker();
                setBusy(card, false);
                updateDifficultyControls();
                renderEstimateTable(clampDifficulty(document.getElementById('pow-test-difficulty').value));
            }
        };
        worker.onerror = function () {
            status.textContent = translate('benchmarkFailed', 'Benchmark worker failed. Check browser worker support and try again.');
            terminateWorker();
            setBusy(card, false);
        };
        worker.postMessage({ action: 'benchmark', duration: 2000 });
    }

    function solveOnce(workerUrl, difficulty, onProgress) {
        return new Promise(function (resolve, reject) {
            terminateWorker();
            rejectActiveSolve = reject;
            worker = new Worker(workerUrl);
            worker.onmessage = function (event) {
                var data = event.data || {};
                if (data.type === 'progress') {
                    onProgress(data);
                } else if (data.type === 'solution') {
                    rejectActiveSolve = null;
                    terminateWorker();
                    resolve(data);
                } else if (data.type === 'error') {
                    rejectActiveSolve = null;
                    terminateWorker();
                    reject(new Error(data.message));
                }
            };
            worker.onerror = function () {
                rejectActiveSolve = null;
                terminateWorker();
                reject(new Error(translate('solveWorkerFailed', 'Solve worker failed.')));
            };
            worker.postMessage({
                challenge: randomChallenge(),
                difficulty: difficulty,
                version: 3
            });
        });
    }

    function median(values) {
        var sorted = values.slice().sort(function (a, b) { return a - b; });
        var middle = Math.floor(sorted.length / 2);
        return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
    }

    async function runSolveTests(card, status, results) {
        var difficulty = clampDifficulty(document.getElementById('pow-test-difficulty').value);
        var runs = Math.max(1, Math.min(10, parseInt(document.getElementById('pow-test-runs').value, 10) || 3));
        var samples = [];
        cancelled = false;
        setBusy(card, true);
        results.innerHTML = '';
        renderEstimateTable(difficulty);

        try {
            for (var index = 0; index < runs; index++) {
                if (cancelled) {
                    throw new Error(translate('testCancelled', 'Test cancelled.'));
                }
                status.textContent = interpolate(translate('solveAtDifficulty', 'Solve %1$s of %2$s at difficulty %3$s…'), index + 1, runs, difficulty);
                var sample = await solveOnce(card.getAttribute('data-worker-url'), difficulty, function (progress) {
                    status.textContent = interpolate(translate('solveProgress', 'Solve %1$s of %2$s: %3$s attempts · %4$s'), index + 1, runs, formatInteger(progress.attempts), formatDuration(progress.elapsed / 1000));
                });
                samples.push(sample);
            }

            var times = samples.map(function (sample) { return sample.elapsed / 1000; });
            var attempts = samples.map(function (sample) { return sample.attempts; });
            var totalAttempts = attempts.reduce(function (sum, value) { return sum + value; }, 0);
            var totalSeconds = times.reduce(function (sum, value) { return sum + value; }, 0);
            var actualRate = totalSeconds > 0 ? totalAttempts / totalSeconds : 0;
            status.textContent = interpolate(translate('completedSolves', 'Completed %1$s real solves at difficulty %2$s.'), runs, difficulty);
            results.innerHTML = '<table class="widefat striped"><thead><tr><th>' + translate('statistic', 'Statistic') + '</th><th>' + translate('solveTime', 'Solve time') + '</th></tr></thead><tbody>' +
                '<tr><td>' + translate('minimum', 'Minimum') + '</td><td>' + formatDuration(Math.min.apply(null, times)) + '</td></tr>' +
                '<tr><td>' + translate('median', 'Median') + '</td><td>' + formatDuration(median(times)) + '</td></tr>' +
                '<tr><td>' + translate('average', 'Average') + '</td><td>' + formatDuration(totalSeconds / runs) + '</td></tr>' +
                '<tr><td>' + translate('maximum', 'Maximum') + '</td><td>' + formatDuration(Math.max.apply(null, times)) + '</td></tr>' +
                '<tr><td>' + translate('totalAttempts', 'Total attempts') + '</td><td>' + formatInteger(totalAttempts) + '</td></tr>' +
                '<tr><td>' + translate('observedHashRate', 'Observed hash rate') + '</td><td>' + formatRate(actualRate) + '</td></tr>' +
                '</tbody></table>';
        } catch (error) {
            status.textContent = error.message || translate('solveTestFailed', 'Solve test failed.');
        } finally {
            terminateWorker();
            setBusy(card, false);
        }
    }

    document.addEventListener('DOMContentLoaded', function () {
        var card = document.getElementById('pow-benchmark');
        updateDifficultyControls();
        if (!card) {
            return;
        }

        var status = document.getElementById('pow-benchmark-status');
        var results = document.getElementById('pow-solve-results');
        var difficulty = document.getElementById('pow-test-difficulty');
        if (measuredRate > 0) {
            status.textContent = interpolate(translate('savedBenchmark', 'Saved browser benchmark: %1$s. Run again to refresh it.'), formatRate(measuredRate));
        }
        renderEstimateTable(clampDifficulty(difficulty.value));

        difficulty.addEventListener('input', function () {
            difficulty.value = clampDifficulty(difficulty.value);
            renderEstimateTable(clampDifficulty(difficulty.value));
        });
        document.getElementById('pow-run-benchmark').addEventListener('click', function () {
            runBenchmark(card, status);
        });
        document.getElementById('pow-run-solves').addEventListener('click', function () {
            runSolveTests(card, status, results);
        });
        document.getElementById('pow-cancel-test').addEventListener('click', function () {
            cancelled = true;
            if (rejectActiveSolve) {
                var reject = rejectActiveSolve;
                rejectActiveSolve = null;
                reject(new Error(translate('testCancelled', 'Test cancelled.')));
            }
            terminateWorker();
            status.textContent = translate('testCancelled', 'Test cancelled.');
            setBusy(card, false);
        });
    });
}());
