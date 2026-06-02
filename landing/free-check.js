/**
 * KyberGuard Dark Web Free Check — Frontend Logic
 * Atlas/Nero-Standard:
 *   - Kein eval(), keine externen CDN-Scripts
 *   - E-Mail-Validierung client-seitig (zusätzlich zur Server-Validierung)
 *   - Keine E-Mail in URL-Parametern (Privacy)
 *   - Rate-Limit-Feedback für User
 *   - CSP: 'self' only
 */

(function () {
    'use strict';

    // -------------------------------------------------------
    // CONSTANTS
    // -------------------------------------------------------
    var API_URL = '/api/public/dark-web-check';
    var EMAIL_RE = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;
    var EMAIL_MAX = 254;

    // -------------------------------------------------------
    // DOM REFS
    // -------------------------------------------------------
    var emailInput    = document.getElementById('email-input');
    var checkBtn      = document.getElementById('check-btn');
    var checkBtnText  = document.getElementById('check-btn-text');
    var checkSpinner  = document.getElementById('check-spinner');
    var inputError    = document.getElementById('input-error');
    var resultArea    = document.getElementById('result-area');
    var resultBreach  = document.getElementById('result-breach');
    var resultClean   = document.getElementById('result-clean');
    var breachCount   = document.getElementById('breach-count');
    var breachTitle   = document.getElementById('breach-title');
    var breachTags    = document.getElementById('breach-tags');
    var breachNamesSection = document.getElementById('breach-names-section');
    var optinCheck    = document.getElementById('optin-check');
    var checkCard     = document.getElementById('check-card');
    var optinConfirmBreach = document.getElementById('optin-confirm-breach');
    var optinConfirmClean  = document.getElementById('optin-confirm-clean');

    // -------------------------------------------------------
    // HELPERS
    // -------------------------------------------------------
    function showError(msg) {
        inputError.textContent = msg;
        inputError.style.display = 'block';
        emailInput.classList.add('error-state');
    }

    function clearError() {
        inputError.style.display = 'none';
        inputError.textContent = '';
        emailInput.classList.remove('error-state');
    }

    function setLoading(loading) {
        checkBtn.disabled = loading;
        checkSpinner.style.display = loading ? 'block' : 'none';
        checkBtnText.style.display = loading ? 'none' : 'inline';
        if (loading) {
            checkCard.classList.add('scanning');
        } else {
            checkCard.classList.remove('scanning');
        }
    }

    function animateCount(el, target) {
        var start = 0;
        var duration = 600;
        var startTime = null;
        function step(ts) {
            if (!startTime) startTime = ts;
            var progress = Math.min((ts - startTime) / duration, 1);
            var ease = 1 - Math.pow(1 - progress, 3);
            el.textContent = Math.round(start + (target - start) * ease);
            if (progress < 1) requestAnimationFrame(step);
        }
        requestAnimationFrame(step);
    }

    // -------------------------------------------------------
    // VALIDATE EMAIL (client-side pre-check)
    // -------------------------------------------------------
    function validateEmail(email) {
        if (!email || email.trim() === '') return 'Bitte E-Mail-Adresse eingeben.';
        if (email.length > EMAIL_MAX) return 'E-Mail-Adresse zu lang (max. 254 Zeichen).';
        if (!EMAIL_RE.test(email)) return 'Bitte eine gültige E-Mail-Adresse eingeben.';
        return null;
    }

    // -------------------------------------------------------
    // SHOW RESULTS
    // -------------------------------------------------------
    function showBreach(data) {
        var count = data.count || 0;
        var names = data.breach_names || [];

        // Headline
        breachTitle.textContent = count === 1
            ? 'Datenleck gefunden!'
            : count + ' Datenlecks gefunden!';

        // Count animieren
        animateCount(breachCount, count);

        // Breach-Namen als Tags
        if (names.length > 0) {
            breachNamesSection.style.display = 'block';
            breachTags.innerHTML = '';
            names.forEach(function (name) {
                var tag = document.createElement('span');
                tag.className = 'breach-tag';
                tag.textContent = name;
                breachTags.appendChild(tag);
            });
        } else {
            breachNamesSection.style.display = 'none';
        }

        // Opt-In bestätigen
        if (data.opted_in) {
            optinConfirmBreach.style.display = 'flex';
        }

        resultClean.style.display = 'none';
        resultBreach.style.display = 'block';
        resultArea.style.display = 'block';

        // Smooth scroll
        setTimeout(function () {
            resultArea.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }, 100);
    }

    function showClean(data) {
        // Opt-In bestätigen
        if (data.opted_in) {
            optinConfirmClean.style.display = 'flex';
        }

        resultBreach.style.display = 'none';
        resultClean.style.display = 'block';
        resultArea.style.display = 'block';

        setTimeout(function () {
            resultArea.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }, 100);
    }

    // -------------------------------------------------------
    // PERFORM CHECK
    // -------------------------------------------------------
    function performCheck() {
        var email = (emailInput.value || '').trim().toLowerCase();
        var optIn = optinCheck.checked;

        clearError();

        // Client-seitige Validierung
        var validationError = validateEmail(email);
        if (validationError) {
            showError(validationError);
            emailInput.focus();
            return;
        }

        setLoading(true);

        var payload = JSON.stringify({ email: email, opt_in: optIn });

        fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: payload,
            credentials: 'omit',  // kein Cookie-Leakage
        })
        .then(function (resp) {
            if (resp.status === 429) {
                throw new Error('rate_limit');
            }
            if (resp.status === 503) {
                throw new Error('service_unavailable');
            }
            if (!resp.ok) {
                return resp.json().then(function (d) {
                    throw new Error(d.error || 'server_error');
                });
            }
            return resp.json();
        })
        .then(function (data) {
            setLoading(false);
            if (data.found === true) {
                showBreach(data);
            } else {
                showClean(data);
            }
        })
        .catch(function (err) {
            setLoading(false);
            var msg = err.message || '';
            if (msg === 'rate_limit') {
                showError('Zu viele Anfragen. Bitte warten Sie einen Moment und versuchen Sie es erneut.');
            } else if (msg === 'service_unavailable') {
                showError('Der Check-Dienst ist momentan nicht verfügbar. Bitte versuchen Sie es später erneut.');
            } else if (msg === 'Failed to fetch') {
                showError('Netzwerkfehler. Bitte Internetverbindung prüfen.');
            } else {
                showError('Fehler bei der Prüfung. Bitte erneut versuchen.');
            }
        });
    }

    // -------------------------------------------------------
    // EVENT LISTENERS
    // -------------------------------------------------------
    checkBtn.addEventListener('click', performCheck);

    emailInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') performCheck();
    });

    // Fehler-State beim Tippen entfernen
    emailInput.addEventListener('input', function () {
        if (emailInput.classList.contains('error-state')) clearError();
    });

    // Autofocus
    emailInput.focus();

    // UTM/Ref aus URL? => Redirect-Link für CTAs anpassen
    // (URL-Parameter werden NICHT an API gesendet — Privacy)
    try {
        var params = new URLSearchParams(window.location.search);
        var ref = params.get('ref');
        if (ref && /^[a-z0-9_-]{1,40}$/.test(ref)) {
            var ctaBtns = document.querySelectorAll('a[href*="/auth/register"]');
            ctaBtns.forEach(function (btn) {
                var url = new URL(btn.href, window.location.origin);
                url.searchParams.set('ref', ref);
                btn.href = url.toString();
            });
        }
    } catch (e) { /* ignorieren — non-critical */ }

})();
