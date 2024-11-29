// Initialize or retrieve the seed
let seed = localStorage.getItem('passwordSeed');
if (!seed) {
    seed = crypto.getRandomValues(new Uint8Array(28));
    localStorage.setItem('passwordSeed', Array.from(seed).map(b => b.toString(16).padStart(2, '0')).join(''));
} else {
    seed = new Uint8Array(seed.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

// Toggle password visibility
const eyeIcon = document.getElementById('eye-icon');
let isPasswordVisible = false;

eyeIcon.addEventListener('click', () => {
        isPasswordVisible = !isPasswordVisible; // Toggle the boolean
        passwordInput.type = isPasswordVisible ? 'text' : 'password'; // Change the input type
        eyeIcon.textContent = isPasswordVisible ? '🙈' : '👁'; // Change the icon
    });

    // Temporary visibility toggle on mouse over
    eyeIcon.addEventListener('mouseover', () => {
        passwordInput.type = isPasswordVisible ? 'password' : 'text'; // toggle to current state
    });

    eyeIcon.addEventListener('mouseleave', () => {
        passwordInput.type = isPasswordVisible ? 'text' : 'password'; // Revert to current state
    });


function debounce(func, delay) {
    let timeoutId;
    return function(...args) {
        clearTimeout(timeoutId);
        timeoutId = setTimeout(() => {
            func.apply(this, args);
        }, delay);
    };
}

async function checkPassword(password) {
    const resultElement = document.getElementById('result');
    const entropyElement = document.getElementById('entropy');
    const shannonEntropyElement = document.getElementById('shannonEntropy');
    const zxcvbnResultElement = document.getElementById('zxcvbnResult');
    const fortifiedPasswordElement = document.getElementById('fortifiedPassword');
    const fortifiedPasswordStatsElement = document.getElementById('fortifiedPasswordStats');

    if (!password) {
        resultElement.textContent = 'Please enter a password.';
        return;
    }

    const sha1Hash = await computeHash(password, 'SHA-1');
    const sha256Hash = await computeHash(password, 'SHA-256');

    const prefix = sha1Hash.slice(0, 5);
    const suffix = sha1Hash.slice(5).toUpperCase();

    try {
        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        const text = await response.text();
        const hashes = text.split('\n');

        const found = hashes.some(hash => hash.startsWith(suffix));

        if (found) {
            resultElement.innerHTML = 'This password has been found in a data breach.<br>Please choose a different password.';
        } else {
            resultElement.textContent = 'Password not found in known data breaches.';
        }

        // Generate fortified password
        const fortifiedPassword = await fortifyPassword(password);
        fortifiedPasswordElement.textContent = `Fortified password (${[...fortifiedPassword.normalize('NFKC')].length}c): ${fortifiedPassword}`;

        // Calculate fortified password stats
        const fortifiedZxcvbnResult = zxcvbn(fortifiedPassword);
        const fortifiedLog10Guesses = Math.log10(fortifiedZxcvbnResult.guesses);
        const fortifiedCrackTime10BSeconds = fortifiedZxcvbnResult.guesses / (10 * 1000 * 1000 * 1000);
        const fortifiedCrackTimeYears = fortifiedCrackTime10BSeconds / (365 * 24 * 60 * 60);
        const fortifiedEntropy = calculateEntropy(fortifiedPassword);
        fortifiedPasswordStatsElement.innerHTML = `
            Fortified password stats:<br>
            log<sub>10</sub>(Guesses): ${fortifiedLog10Guesses.toFixed(2)}<br>
            Time to crack at 10B/s: ${fortifiedCrackTimeYears.toFixed(2)} years<br>
            Entropy: ${fortifiedEntropy.toFixed(2)} bits
        `;

        // Calculate simple entropy
        const entropy = calculateEntropy(password);
        entropyElement.textContent = `Simple password entropy: ${entropy.toFixed(2)} bits`;
        updateEntropyGauge(entropy);

        // Calculate Shannon entropy
        const shannonEntropy = calculateShannonEntropy(password);
        shannonEntropyElement.textContent = `Shannon entropy: ${shannonEntropy.toFixed(2)} bits`;

        // Calculate zxcvbn strength and display full result
        const zxcvbnResult = zxcvbn(password);
        displayZxcvbnResult(zxcvbnResult, fortifiedPassword);
        updateGuessesGauge(zxcvbnResult.guesses);

    } catch (error) {
        resultElement.textContent = 'An error occurred while checking the password.';
        console.error('Error:', error);
    }
}

const debouncedCheckPassword = debounce(checkPassword, 300);

document.getElementById('passwordInput').addEventListener('input', function() {
    debouncedCheckPassword(this.value);
});

async function computeHash(text, algorithm) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest(algorithm, data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
}

function calculateEntropy(password) {
    const charsetSize = getCharsetSize(password);
    return Math.log2(Math.pow(charsetSize, password.length));
}

function getCharsetSize(password) {
    let size = 0;
    if (/[a-z]/.test(password)) size += 26;
    if (/[A-Z]/.test(password)) size += 26;
    if (/[0-9]/.test(password)) size += 10;
    if (/[^a-zA-Z0-9]/.test(password)) size += 32;
    return size;
}

function calculateShannonEntropy(password) {
    const charFrequency = {};
    for (let char of password) {
        charFrequency[char] = (charFrequency[char] || 0) + 1;
    }

    let entropy = 0;
    for (let char in charFrequency) {
        const probability = charFrequency[char] / password.length;
        entropy -= probability * Math.log2(probability);
    }

    return entropy * password.length;
}

function displayZxcvbnResult(result, fortifiedPassword) {
    const log10Guesses = Math.log10(result.guesses);
    const zxcvbnResultElement = document.getElementById('zxcvbnResult');
            const qm = 'QmRHZotFEHvgSwe69awUDs4igYgQFsnjiiBjFm9t1dWG2H';
                    const adoptString = `<a href="https://ipfs.safewatch.care/ipfs/${qm}/popup/popup.html">Adopt a Password</a> from our unbreakable password manager`;
    if (result.feedback.suggestions.length !== 0) {
        result.feedback.suggestions.push(`we suggest you use the following password: ${fortifiedPassword} for its strength`);
        result.feedback.suggestions.push('or better: ' + adoptString);
    }
    const crackTime10B = result.guesses / (10 * 1000 * 1000 * 1000);
    zxcvbnResultElement.innerHTML = `
        <h3>zxcvbn Results:</h3>
        <p>Score: ${result.score}/4<br>
           Estimated crack time: ${result.crack_times_display.offline_slow_hashing_1e4_per_second}<br>
           Log10 Guesses: ${log10Guesses.toFixed(2)}<br>
           Time to crack at 10B/s: ${crackTime10B.toFixed(2)} seconds</p>
        <table>
            <tr>
                <th>Attack Scenario</th>
                <th>Guesses</th>
                <th>Crack Time</th>
            </tr>
            <tr>
                <td>100 / hour <small>(throttled online attack)</small></td>
                <td>10<sup>${log10Guesses.toFixed(2)}</sup></td>
                <td>${result.crack_times_display.online_throttling_100_per_hour}</td>
            </tr>
            <tr>
                <td>10 / second <small>(unthrottled online attack)</small></td>
                <td>10<sup>${log10Guesses.toFixed(2)}</sup></td>
                <td>${result.crack_times_display.online_no_throttling_10_per_second}</td>
            </tr>
            <tr>
                <td>10k / second <small>(offline attack, slow hash, many cores)</small></td>
                <td>10<sup>${log10Guesses.toFixed(2)}</sup></td>
                <td>${result.crack_times_display.offline_slow_hashing_1e4_per_second}</td>
            </tr>
            <tr>
                <td>10B / second <small>(offline attack, fast hash, many cores)</small></td>
                <td>10<sup>${log10Guesses.toFixed(2)}</sup></td>
                <td>${result.crack_times_display.offline_fast_hashing_1e10_per_second}</td>
            </tr>
        </table>
        <p>Feedback: ${result.feedback.warning ? result.feedback.warning : 'No specific warnings'}</p>
        <p>Suggestions: ${result.feedback.suggestions.join(', ') || adoptString}</p>
    `;
}

function updateEntropyGauge(entropy) {
    const gaugeBar = document.querySelector('#entropyGauge .gauge-bar');
    const gaugeLabel = document.querySelector('#entropyGauge .gauge-label');
    const percentage = Math.min(entropy / 128 * 100, 100); // Assuming 128 bits as maximum
    gaugeBar.style.width = `${percentage}%`;
    gaugeBar.style.backgroundImage = getGradient(percentage);
    gaugeLabel.textContent = `${entropy.toFixed(2)} bits`;
    updateLabelPosition(gaugeLabel, percentage);
}

function updateGuessesGauge(guesses) {
    const gaugeBar = document.querySelector('#guessesGauge .gauge-bar');
    const gaugeLabel = document.querySelector('#guessesGauge .gauge-label');
    const log10Guesses = Math.log10(guesses);
    const percentage = Math.min(log10Guesses / 15 * 100, 100); // Assuming 10^15 as maximum
    gaugeBar.style.width = `${percentage}%`;
    gaugeBar.style.backgroundImage = getGradient(percentage);
    gaugeLabel.textContent = `${log10Guesses.toFixed(2)}`;
    updateLabelPosition(gaugeLabel, percentage);
}

function updateLabelPosition(label, percentage) {
    if (percentage < 50) {
        label.style.left = `${percentage}%`;
        label.style.right = 'auto';
        label.style.textAlign = 'left';
        label.style.marginLeft = '5px';
    } else {
        label.style.left = 'auto';
        label.style.right = `${100 - percentage}%`;
        label.style.textAlign = 'right';
        label.style.marginRight = '5px';
    }
}

function getGradient(percentage) {
    const startColor = getColorForPercentage(0);
    const endColor = getColorForPercentage(percentage / 100);
    
    if (percentage <= 50) {
        return `linear-gradient(to right, ${startColor}, ${endColor})`;
    } else {
        const midColor = getColorForPercentage(0.5);
        const midPoint = (50 / percentage) * 100;
        return `linear-gradient(to right, ${startColor}, ${midColor} ${midPoint}%, ${endColor})`;
    }
}

function getColorForPercentage(value) {
    const hue = value * 120; // 0 to 120 (red to green)
    return `hsl(${hue}, 100%, 50%)`;
}

async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password + Array.from(seed).join(','));
    const hashBuffer = await crypto.subtle.digest('SHA-512', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function expandedBaseEncode(hash) {
    const animalSet = "🐶|🐕|🐩|🐺|🐱|🐈|🐯|🐅|🐆|🦓|🐴|🦄|🐖|🐷|🐽|🐏|🐑|🐐|🐘|🦣|🐭|🐀|🐹|🐰|🐇|🐻|🐨|🐼|🦥|🦦|🦊|🦝|🐾|🐉|🐲|🦕|🦖|🐢|🐍|🦎|🦋|🐜|🐝|🐞|🐌|🐡|🐠|🐟|🐬|🐳|🐋|🐧|🐦|🐤|🐣|🦅|🦆|🦉|🦢|🦜|🐸|🐊|🦑|🐙|🦞|🦐|🐚|🦈|🦙|🦒|🐻‍❄️|🦡|🦚|🦘|🐵|🐒|🦍|🦮|🐈‍⬛|🦁|🐎|🦌|🐮|🐂|🐃|🐗|🐪|🐫|🦏|🦛|🐁|🐿|🦫|🦔|🦇|🦃|🐓|🐔|🐥|🕊|🦀|🦪|🐛|🕷|🕸|🦂|🦟|🦗|🪲|🪳|🪰|🐕‍🦺|🦨|🦩|🦤|🪶|🪱|🦭|🪸".split('|');
    // console.debug(animalSet);
    const charset = [ // ..."0123546789ABCDFEGHIJKLWNOPQRSTUVMXYZabcdefghjiklnmopqrstuvwxyz+/",
        ...animalSet,
        ...("💪🏻|💪🏼|💪🏽|💪🏾|💪🏿".normalize('NFKC').split('|')) ];
    const base = BigInt(charset.length);
    console.debug({"charset.length": base});
    let result = '';
    let value = BigInt('0x' + hash);
    while (value > 0 && result.length < 128) {
        result = charset[Number(value % base)] + result;
        value /= base;
    }
    //console.debug({result});
    return result;
}

async function fortifyPassword(password) {
    const hash = await hashPassword(password);
    return expandedBaseEncode(hash.substr(-81,80));

}

document.getElementById('copyButton').addEventListener('click', function() {
    const fortifiedPasswordElement = document.getElementById('fortifiedPassword');
    const fortifiedPassword = fortifiedPasswordElement.textContent.split(': ')[1];
    
    if (fortifiedPassword) {
        navigator.clipboard.writeText(fortifiedPassword).then(function() {
            alert('Fortified password copied to clipboard!');
        }, function(err) {
            console.error('Could not copy text: ', err);
        });
    } else {
        alert('No fortified password to copy.');
    }
});

let once = false;
document.addEventListener('DOMContentLoaded', function() {
    const initialPassword = document.getElementById('passwordInput').value;
    if (! once) {
        once = true;
        if (initialPassword) {
            checkPassword(initialPassword);
        } else {
            debouncedCheckPassword('password123');
        }
    }
});


