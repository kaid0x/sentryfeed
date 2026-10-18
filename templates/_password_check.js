// The password check, shared by /password and the redesign prototypes.
// Needs Web Crypto and the page's elements with these ids:
// pw-form, pw, pw-toggle, pw-check, pw-error, result, result-title, result-text, result-sent.
(function () {
  const $ = (id) => document.getElementById(id);
  const form = $("pw-form"), input = $("pw"), toggle = $("pw-toggle"), button = $("pw-check");
  const error = $("pw-error"), result = $("result");

  async function hashPassword(password) {
    const bytes = new TextEncoder().encode(password);
    const digest = await window.crypto.subtle.digest("SHA-1", bytes);
    return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  }

  function showResult(severity, title, text, prefix) {
    result.className = "result sev-" + severity;
    $("result-title").textContent = title;
    $("result-text").textContent = text;
    const sent = $("result-sent");
    sent.replaceChildren();
    if (prefix) {
      const code = document.createElement("code");
      code.textContent = prefix;
      sent.append("This check sent only ", code, " (the first 5 of 40 hash characters).");
    }
    result.hidden = false;
  }

  function clearMessages() {
    error.hidden = true;
    result.hidden = true;
  }

  toggle.addEventListener("click", () => {
    const showing = input.type === "text";
    input.type = showing ? "password" : "text";
    toggle.textContent = showing ? "Show" : "Hide";
    toggle.setAttribute("aria-pressed", String(!showing));
    input.focus();
  });

  input.addEventListener("input", clearMessages);

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    clearMessages();
    if (!input.value) {
      error.textContent = "Enter a password first.";
      error.hidden = false;
      input.focus();
      return;
    }

    if (!window.crypto || !window.crypto.subtle) {
      showResult("yellow", "This browser cannot run the check",
        "Open SentryFeed over HTTPS in an up-to-date browser, then try again. Your password has not been sent.", null);
      return;
    }

    button.disabled = true;
    button.textContent = "Checking…";
    let requested = false;
    try {
      const hash = await hashPassword(input.value);
      const prefix = hash.slice(0, 5), suffix = hash.slice(5);
      requested = true;
      const resp = await fetch("/api/pwned/" + prefix, { cache: "no-store" });
      if (!resp.ok) throw new Error("HTTP " + resp.status);

      // Each line is SUFFIX:COUNT. Padding lines have a count of 0 and never match.
      let count = 0;
      for (const line of (await resp.text()).split("\n")) {
        const [lineSuffix, lineCount] = line.trim().split(":");
        if (lineSuffix === suffix) { count = parseInt(lineCount, 10) || 0; break; }
      }

      if (count > 0) {
        showResult("red",
          "Found in data breaches " + count.toLocaleString() + (count === 1 ? " time" : " times"),
          "Attackers try leaked passwords first, so this one isn't safe anywhere. If you use it, change it, starting with your email and banking accounts.",
          prefix);
      } else {
        showResult("green",
          "Not found in known breaches",
          "Good news, but it doesn't make the password strong. Use a long, different password for every site, ideally from a password manager.",
          prefix);
      }
    } catch (err) {
      showResult("yellow", "Couldn't run the check", requested
        ? "The breach database didn't respond. Try again in a minute."
        : "Your browser could not prepare the check. Try an up-to-date browser. Your password has not been sent.", null);
    } finally {
      button.disabled = false;
      button.textContent = "Check";
    }
  });
})();
