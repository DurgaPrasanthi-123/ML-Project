/**
 * Front-end Interaction & AJAX Controller for Phishing Detection System.
 * Connects frontend forms to Flask REST API via fetch() with loading indicators,
 * real-time validation, and dynamic visualization updates.
 */

document.addEventListener("DOMContentLoaded", () => {
  // Mobile Navigation Toggle
  const mobileToggle = document.getElementById("mobileToggle");
  const navLinks = document.getElementById("navLinks");
  if (mobileToggle && navLinks) {
    mobileToggle.addEventListener("click", () => {
      navLinks.classList.toggle("show");
    });
  }

  // URL Scanner Logic
  const urlForm = document.getElementById("urlForm");
  const urlInput = document.getElementById("urlInput");
  const loadingState = document.getElementById("loadingState");
  const resultCard = document.getElementById("resultCard");
  const errorAlert = document.getElementById("errorAlert");

  // Sample Chips Auto-Filler
  const sampleChips = document.querySelectorAll(".sample-chip");
  sampleChips.forEach((chip) => {
    chip.addEventListener("click", (e) => {
      e.preventDefault();
      const sampleUrl = chip.getAttribute("data-url");
      if (urlInput && sampleUrl) {
        urlInput.value = sampleUrl;
        urlInput.focus();
        // Trigger auto submit if requested
        if (urlForm) {
          submitUrlAnalysis(sampleUrl);
        }
      }
    });
  });

  if (urlForm) {
    urlForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const enteredUrl = urlInput.value.trim();
      submitUrlAnalysis(enteredUrl);
    });
  }

  async function submitUrlAnalysis(targetUrl) {
    if (!targetUrl) {
      showError("Please enter a website URL to analyze.");
      if (urlInput) urlInput.focus();
      return;
    }

    // Hide previous error and result
    hideError();
    if (resultCard) resultCard.style.display = "none";

    // Show loading state
    if (loadingState) loadingState.style.display = "block";

    try {
      const response = await fetch("/predict", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        body: JSON.stringify({ url: targetUrl })
      });

      const data = await response.json();

      if (loadingState) loadingState.style.display = "none";

      if (!response.ok || data.status === "error") {
        showError(data.message || "Failed to analyze URL. Please check the URL format.");
        return;
      }

      displayResult(data);
    } catch (err) {
      if (loadingState) loadingState.style.display = "none";
      showError("Network connection error. Ensure the Flask server is running.");
      console.error("Prediction fetch error:", err);
    }
  }

  function displayResult(data) {
    if (!resultCard) return;

    const isPhishing = data.is_phishing;
    const prediction = data.prediction;
    const confidence = data.confidence || 0;
    const targetUrl = data.url;
    const reasons = data.reasons || [];

    // Reset card classes
    resultCard.classList.remove("legitimate", "phishing");
    resultCard.classList.add(isPhishing ? "phishing" : "legitimate");

    // Update Verdict Header
    const badgeIcon = document.getElementById("resultBadgeIcon");
    const resultTitle = document.getElementById("resultTitle");
    const scoreNum = document.getElementById("scoreNum");
    const analyzedUrl = document.getElementById("analyzedUrl");
    const reasonsList = document.getElementById("reasonsList");

    if (badgeIcon) {
      badgeIcon.innerHTML = isPhishing ? "⚠" : "✓";
    }

    if (resultTitle) {
      resultTitle.textContent = isPhishing
        ? "⚠ Potential Phishing Website"
        : "✓ Legitimate Website";
    }

    if (scoreNum) {
      scoreNum.textContent = `${confidence.toFixed(1)}%`;
    }

    if (analyzedUrl) {
      analyzedUrl.textContent = targetUrl;
    }

    // Render Explanations / Indicators
    if (reasonsList) {
      reasonsList.innerHTML = "";
      if (reasons.length === 0) {
        reasonsList.innerHTML = `
          <div class="reason-item success">
            <div class="reason-title">✓ Standard Syntax</div>
            <p>No anomalous patterns, IP hostnames, or redirection tokens detected in the URL structure.</p>
          </div>
        `;
      } else {
        reasons.forEach((reason) => {
          const item = document.createElement("div");
          item.className = `reason-item ${reason.type || "warning"}`;
          item.innerHTML = `
            <div class="reason-title">${getReasonIcon(reason.type)} ${escapeHtml(reason.title)}</div>
            <p>${escapeHtml(reason.desc)}</p>
          `;
          reasonsList.appendChild(item);
        });
      }
    }

    // Show Card with smooth scroll
    resultCard.style.display = "block";
    resultCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function getReasonIcon(type) {
    switch (type) {
      case "danger": return "🔴";
      case "warning": return "🟡";
      case "success": return "🟢";
      default: return "ℹ️";
    }
  }

  function showError(message) {
    if (errorAlert) {
      errorAlert.textContent = message;
      errorAlert.style.display = "block";
    } else {
      alert(message);
    }
  }

  function hideError() {
    if (errorAlert) {
      errorAlert.style.display = "none";
      errorAlert.textContent = "";
    }
  }

  function escapeHtml(str) {
    if (!str) return "";
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
});
