// popup.js
document.addEventListener("DOMContentLoaded", () => {
  const toolSelector = document.getElementById("toolSelector");
  const scanButton = document.getElementById("scanButton");
  const payloadList = document.getElementById("payloadList");

  console.log("DOM loaded:", { toolSelector, scanButton, payloadList });
  if (!toolSelector || !scanButton || !payloadList) {
    console.error("Missing DOM elements:", { toolSelector, scanButton, payloadList });
    payloadList.innerHTML = "<p>Error: UI elements not found</p>";
    return;
  }
function loadXssPayloads() {
  console.log("Loading xss.txt...");
  fetch(chrome.runtime.getURL("xss.txt"))
    .then(response => {
      if (!response.ok) throw new Error("Failed to load xss.txt");
      return response.text();
    })
    .then(text => {
      const payloads = text.split("\n").map(line => line.trim()).filter(line => line !== "");
      console.log("Payloads loaded:", payloads.length);
      payloadList.innerHTML = "";
      if (payloads.length === 0) {
        payloadList.innerHTML = "<p>No payloads found in xss.txt</p>";
      } else {
        // Container for better layout
        const container = document.createElement("div");
        container.style.cssText = `
          display: flex;
          flex-direction: column;
          gap: 10px;
          padding: 10px;
          max-height: 400px;
          overflow-y: auto;
        `;

        payloads.forEach((payload, index) => {
          const payloadCard = document.createElement("div");
          payloadCard.style.cssText = `
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: #fff8e1;
            border: 1px solid #ffb300;
            border-radius: 5px;
            padding: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            transition: transform 0.2s, box-shadow 0.2s;
          `;
          payloadCard.onmouseover = () => {
            payloadCard.style.transform = "scale(1.02)";
            payloadCard.style.boxShadow = "0 4px 8px rgba(0,0,0,0.2)";
          };
          payloadCard.onmouseout = () => {
            payloadCard.style.transform = "scale(1)";
            payloadCard.style.boxShadow = "0 2px 4px rgba(0,0,0,0.1)";
          };

          const payloadText = document.createElement("span");
          payloadText.textContent = payload;
          payloadText.style.cssText = `
            flex-grow: 1;
            font-family: monospace;
            font-size: 14px;
            color: #333;
            word-break: break-all;
            margin-right: 10px;
          `;

          const copyButton = document.createElement("button");
          copyButton.textContent = "Copy";
          copyButton.style.cssText = `
            background: #ffb300;
            color: white;
            border: none;
            border-radius: 3px;
            padding: 5px 10px;
            cursor: pointer;
            font-size: 12px;
            transition: background 0.3s;
          `;
          copyButton.onmouseover = () => { copyButton.style.background = "#ffca28"; };
          copyButton.onmouseout = () => { copyButton.style.background = "#ffb300"; };

          copyButton.addEventListener("click", () => {
            navigator.clipboard.writeText(payload).then(() => {
              copyButton.textContent = "Copied!";
              copyButton.style.background = "#4CAF50";
              setTimeout(() => {
                copyButton.textContent = "Copy";
                copyButton.style.background = "#ffb300";
              }, 1000);
            });
          });

          payloadCard.appendChild(payloadText);
          payloadCard.appendChild(copyButton);
          container.appendChild(payloadCard);
        });

        payloadList.appendChild(container);
      }
    })
    .catch(error => {
      console.error("Error loading xss.txt:", error);
      payloadList.innerHTML = `<p>Error: ${error.message}</p>`;
    });
}
// Header Analyzer with Updated UI
function runHeaderAnalyzer() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs[0]) {
      payloadList.innerHTML = "<p>Error: No active tab</p>";
      return;
    }
    const tabId = tabs[0].id;
    const url = tabs[0].url;
    console.log("Running Header Analyzer on tab:", tabId, "url:", url);
    
    chrome.scripting.executeScript({
      target: { tabId },
      function: () => {
        fetch(window.location.href, { method: "GET" })
          .then(response => {
            const headers = [];
            for (let [name, value] of response.headers.entries()) {
              headers.push({ name, value });
            }
            chrome.runtime.sendMessage({ action: "headerResults", headers });
          })
          .catch(error => {
            chrome.runtime.sendMessage({ action: "headerResults", error: error.message });
          });
      }
    });    
    
    chrome.runtime.onMessage.addListener(function listener(message) {
      if (message.action === "headerResults") {
        if (message.error) {
          payloadList.innerHTML = `<p>Error fetching headers: ${message.error}</p>`;
        } else {
          const securityHeaders = {
            "cache-control": { present: false, value: "", recommended: "no-store, no-cache, must-revalidate" },
            "content-security-policy": { present: false, value: "", recommended: "default-src 'self'" },
            "permissions-policy": { present: false, value: "", recommended: "geolocation=(), microphone=()" },
            "referrer-policy": { present: false, value: "", recommended: "strict-origin-when-cross-origin" },
            "strict-transport-security": { present: false, value: "", recommended: "max-age=31536000; includeSubDomains" },
            "x-content-type-options": { present: false, value: "", recommended: "nosniff" },
            "x-frame-options": { present: false, value: "", recommended: "DENY or SAMEORIGIN" },
            "x-xss-protection": { present: false, value: "", recommended: "1; mode=block" }
          };
          
          const sensitiveHeaders = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-runtime", "x-version"];
          let disclosedSensitive = [];
          let allHeaders = [];
          
          message.headers.forEach(header => {
            const name = header.name.toLowerCase();
            const value = header.value;
            if (securityHeaders.hasOwnProperty(name)) {
              securityHeaders[name].present = true;
              securityHeaders[name].value = value;
            }
            if (sensitiveHeaders.includes(name)) {
              disclosedSensitive.push({ name: name.toUpperCase(), value });
            }
            allHeaders.push({ name: name.toUpperCase(), value });
          });

          // Build spacious table output
          let output = `
            <table style="width: 100%; border-collapse: collapse;">
              <tbody>
                <!-- Missing Security Headers -->
                <tr style="background: #ffebee; border-top: 2px solid #d32f2f;">
                  <td colspan="2" class="header-category" style="color: #d32f2f; padding: 10px; font-size: 16px;">Missing Security Headers</td>
                </tr>`;
          
          let missingFound = false;
          for (const [key, info] of Object.entries(securityHeaders)) {
            if (!info.present) {
              output += `
                <tr style="border-bottom: 1px solid #ddd;">
                  <td style="padding: 10px; width: 30%;"><strong>${key.toUpperCase()}</strong></td>
                  <td style="padding: 10px; width: 70%;"><span class="vulnerable">Missing</span> - Recommended: ${info.recommended}</td>
                </tr>`;
              missingFound = true;
            }
          }
          if (!missingFound) {
            output += `<tr><td colspan="2" style="padding: 10px;">None</td></tr>`;
          }

          // Misconfigured Headers
          output += `
                <tr style="background: #fff3e0; border-top: 2px solid #f57c00;">
                  <td colspan="2" class="header-category" style="color: #f57c00; padding: 10px; font-size: 16px;">Misconfigured Headers</td>
                </tr>`;
          
          let misconfigFound = false;
          for (const [key, info] of Object.entries(securityHeaders)) {
            if (info.present) {
              const recommendedCheck = info.recommended.split(",")[0].toLowerCase();
              if (!info.value.toLowerCase().includes(recommendedCheck)) {
                output += `
                  <tr style="border-bottom: 1px solid #ddd;">
                    <td style="padding: 10px; width: 30%;"><strong>${key.toUpperCase()}</strong></td>
                    <td style="padding: 10px; width: 70%;"><span class="vulnerable">Current: ${info.value}</span> - Recommended: ${info.recommended}</td>
                  </tr>`;
                misconfigFound = true;
              }
            }
          }
          if (!misconfigFound) {
            output += `<tr><td colspan="2" style="padding: 10px;">None</td></tr>`;
          }

          // Sensitive Headers Disclosed
          output += `
                <tr style="background: #f5f5f5; border-top: 2px dashed #616161;">
                  <td colspan="2" class="header-category" style="color: #616161; padding: 10px; font-size: 16px;">Sensitive Headers Disclosed</td>
                </tr>`;
          
          if (disclosedSensitive.length > 0) {
            disclosedSensitive.forEach(item => {
              output += `
                <tr style="border-bottom: 1px solid #ddd;">
                  <td style="padding: 10px; width: 30%;"><strong>${item.name}</strong></td>
                  <td style="padding: 10px; width: 70%;">${item.value}</td>
                </tr>`;
            });
          } else {
            output += `<tr><td colspan="2" style="padding: 10px;">None</td></tr>`;
          }

          // All Headers
          output += `
                <tr style="background: #e8eaf6; border-top: 2px dotted #3f51b5;">
                  <td colspan="2" class="header-category" style="color: #3f51b5; padding: 10px; font-size: 16px;">All Headers</td>
                </tr>`;
          
          allHeaders.forEach(header => {
            output += `
              <tr style="border-bottom: 1px solid #ddd;">
                <td style="padding: 10px; width: 30%;"><strong>${header.name}</strong></td>
                <td style="padding: 10px; width: 70%;">${header.value}</td>
              </tr>`;
          });

          output += `</tbody></table>`;
          payloadList.innerHTML = output;
        }
        chrome.runtime.onMessage.removeListener(listener);
      }
    });
  });
}
  function runCookieAnalyzer() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs[0]) {
        payloadList.innerHTML = "<p>Error: No active tab</p>";
        return;
      }
      const tabId = tabs[0].id;
      const url = tabs[0].url;
      console.log("Running Cookie Analyzer on tab:", tabId, "url:", url);

      let activeUrl;
      try {
        activeUrl = new URL(url).href;
        console.log("Active URL for cookies:", activeUrl);
      } catch (e) {
        console.error("Error parsing URL:", e);
        payloadList.innerHTML = "<p>Invalid URL for cookie analysis.</p>";
        return;
      }

      if (!activeUrl.startsWith("http")) {
        payloadList.innerHTML = "<p>Cookies are not available for this URL.</p>";
        return;
      }

      chrome.cookies.getAll({ url: activeUrl }, (cookies) => {
        console.log("Cookies retrieved:", cookies);

        chrome.scripting.executeScript({
          target: { tabId },
          function: () => {
            return {
              sessionStorage: Object.entries(sessionStorage),
              localStorage: Object.entries(localStorage)
            };
          }
        }, (results) => {
          if (!results || !results[0] || !results[0].result) {
            console.error("Failed to retrieve storage data");
            payloadList.innerHTML = "<p>Error retrieving storage data</p>";
            return;
          }

          const { sessionStorage, localStorage } = results[0].result;
          console.log("Session Storage:", sessionStorage);
          console.log("Local Storage:", localStorage);

          const sensitivePatterns = /(eyJ|token|key|password|email|secret|session|sid|api_key|bearer|credit|cc_|phone|tel_|pass|pwd)/i;
          const jwtPattern = /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/;

          let output = `
            <table style="width: 100%; border-collapse: collapse;">
              <tbody>
                <tr style="background: #e0f7fa; border-top: 2px solid #0288d1;">
                  <td colspan="2" class="header-category" style="color: #0288d1; padding: 10px; font-size: 16px;">Cookies</td>
                </tr>`;

          if (!cookies || cookies.length === 0) {
            output += `<tr><td colspan="2" style="padding: 10px;">No cookies detected</td></tr>`;
          } else {
            cookies.forEach(cookie => {
              const secureChecked = cookie.secure ? "checked" : "";
              const httpOnlyChecked = cookie.httpOnly ? "checked" : "";
              const sameSiteChecked = cookie.sameSite && (cookie.sameSite.toLowerCase() === "lax" || cookie.sameSite.toLowerCase() === "strict") ? "checked" : "";
              let issues = [];
              if (!cookie.secure) issues.push("Missing Secure");
              if (!cookie.httpOnly) issues.push("Missing HttpOnly");
              if (!cookie.sameSite || cookie.sameSite.toLowerCase() === "none") issues.push("Missing/Weak SameSite");

              if (jwtPattern.test(cookie.value)) issues.push("JWT Token");
              else if (sensitivePatterns.test(cookie.name) || sensitivePatterns.test(cookie.value)) {
                if (/session|sid/i.test(cookie.name)) issues.push("Session Token");
                else if (/api_key|token|bearer/i.test(cookie.name)) issues.push("API Token");
                else if (/email/i.test(cookie.value)) issues.push("Sensitive (Email)");
                else if (/pass|pwd/i.test(cookie.name)) issues.push("Sensitive (Password)");
                else if (/credit|cc_/i.test(cookie.name)) issues.push("Sensitive (Credit Card)");
                else if (/phone|tel_/i.test(cookie.name)) issues.push("Sensitive (Phone)");
                else issues.push("Sensitive Data");
              }

              const issuesChecked = issues.length > 0 ? "checked" : "";
              output += `
                <tr style="border-bottom: 1px solid #ddd;">
                  <td style="padding: 10px; width: 20%;"><strong>${cookie.name}</strong></td>
                  <td style="padding: 10px; width: 80%;">${cookie.value}</td>
                </tr>
                <tr>
                  <td style="padding: 5px 10px;">Security:</td>
                  <td style="padding: 5px 10px;">
                    Secure: <input type="checkbox" ${secureChecked} disabled>
                    HttpOnly: <input type="checkbox" ${httpOnlyChecked} disabled>
                    SameSite: <input type="checkbox" ${sameSiteChecked} disabled>
                  </td>
                </tr>
                <tr>
                  <td style="padding: 5px 10px;">Issues:</td>
                  <td style="padding: 5px 10px;">
                    <input type="checkbox" ${issuesChecked} disabled> 
                    ${issues.length > 0 ? '<span class="sensitive">' + issues.join(", ") + '</span>' : "None"}
                  </td>
                </tr>`;
            });
          }

          output += `
                <tr style="background: #e8f5e9; border-top: 2px dashed #4CAF50;">
                  <td colspan="2" class="header-category" style="color: #4CAF50; padding: 10px; font-size: 16px;">Session Storage</td>
                </tr>`;

          if (sessionStorage.length === 0) {
            output += `<tr><td colspan="2" style="padding: 10px;">No session storage items detected</td></tr>`;
          } else {
            sessionStorage.forEach(([key, value]) => {
              let issues = [];
              if (jwtPattern.test(value)) issues.push("JWT Token");
              else if (sensitivePatterns.test(key) || sensitivePatterns.test(value)) {
                if (/session|sid/i.test(key)) issues.push("Session Token");
                else if (/api_key|token|bearer/i.test(key)) issues.push("API Token");
                else if (/email/i.test(value)) issues.push("Sensitive (Email)");
                else if (/pass|pwd/i.test(key)) issues.push("Sensitive (Password)");
                else if (/credit|cc_/i.test(key)) issues.push("Sensitive (Credit Card)");
                else if (/phone|tel_/i.test(key)) issues.push("Sensitive (Phone)");
                else issues.push("Sensitive Data");
              }

              const issuesChecked = issues.length > 0 ? "checked" : "";
              output += `
                <tr style="border-bottom: 1px solid #ddd;">
                  <td style="padding: 10px; width: 20%;"><strong>${key}</strong></td>
                  <td style="padding: 10px; width: 80%;">${value}</td>
                </tr>
                <tr>
                  <td style="padding: 5px 10px;">Security:</td>
                  <td style="padding: 5px 10px;">
                    Secure: <input type="checkbox" disabled>
                    HttpOnly: <input type="checkbox" disabled>
                    SameSite: <input type="checkbox" disabled>
                  </td>
                </tr>
                <tr>
                  <td style="padding: 5px 10px;">Issues:</td>
                  <td style="padding: 5px 10px;">
                    <input type="checkbox" ${issuesChecked} disabled> 
                    ${issues.length > 0 ? '<span class="sensitive">' + issues.join(", ") + '</span>' : "None"}
                  </td>
                </tr>`;
            });
          }

          output += `
                <tr style="background: #f3e5f5; border-top: 2px dotted #8e24aa;">
                  <td colspan="2" class="header-category" style="color: #8e24aa; padding: 10px; font-size: 16px;">Local Storage</td>
                </tr>`;

          if (localStorage.length === 0) {
            output += `<tr><td colspan="2" style="padding: 10px;">No local storage items detected</td></tr>`;
          } else {
            localStorage.forEach(([key, value]) => {
              let issues = [];
              if (jwtPattern.test(value)) issues.push("JWT Token");
              else if (sensitivePatterns.test(key) || sensitivePatterns.test(value)) {
                if (/session|sid/i.test(key)) issues.push("Session Token");
                else if (/api_key|token|bearer/i.test(key)) issues.push("API Token");
                else if (/email/i.test(value)) issues.push("Sensitive (Email)");
                else if (/pass|pwd/i.test(key)) issues.push("Sensitive (Password)");
                else if (/credit|cc_/i.test(key)) issues.push("Sensitive (Credit Card)");
                else if (/phone|tel_/i.test(key)) issues.push("Sensitive (Phone)");
                else issues.push("Sensitive Data");
              }

              const issuesChecked = issues.length > 0 ? "checked" : "";
              output += `
                <tr style="border-bottom: 1px solid #ddd;">
                  <td style="padding: 10px; width: 20%;"><strong>${key}</strong></td>
                  <td style="padding: 10px; width: 80%;">${value}</td>
                </tr>
                <tr>
                  <td style="padding: 5px 10px;">Security:</td>
                  <td style="padding: 5px 10px;">
                    Secure: <input type="checkbox" disabled>
                    HttpOnly: <input type="checkbox" disabled>
                    SameSite: <input type="checkbox" disabled>
                  </td>
                </tr>
                <tr>
                  <td style="padding: 5px 10px;">Issues:</td>
                  <td style="padding: 5px 10px;">
                    <input type="checkbox" ${issuesChecked} disabled> 
                    ${issues.length > 0 ? '<span class="sensitive">' + issues.join(", ") + '</span>' : "None"}
                  </td>
                </tr>`;
            });
          }

          output += `</tbody></table>`;
          payloadList.innerHTML = output;
        });
      });
    });
  }

  document.getElementById("scanButton").addEventListener("click", () => {
  const selectedTool = document.getElementById("toolSelector").value;

  if (selectedTool === "openredirect") {
    // Trigger the Open Redirect scan
    chrome.runtime.sendMessage({ action: "startOpenRedirectScan" }, (response) => {
      if (response && response.status === "started") {
        console.log("Open Redirect scan started...");
      }
    });
  }
});
// Function to inject and run the Open Redirect Analyzer
function runOpenRedirectAnalyzer() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs[0]) {
      payloadList.innerHTML = "<p>Error: No active tab</p>";
      return;
    }
    const tabId = tabs[0].id;

    console.log("Injecting openredirect.js into tab:", tabId);

    chrome.scripting.executeScript({
      target: { tabId },
      files: ["openredirect.js"]
    }, () => {
      if (chrome.runtime.lastError) {
        console.error("Script injection failed:", chrome.runtime.lastError.message);
        payloadList.innerHTML = `<p>Error: ${chrome.runtime.lastError.message}</p>`;
      } else {
        console.log("openredirect.js injected successfully");
        payloadList.innerHTML = "<p>Scanning for open redirects...</p>";

        const listener = (message) => {
          if (message.action === "openRedirectScanComplete") {
            if (message.results.length > 0) {
              let resultHTML = "<h3>Open Redirects Found:</h3><ul>";
              message.results.forEach(result => {
                resultHTML += `<li>Param: <b>${result.param}</b>, URL: <a href="${result.url}" target="_blank">${result.url}</a></li>`;
              });
              resultHTML += "</ul>";
              payloadList.innerHTML = resultHTML;
            } else {
              payloadList.innerHTML = "<p>No Open Redirect vulnerabilities detected.</p>";
            }
            chrome.runtime.onMessage.removeListener(listener);
          }
        };

        // Listen for scan completion message
        chrome.runtime.onMessage.addListener(listener);

        // Fallback in case no message is received
        setTimeout(() => {
          if (payloadList.innerHTML === "<p>Scanning for open redirects...</p>") {
            payloadList.innerHTML = "<p>Scan likely complete. Check console for more info.</p>";
            chrome.runtime.onMessage.removeListener(listener);
          }
        }, 5000);
      }
    });
  });
}

function runHttpMethodsScanner() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs[0]) {
      payloadList.innerHTML = "<p>Error: No active tab</p>";
      return;
    }
    const tabId = tabs[0].id;

    console.log("Injecting httpchecker.js into tab:", tabId);

    chrome.scripting.executeScript({
      target: { tabId },
      files: ["httpchecker.js"]
    }, () => {
      if (chrome.runtime.lastError) {
        console.error("Script injection failed:", chrome.runtime.lastError.message);
        payloadList.innerHTML = `<p>Error: ${chrome.runtime.lastError.message}</p>`;
      } else {
        console.log("httpchecker.js injected successfully");
        payloadList.innerHTML = "<p>Scanning HTTP methods...</p>";

        const listener = (message) => {
          if (message.action === "httpMethodsScanComplete") {
            console.log("Scan completed, results sent to tab console");
            payloadList.innerHTML = "<p>Scan complete. Check console for more info.</p>";
            chrome.runtime.onMessage.removeListener(listener);
          }
        };
        chrome.runtime.onMessage.addListener(listener);

        // Fallback: if no message after 5 seconds, assume console has it
        setTimeout(() => {
          if (payloadList.innerHTML === "<p>Scanning HTTP methods...</p>") {
            payloadList.innerHTML = "<p>Scan likely complete. Check console for more info.</p>";
            chrome.runtime.onMessage.removeListener(listener);
          }
        }, 5000);
      }
    });
  });
}
  toolSelector.addEventListener("change", () => {
    const selectedTool = toolSelector.value;
    console.log("Tool changed to:", selectedTool);
    payloadList.innerHTML = "";
    if (selectedTool === "xss") {
      scanButton.style.display = "none";
      loadXssPayloads();
    } else {
      scanButton.style.display = "block";
      payloadList.innerHTML = "<p>Click Scan to run the test.</p>";
    }
  });

  scanButton.addEventListener("click", () => {
    const selectedTool = toolSelector.value;
    console.log("Scan button clicked for:", selectedTool);
    payloadList.innerHTML = `<p>Scanning for ${selectedTool}...</p>`;
    if (selectedTool === "headers") {
      runHeaderAnalyzer();
    } else if (selectedTool === "cookies") {
      runCookieAnalyzer();
    } else if (selectedTool === "openredirect") {
      runOpenRedirectAnalyzer();
    } else if (selectedTool === "httpmethods") {
      runHttpMethodsScanner();
    } else {
      payloadList.innerHTML = `<p>Scanning ${selectedTool}... This is a test!</p>`;
    }
  });

  console.log("Initial tool:", toolSelector.value);
  if (toolSelector.value === "xss") {
    scanButton.style.display = "none";
    loadXssPayloads();
  } else {
    scanButton.style.display = "block";
    payloadList.innerHTML = "<p>Click Scan to run the test.</p>";
  }
});