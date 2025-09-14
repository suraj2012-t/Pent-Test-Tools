// Add webRequest listener for capturing headers
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.type === "main_frame") {
      const headers = details.responseHeaders.map(header => ({
        name: header.name.toLowerCase(),
        value: header.value
      }));
      console.log("Captured headers:", headers);

      // Send captured headers to the active tab
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs.length > 0) {
          chrome.tabs.sendMessage(tabs[0].id, { action: "headerResults", headers });
        }
      });
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// Handle messages from the popup or content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "startHeaderScan") {
    console.log("Header scan initiated...");
    sendResponse({ status: "started" });
  }
});
