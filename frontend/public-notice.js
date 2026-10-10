(function () {
    "use strict";

    fetch("/health", { headers: { Accept: "application/json" } })
        .then(function (response) {
            if (!response.ok) return null;
            return response.json();
        })
        .then(function (health) {
            if (!health || health.database !== "disabled_public_demo") return;

            var style = document.createElement("style");
            style.textContent =
                ".public-demo-notice{position:relative;z-index:10000;padding:10px 16px;" +
                "background:#332713;color:#ffe3a2;border-bottom:1px solid #8c672c;" +
                "font:13px/1.55 system-ui,Segoe UI,Arial,sans-serif;text-align:center}" +
                ".public-demo-notice strong{color:#fff0c5}";
            document.head.appendChild(style);

            var notice = document.createElement("aside");
            notice.className = "public-demo-notice";
            notice.setAttribute("role", "note");
            var strong = document.createElement("strong");
            strong.textContent = "Public demo privacy notice: ";
            notice.appendChild(strong);
            notice.appendChild(document.createTextNode(
                "do not submit passwords, OTPs, private links, personal, or confidential data. " +
                "Scans are not saved to shared history. URL, message, and image inputs may be sent " +
                "to Gemini if the operator configures its API key."
            ));
            document.body.prepend(notice);
        })
        .catch(function () {});
}());
