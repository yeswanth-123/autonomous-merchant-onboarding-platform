(function () {
  "use strict";

  function findAll(selector, parent) {
    return Array.prototype.slice.call((parent || document).querySelectorAll(selector));
  }

  findAll("[data-poll]").forEach(function (region) {
    var fragmentUrl = region.getAttribute("data-poll");
    var intervalMilliseconds = parseInt(region.getAttribute("data-interval") || "2500", 10);

    setInterval(function () {
      var focused = document.activeElement;
      if (focused && /INPUT|TEXTAREA|SELECT/.test(focused.tagName)) {
        return;
      }

      fetch(fragmentUrl, {
        headers: { "X-Requested-With": "poll" },
        credentials: "same-origin"
      })
        .then(function (response) {
          return response.ok ? response.text() : null;
        })
        .then(function (html) {
          if (html) {
            region.innerHTML = html;
          }
        })
        .catch(function () {
        });
    }, intervalMilliseconds);
  });

  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (form.hasAttribute("data-confirm") && !window.confirm(form.getAttribute("data-confirm"))) {
      event.preventDefault();
      return;
    }

    setTimeout(function () {
      findAll("button[type=submit],button:not([type])", form).forEach(function (button) {
        button.disabled = true;
      });
    }, 0);
  });

  findAll(".file-drop").forEach(function (dropZone) {
    var fileInput = dropZone.querySelector("input[type=file]");
    var title = dropZone.querySelector(".t");
    var originalTitle = title ? title.textContent : "";

    if (!fileInput) {
      return;
    }

    fileInput.addEventListener("change", function () {
      if (fileInput.files && fileInput.files.length) {
        dropZone.classList.add("has");
        title.textContent = "✓ " + fileInput.files[0].name;
      } else {
        dropZone.classList.remove("has");
        title.textContent = originalTitle;
      }
    });

    ["dragenter", "dragover"].forEach(function (eventName) {
      dropZone.addEventListener(eventName, function () {
        dropZone.classList.add("drag");
      });
    });

    ["dragleave", "drop"].forEach(function (eventName) {
      dropZone.addEventListener(eventName, function () {
        dropZone.classList.remove("drag");
      });
    });
  });

  var businessTypeSelect = document.querySelector("[data-business-type]");

  function syncGstFields() {
    if (!businessTypeSelect) {
      return;
    }

    var isIndividual = businessTypeSelect.value === "individual";

    findAll("[data-gst-field]").forEach(function (element) {
      element.classList.toggle("hidden", isIndividual);
    });

    findAll("[data-individual-field]").forEach(function (element) {
      element.classList.toggle("hidden", !isIndividual);
    });
  }

  if (businessTypeSelect) {
    businessTypeSelect.addEventListener("change", syncGstFields);
    syncGstFields();
  }

  findAll("[data-toggle-password]").forEach(function (button) {
    button.addEventListener("click", function () {
      var passwordInput = document.getElementById(button.getAttribute("data-toggle-password"));
      if (!passwordInput) {
        return;
      }

      passwordInput.type = passwordInput.type === "password" ? "text" : "password";
      button.textContent = passwordInput.type === "password" ? "Show" : "Hide";
    });
  });

  findAll(".flash").forEach(function (message) {
    setTimeout(function () {
      message.style.display = "none";
    }, 6000);
  });
})();
