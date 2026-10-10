(function () {
    "use strict";

    var form = document.getElementById("login-form");
    var pin = document.getElementById("pin");
    var error = document.getElementById("login-error");

    var MESSAGES = {
        wrong_pin: "That PIN is not right.",
        too_many_attempts: "Too many attempts. Wait a moment and try again."
    };

    form.addEventListener("submit", function (event) {
        event.preventDefault();
        error.textContent = "";
        fetch("/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-Requested-With": "autostream-hd"
            },
            body: JSON.stringify({ pin: pin.value })
        }).then(function (response) {
            return response.json().then(function (body) {
                return { ok: response.ok, body: body };
            });
        }).then(function (result) {
            if (result.ok) {
                window.location.assign("/");
                return;
            }
            error.textContent = MESSAGES[result.body.error] || "Sign in failed.";
            pin.value = "";
        }).catch(function () {
            error.textContent = "Sign in failed.";
        });
    });
}());
