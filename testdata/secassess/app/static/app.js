// Notes demo application: sign-in form handler (local testing only).
document.getElementById("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  const response = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: form.get("username"), password: form.get("password") }),
  });
  const text = await response.text();
  document.getElementById("login-result").textContent = response.status + " " + text;
});
