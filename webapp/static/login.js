const form = document.getElementById("login-form");
const username = document.getElementById("username");
const password = document.getElementById("password");
const errorMessage = document.getElementById("login-error");
const submitButton = document.getElementById("login-button");
const toggleButton = document.getElementById("toggle-password");

function showError(message) {
  errorMessage.textContent = message;
  errorMessage.hidden = false;
}

toggleButton.addEventListener("click", () => {
  const visible = password.type === "text";
  password.type = visible ? "password" : "text";
  toggleButton.title = visible ? "显示密码" : "隐藏密码";
  toggleButton.setAttribute("aria-label", toggleButton.title);
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorMessage.hidden = true;
  if (!form.reportValidity()) return;

  submitButton.disabled = true;
  submitButton.textContent = "登录中…";
  try {
    const response = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: username.value.trim(), password: password.value }),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.detail || "登录失败，请重试");
    window.location.replace("/");
  } catch (error) {
    showError(error.message);
    password.select();
  } finally {
    submitButton.disabled = false;
    submitButton.textContent = "登录";
  }
});
