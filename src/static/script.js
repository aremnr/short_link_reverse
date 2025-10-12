document.getElementById("check-btn").addEventListener("click", async () => {
  const urlInput = document.getElementById("url-input").value.trim();
  const resultDiv = document.getElementById("result");
  const errorDiv = document.getElementById("error");
  const detailsBtn = document.getElementById("details-btn");
  const detailsSection = document.getElementById("details-section");
  const detailsContent = document.getElementById("details-content");

  if (!urlInput) {
    errorDiv.textContent = "Введите URL";
    errorDiv.classList.remove("hidden");
    resultDiv.classList.add("hidden");
    return;
  }

  errorDiv.classList.add("hidden");
  detailsBtn.classList.add("hidden");
  detailsSection.classList.add("hidden");

  try {
    const response = await fetch("/api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: urlInput }),
    });

    if (!response.ok) throw new Error("Ошибка при запросе к API");
    const data = await response.json();

    document.getElementById("original-url").textContent = data.original_url;
    const domainStatus = document.getElementById("domain-status");
    domainStatus.textContent = data.domain_status ? "Домен безопасен" : "Опасный домен";
    domainStatus.className = "status " + (data.domain_status ? "ok" : "bad");

    const googleList = document.getElementById("google-list");
    const openList = document.getElementById("open-list");
    const localList = document.getElementById("local-list");

    googleList.innerHTML = "";
    openList.innerHTML = "";
    localList.innerHTML = "";

    const googlePhish = data.google_safebrowsing.some(i => i?.phishing);
    const openPhish = data.open_source.some(i => i?.phishing);
    const localPhish = data.local_check.some(i => i?.phishing);

    document.getElementById("google").className = "column " + (googlePhish ? "phish" : "safe");
    document.getElementById("open-source").className = "column " + (openPhish ? "phish" : "safe");
    document.getElementById("local").className = "column " + (localPhish ? "phish" : "safe");

    data.google_safebrowsing.forEach((item, index) => {
      googleList.innerHTML += `<li>Проверка ${index + 1}: ${item.phishing ? "Фишинг" : "ОК"}</li>`;
    });

    data.open_source.forEach((item, index) => {
      if (!item) return;
      openList.innerHTML += `<li>${item.details.url || "Без URL"} — ${item.phishing ? "Фишинг" : "ОК"}</li>`;
    });

    data.local_check.forEach((item, index) => {
      localList.innerHTML += `<li>${item.details}</li>`;
    });

    // Сохраним детали в скрытый блок
    detailsContent.textContent = JSON.stringify({
      google_safebrowsing: data.google_safebrowsing,
      open_source: data.open_source,
      local_check: data.local_check
    }, null, 2);

    // Покажем кнопку "Посмотреть детали"
    detailsBtn.classList.remove("hidden");
    resultDiv.classList.remove("hidden");

  } catch (e) {
    console.error(e);
    errorDiv.textContent = "Ошибка при обращении к API";
    errorDiv.classList.remove("hidden");
    resultDiv.classList.add("hidden");
  }
});

// Обработчик кнопки "Посмотреть детали"
document.getElementById("details-btn").addEventListener("click", () => {
  const section = document.getElementById("details-section");
  section.classList.toggle("hidden");
});


