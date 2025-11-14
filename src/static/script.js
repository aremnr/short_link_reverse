document.getElementById("check-btn").addEventListener("click", async () => {
  const urlInput = document.getElementById("url-input").value.trim();
  const resultDiv = document.getElementById("result");
  const errorDiv = document.getElementById("error");
  const detailsBtn = document.getElementById("details-btn");
  const detailsSection = document.getElementById("details-section");
  const detailsContent = document.getElementById("details-content");
  const loader = document.getElementById("loader");
  var is_phish = 0
  if (!urlInput) {
    errorDiv.textContent = "Введите URL";
    errorDiv.classList.remove("hidden");
    resultDiv.classList.add("hidden");
    return;
  }

  
  errorDiv.classList.add("hidden");
  resultDiv.classList.add("hidden");
  detailsBtn.classList.add("hidden");
  detailsSection.classList.add("hidden");
  
  
  loader.classList.add("visible");
  loader.classList.remove("hidden");

  try {
    const requestBody = JSON.stringify({ url: urlInput });
    const headers = { "Content-Type": "application/json" };

    const domainRequest = fetch("/api/phishing_check_by_damain", {
      method: "POST", headers, body: requestBody
    });
    const dynamicRequest = fetch("/api/phishing_check_dynamic", {
      method: "POST", headers, body: requestBody
    });
    const localRequest = fetch("/api/phishing_check_local", {
      method: "POST", headers, body: requestBody
    });

    const [domainResponse, dynamicResponse, localResponse] = await Promise.all([
      domainRequest,
      dynamicRequest,
      localRequest,
    ]);

    
    loader.classList.remove("visible");
    loader.classList.add("hidden");

    if (!domainResponse.ok || !dynamicResponse.ok || !localResponse.ok) {
      throw new Error("Один или несколько запросов к API завершились с ошибкой");
    }

    const domainData = await domainResponse.json();
    const dynamicData = await dynamicResponse.json();
    const localData = await localResponse.json();

    document.getElementById("original-url").textContent = domainData.original_url || urlInput;

    const googleList = document.getElementById("google-list");
    const dynamicList = document.getElementById("dynamic-list");
    const localList = document.getElementById("local-list");

    googleList.innerHTML = "";
    dynamicList.innerHTML = "";
    localList.innerHTML = "";

    const googlePhish = domainData.domain_status;
    const dynamicPhish = dynamicData.phishing;
    const localPhish = localData.domain_status;

    
    
    document.getElementById("dynamic").className = "column " + (dynamicPhish ? "phish" : "safe");
    

    

    
    if (domainData.scannig_results && domainData.scannig_results.length > 0) {
      domainData.scannig_results.forEach((item, index) => {
        googleList.innerHTML += `<li>Проверка ${index + 1}: ${item.phishing ? "Фишинг" : "ОК"}</li>`;
        document.getElementById("google").className = "column " + (item.phishing ? "phish" : "safe");
        is_phish = item.phishing
      });
    } else {
      googleList.innerHTML = `<li>Проверка: ${googlePhish ? "Фишинг" : "ОК"}</li>`;
    }

    
    dynamicList.innerHTML += `<li>Результат: ${dynamicData.phishing ? "Фишинг" : "ОК"} (Оценка: ${dynamicData.score})</li>`;
    
    
    
    if (localData.scannig_results && localData.scannig_results.length > 0) {
      
      localData.scannig_results.forEach((item) => {
        if (typeof item === 'object' && item !== null && typeof item.details === 'string') {
          localList.innerHTML += `<li>${item.phishing ? "Фишинг" : "ОК"}</li>`; 
          document.getElementById("local").className = "column " + (item.phishing ? "phish" : "safe");
          is_phish = item.phishing
        } else {
          localList.innerHTML += `<li>Обнаружено совпадение: ${JSON.stringify(item)}</li>`;
        }
      });
    } else {
      
      localList.innerHTML = '<li>В локальной базе не обнаружен.</li>';
    }

    
    const isPhishingOverall = dynamicPhish || is_phish;
    const domainStatus = document.getElementById("domain-status");
    domainStatus.textContent = isPhishingOverall ? "Опасный домен" : "Домен безопасен";
    domainStatus.className = "status " + (isPhishingOverall ? "bad" : "ok");

    detailsContent.textContent = JSON.stringify({
      google_domain_check: domainData,
      dynamic_check: dynamicData,
      local_check: localData
    }, null, 2);

    detailsBtn.classList.remove("hidden");
    resultDiv.classList.remove("hidden");

  } catch (e) {
    loader.classList.remove("visible");
    loader.classList.add("hidden");
    
    console.error(e);
    errorDiv.textContent = "Ошибка при обращении к API: " + e.message;
    errorDiv.classList.remove("hidden");
    resultDiv.classList.add("hidden");
  }
});

document.getElementById("details-btn").addEventListener("click", () => {
  const section = document.getElementById("details-section");
  section.classList.toggle("hidden");
});