let sidebar = document.querySelector(".sidebar");
let sidebarBtn = document.querySelector(".sidebarBtn");
let logoName = document.querySelector(".logo_name");

// Leer el estado de la cookie al cargar la página
document.addEventListener("DOMContentLoaded", function() {
  let sidebarState = getCookie("sidebarState");
  if (sidebarState === "active") {
    sidebar.classList.add("active");
    sidebarBtn.classList.replace("bx-menu", "bx-menu-alt-right");
    logoName.style.display = "none"; // Ocultar el texto
  } else {
    sidebar.classList.remove("active");
    sidebarBtn.classList.replace("bx-menu-alt-right", "bx-menu");
    logoName.style.display = "inline"; // Mostrar el texto
  }
});

sidebarBtn.onclick = function() {
  sidebar.classList.toggle("active");
  if (sidebar.classList.contains("active")) {
    sidebarBtn.classList.replace("bx-menu", "bx-menu-alt-right");
    logoName.style.display = "none"; // Ocultar el texto
    setCookie("sidebarState", "active", 7); // Guardar estado en cookie
    console.log("Ocultar texto");
  } else {
    sidebarBtn.classList.replace("bx-menu-alt-right", "bx-menu");
    logoName.style.display = "inline"; // Mostrar el texto
    setCookie("sidebarState", "inactive", 7); // Guardar estado en cookie
    console.log("Mostrar texto");
  }
};

// Función para establecer una cookie
function setCookie(name, value, days) {
  let date = new Date();
  date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
  let expires = "expires=" + date.toUTCString();
  document.cookie = name + "=" + value + ";" + expires + ";path=/";
}

// Función para obtener una cookie
function getCookie(name) {
  let decodedCookie = decodeURIComponent(document.cookie);
  let cookies = decodedCookie.split(';');
  name = name + "=";
  for (let i = 0; i < cookies.length; i++) {
    let cookie = cookies[i].trim();
    if (cookie.indexOf(name) === 0) {
      return cookie.substring(name.length, cookie.length);
    }
  }
  return "";
}
