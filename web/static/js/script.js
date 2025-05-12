let sidebar = document.querySelector(".sidebar");
let sidebarBtn = document.querySelector(".sidebarBtn");
let logoName = document.querySelector(".logo_name");

sidebarBtn.onclick = function() {
  sidebar.classList.toggle("active");
  if(sidebar.classList.contains("active")){
    sidebarBtn.classList.replace("bx-menu" ,"bx-menu-alt-right");
    logoName.style.display = "none"; // Ocultar el texto
    console.log("Ocultar texto");
  } else {
    sidebarBtn.classList.replace("bx-menu-alt-right", "bx-menu");
    logoName.style.display = "inline"; // Mostrar el texto
    console.log("Mostrar texto");
  }
}
