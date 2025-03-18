document.addEventListener("DOMContentLoaded", () => {
    const hamburger = document.querySelector(".toggle-btn");
    const toggler = document.querySelector("#icon");
    const sidebar = document.querySelector("#sidebar");

    if (hamburger && toggler && sidebar) {
        hamburger.addEventListener("click", () => {
            sidebar.classList.toggle("expand");
            toggler.classList.toggle("bxs-chevrons-right");
            toggler.classList.toggle("bxs-chevrons-left");
                });
            }
        });