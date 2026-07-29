document.addEventListener("DOMContentLoaded", () => {
    const slides = Array.from(document.querySelectorAll(".carousel-image"));

    if (slides.length > 1) {
        let activeIndex = 0;

        setInterval(() => {
            slides[activeIndex].classList.remove("active");
            activeIndex = (activeIndex + 1) % slides.length;
            slides[activeIndex].classList.add("active");
        }, 4000);
    }

    if (!document.querySelector(".page-flip-overlay")) {
        const overlay = document.createElement("div");
        overlay.className = "page-flip-overlay";
        document.body.appendChild(overlay);
    }

    const overlay = document.querySelector(".page-flip-overlay");

    document.querySelectorAll('a[href]').forEach((link) => {
        const href = link.getAttribute("href") || "";
        if (!href || href.startsWith("#") || href.startsWith("mailto:") || href.startsWith("tel:")) {
            return;
        }

        const isExternal = /^https?:\/\//i.test(href);
        const isCurrentPageAnchor = href.startsWith("/") && href === window.location.pathname;
        if (isExternal || isCurrentPageAnchor) {
            return;
        }

        link.addEventListener("click", (event) => {
            const targetPath = href.startsWith("/") ? href : new URL(href, window.location.href).pathname;
            if (targetPath === window.location.pathname) {
                return;
            }

            event.preventDefault();
            overlay.classList.add("active");
            setTimeout(() => {
                window.location.href = href;
            }, 350);
        });
    });
});
