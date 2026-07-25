document.addEventListener('DOMContentLoaded', () => {
    const currentPath = window.location.pathname;
    document.querySelectorAll('.nav-links a').forEach(link => {
        if (link.getAttribute('href') && currentPath.startsWith(link.getAttribute('href').replace('/metrics', ''))) {
            link.classList.add('active');
        }
    });
});
