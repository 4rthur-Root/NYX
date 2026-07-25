document.addEventListener('DOMContentLoaded', () => {
    const form = document.querySelector('.filters form');
    if (!form) return;

    const selects = form.querySelectorAll('select');
    selects.forEach(select => {
        select.addEventListener('change', () => {
            form.submit();
        });
    });
});
