// Frontend interactivity script
document.addEventListener('DOMContentLoaded', function () {
    // Quick URL filler for local demo page
    const demoFillBtn = document.getElementById('fill-demo-url');
    const urlInput = document.querySelector('input[name="url"]');

    if (demoFillBtn && urlInput) {
        demoFillBtn.addEventListener('click', function () {
            urlInput.value = window.location.origin + '/demo';
        });
    }

    // Toggle details row in tables
    const toggleButtons = document.querySelectorAll('.btn-toggle-detail');
    toggleButtons.forEach(btn => {
        btn.addEventListener('click', function () {
            const targetId = this.getAttribute('data-target');
            const detailRow = document.getElementById(targetId);
            if (detailRow) {
                const isHidden = detailRow.style.display === 'none' || detailRow.style.display === '';
                detailRow.style.display = isHidden ? 'table-row' : 'none';
                this.textContent = isHidden ? 'Hide Details' : 'View Evidence';
            }
        });
    });
});
