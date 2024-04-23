document.addEventListener('DOMContentLoaded', function() {
    const toggleButton = document.getElementById('dropdownToggle');
    const dropdownContent = document.getElementById('dropdownContent');

    toggleButton.addEventListener('click', () => {
        // This toggles the visibility of the dropdown content
        if (dropdownContent.style.display === 'block') {
            dropdownContent.style.display = 'none';
        } else {
            dropdownContent.style.display = 'block';
        }
    });
});
