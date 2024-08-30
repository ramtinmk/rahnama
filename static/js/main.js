document.querySelector('.navbar-toggler').addEventListener('click', function () {
  document.getElementById('sidebar').classList.toggle('active');
});
// script.js

document.getElementById('sidebarToggle').addEventListener('click', function() {
  var sidebar = document.getElementById('sidebar');
  if (sidebar.style.display === "none" || !sidebar.style.display) {
      sidebar.style.display = "block";
  } else {
      sidebar.style.display = "none";
  }
});