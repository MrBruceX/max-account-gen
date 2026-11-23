// devtools-off.js — MAX SHOP
// Blocks keyboard shortcuts and right-click only.
(function () {
  'use strict';

  document.addEventListener('keydown', function (e) {
    if (e.key === 'F12' || e.keyCode === 123) {
      e.preventDefault(); e.stopPropagation(); return false;
    }
    if ((e.ctrlKey || e.metaKey) && e.shiftKey &&
        ['I','J','C','K'].includes(e.key.toUpperCase())) {
      e.preventDefault(); e.stopPropagation(); return false;
    }
    if (e.metaKey && e.altKey && e.key.toUpperCase() === 'I') {
      e.preventDefault(); e.stopPropagation(); return false;
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toUpperCase() === 'U') {
      e.preventDefault(); e.stopPropagation(); return false;
    }
  }, true);

  document.addEventListener('contextmenu', function (e) {
    e.preventDefault(); e.stopPropagation(); return false;
  }, true);

})();