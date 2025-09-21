// Enhanced client-side validation for user forms
document.addEventListener('DOMContentLoaded', function() {
  const form = document.querySelector('form[action*="/users"]');
  if (!form) return;

  // Real-time validation for name fields
  const nameFields = form.querySelectorAll('input[name*="name"]');
  nameFields.forEach(field => {
    field.addEventListener('input', function() {
      const value = this.value;
      const isValid = /^[a-zA-Z\s\-']*$/.test(value) && value.length <= 64 && !containsDangerousContent(value);
      
      if (value && !isValid) {
        if (!/^[a-zA-Z\s\-']*$/.test(value)) {
          this.setCustomValidity('Name can only contain letters, spaces, hyphens, and apostrophes');
        } else if (containsDangerousContent(value)) {
          this.setCustomValidity('Name contains prohibited content');
        } else {
          this.setCustomValidity('Name must be 64 characters or less');
        }
      } else {
        this.setCustomValidity('');
      }
    });
  });
  
  // Function to check for dangerous content
  function containsDangerousContent(value) {
    const dangerousPatterns = [
      // SQL injection patterns
      /\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b|\bcreate\b|\balter\b|\btable\b|\bdatabase\b/i,
      /\bunion\b|\bwhere\b|\bfrom\b|\binto\b|\bvalues\b|\bset\b|\bhaving\b|\bgroup\b|\border\b|\bby\b/i,
      /\band\b|\bor\b|\bnot\b|\blike\b|\bin\b|\bexists\b|\bbetween\b|\bis\b|\bnull\b/i,
      /\bexec\b|\bexecute\b/i,
      /['"]\s*;/,  // quotes followed by semicolon
      /['"]\s*--/, // quotes followed by SQL comment
      /['"]\s*drop/i, // quotes followed by DROP
      /['"]\s*insert/i, // quotes followed by INSERT
      /['"]\s*update/i, // quotes followed by UPDATE
      /['"]\s*delete/i, // quotes followed by DELETE
      /['"]\s*union/i, // quotes followed by UNION
      /[;]/,     // semicolons
      /--/,      // SQL comments
      /\/\*.*\*\//,  // block comments
      
      // JavaScript/XSS patterns
      /\bscript\b|\bjavascript\b|\bvbscript\b|\bjscript\b/i,
      /\balert\b|\bconfirm\b|\bprompt\b|\bdocument\b|\bwindow\b/i,
      /\blocation\b|\bhref\b|\bsrc\b/i,
      /\bonload\b|\bonerror\b|\bonclick\b|\bonmouseover\b|\bonfocus\b|\bonblur\b/i,
      /\bonchange\b|\bonsubmit\b|\bonreset\b|\bonselect\b|\bonkeydown\b/i,
      /\bonkeyup\b|\bonkeypress\b|\bonmousedown\b|\bonmouseup\b/i,
      /\bonmousemove\b|\bonmouseout\b|\bonmouseenter\b|\bonmouseleave\b/i,
      /\boncontextmenu\b|\bondblclick\b|\bonwheel\b|\bonresize\b/i,
      /\bonscroll\b|\bonbeforeunload\b|\bonunload\b|\bonloadstart\b/i,
      /\bonloadend\b|\bonprogress\b|\bonabort\b|\boncanplay\b/i,
      /\boncanplaythrough\b|\bondurationchange\b|\bonemptied\b/i,
      /\bonended\b|\bonloadeddata\b|\bonloadedmetadata\b/i,
      /\bonpause\b|\bonplay\b|\bonplaying\b|\bonratechange\b/i,
      /\bonseeked\b|\bonseeking\b|\bonstalled\b|\bonsuspend\b/i,
      /\bontimeupdate\b|\bonvolumechange\b|\bonwaiting\b/i,
      /\bexpression\b|\burl\b|\bdata\b|\btext\b|\bhtml\b|\bcss\b|\bstyle\b/i,
      /\biframe\b|\bobject\b|\bembed\b|\bapplet\b|\bform\b/i,
      /\binput\b|\btextarea\b|\bbutton\b|\bselect\b|\boption\b/i,
      /\boptgroup\b|\bfieldset\b|\blegend\b|\blabel\b|\bimg\b/i,
      /\bsvg\b|\bcanvas\b|\baudio\b|\bvideo\b|\bsource\b/i,
      /\btrack\b|\bmap\b|\barea\b|\blink\b|\bmeta\b/i,
      /\btitle\b|\bbase\b|\bhead\b|\bbody\b|\bhtml\b/i,
      /\bdiv\b|\bspan\b|\bp\b|\bh1\b|\bh2\b|\bh3\b|\bh4\b|\bh5\b|\bh6\b/i,
      /\bul\b|\bol\b|\bli\b|\bdl\b|\bdt\b|\bdd\b|\btable\b/i,
      /\btr\b|\btd\b|\bth\b|\bthead\b|\btbody\b|\btfoot\b/i,
      /\bcaption\b|\bcol\b|\bcolgroup\b/i,
      /<script/i,               // <script tag
      /<\/script>/i,            // </script> tag
      /javascript\s*:/i,        // javascript: protocol
      /vbscript\s*:/i,          // vbscript: protocol
      /data\s*:\s*text\s*\/\s*html/i, // data:text/html
      /expression\s*\(/i,       // CSS expression(
      /url\s*\(\s*javascript/i, // url(javascript
      /on\w+\s*=/i,             // Event handlers (onload=, onclick=, etc.)
      /<iframe/i,               // <iframe tag
      /<object/i,               // <object tag
      /<embed/i,                // <embed tag
      /<applet/i,               // <applet tag
      /<form/i,                 // <form tag
      /<input/i,                // <input tag
      /<textarea/i,             // <textarea tag
      /<button/i,               // <button tag
      /<select/i,               // <select tag
      /<img/i,                  // <img tag
      /<svg/i,                  // <svg tag
      /<canvas/i,               // <canvas tag
      /<audio/i,                // <audio tag
      /<video/i,                // <video tag
      /<link/i,                 // <link tag
      /<meta/i,                 // <meta tag
      /<style/i,                // <style tag
      /&#x?[0-9a-f]+;/i,        // HTML entities (hex)
      /&[a-z]+;/i,              // HTML entities (named)
      /\\x[0-9a-f]{2}/i,        // Hex encoding
      /\\u[0-9a-f]{4}/i,        // Unicode encoding
    ];
    
    return dangerousPatterns.some(pattern => pattern.test(value));
  }

  // Real-time email validation
  const emailField = form.querySelector('input[type="email"]');
  if (emailField) {
    emailField.addEventListener('input', function() {
      const value = this.value;
      const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      const isValid = emailRegex.test(value) && value.length <= 64;
      
      if (value && !isValid) {
        this.setCustomValidity('Please enter a valid email address with proper domain (max 64 characters)');
      } else {
        this.setCustomValidity('');
      }
    });
  }


  // Form submission validation
  form.addEventListener('submit', function(e) {
    let isValid = true;
    
    // Check all required fields
    const requiredFields = form.querySelectorAll('[required]');
    requiredFields.forEach(field => {
      if (!field.value.trim()) {
        field.setCustomValidity('This field is required');
        isValid = false;
      }
    });

    if (!isValid) {
      e.preventDefault();
      // Focus on first invalid field
      const firstInvalid = form.querySelector(':invalid');
      if (firstInvalid) {
        firstInvalid.focus();
      }
    }
  });

  // Clear custom validity on focus
  const allInputs = form.querySelectorAll('input');
  allInputs.forEach(input => {
    input.addEventListener('focus', function() {
      this.setCustomValidity('');
    });
  });
});
