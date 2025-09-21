// Enhanced client-side validation for user forms
document.addEventListener('DOMContentLoaded', function() {
  const form = document.querySelector('form[action*="/users"]');
  if (!form) return;

  // Real-time validation for name fields
  const nameFields = form.querySelectorAll('input[name*="name"]');
  nameFields.forEach(field => {
    field.addEventListener('input', function() {
      const value = this.value;
      const isValid = /^[a-zA-Z\s]*$/.test(value) && value.length <= 64;
      
      if (value && !isValid) {
        this.setCustomValidity('Name can only contain letters and spaces (max 64 characters)');
      } else {
        this.setCustomValidity('');
      }
    });
  });

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
