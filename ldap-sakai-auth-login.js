/* Modify wp-login.php to reflect UH logins */

// Text/Selection range functions to set cursor position
//http://stackoverflow.com/questions/499126/jquery-set-cursor-position-in-text-area
function setSelectionRange(input, selectionStart, selectionEnd) {
  if (input.setSelectionRange) {
    input.focus();
    input.setSelectionRange(selectionStart, selectionEnd);
  }
  else if (input.createTextRange) {
    var range = input.createTextRange();
    range.collapse(true);
    range.moveEnd('character', selectionEnd);
    range.moveStart('character', selectionStart);
    range.select();
  }
}
function setCaretToPos (input, pos) {
  setSelectionRange(input, pos, pos);
}

// Run function after page load
window.onload = function modifyLoginPage() {
	var formElementChildren = document.getElementById('nav');	
	var formElement = document.getElementById('loginform');
	var userFormElement = document.getElementById('user_login');
	var passFormElement = document.getElementById('user_pass')

	var hasPlaceholder = 'placeholder' in document.createElement('input'); // HTML5 placeholder feature detection
	
	// Move the "Forgot your password?" link into the form
	formElement.appendChild(formElementChildren);
	if ( hasPlaceholder ) {
		userFormElement.setAttribute('placeholder','UH Username');
		passFormElement.setAttribute('placeholder','UH Password');	
		// On focus...	
		userFormElement.onfocus = function() {
		
			// Clear placeholder text
			this.setAttribute('placeholder','');
			this.setAttribute('value','@hawaii.edu');
			this.focus();
			// Set cursor to first position
			setCaretToPos(document.getElementById('user_login'), 0);
			// Add "@hawaii.edu" into value


		
		}
		passFormElement.onfocus = function() {
			// Clear placeholder text
			this.setAttribute('placeholder','');
		}
	} else {
		userFormElement.setAttribute('value','UH Username');
		passFormElement.setAttribute('value','UH Password');
	}
}