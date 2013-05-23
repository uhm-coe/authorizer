/* Modify wp-login.php to reflect UH logins */

// Text/Selection range functions to set cursor position
// Source: http://stackoverflow.com/questions/2127221/move-cursor-to-the-beginning-of-the-input-field
function setCaretToPos(input, pos) {
	if (input.setSelectionRange) {
		input.setSelectionRange(pos, pos);
	} else if (input.createTextRange) {
		var range = input.createTextRange();
		range.collapse(true);
		range.move('character', pos);
		range.select();
	}
	input.focus();
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
