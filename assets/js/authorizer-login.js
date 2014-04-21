/* Modify wp-login.php to reflect UH branding */

// Run function after page load
window.onload = function modifyLoginPage() {
	// HTML5 placeholder feature detection
	var hasPlaceholder = 'placeholder' in document.createElement('input');

	var formElementChildren = document.getElementById('nav');	
	var formElement = document.getElementById('loginform');
	var userFormElement = document.getElementById('user_login');
	var passFormElement = document.getElementById('user_pass')

	// Move the "Forgot your password?" link into the form
	formElement.appendChild(formElementChildren);

	if (hasPlaceholder) {
		userFormElement.setAttribute('placeholder', 'WordPress Username');
		passFormElement.setAttribute('placeholder', 'Password');
	} else {
		userFormElement.setAttribute('value','Username');
		passFormElement.setAttribute('value','Password');
	}

	// Focus on username field
	userFormElement.focus();
}
