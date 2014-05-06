/* Reformat wp-login.php to reflect UH logins */

// Run function after page load (uses domready.js, so make sure that's included first)
domReady(function() {
	if ( 'placeholder' in document.createElement('input') ) {
		document.getElementById( 'user_login' ).setAttribute( 'placeholder', 'Username' );
		document.getElementById( 'user_pass' ).setAttribute( 'placeholder', 'Password' );
	}
});
