/* Reformat wp-login.php to reflect UH logins */

jQuery(document).ready(function($) {
	if ( 'placeholder' in document.createElement('input') ) {
		document.getElementById( 'user_login' ).setAttribute( 'placeholder', 'Username' );
		document.getElementById( 'user_pass' ).setAttribute( 'placeholder', 'Password' );
	}
});
