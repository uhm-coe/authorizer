/**
 * Inserts the "Sign in with Google" button.
 */

/* global document, signInCallback, gapi */
( function() {
	var po = document.createElement( 'script' );
	po.async = true;
	po.src = 'https://plus.google.com/js/client:plusone.js?onload=render';
	var scr = document.getElementsByTagName( 'script' )[0];
	scr.parentNode.insertBefore( po, scr );
})();

/* Executed when the APIs finish loading */
// eslint-disable-next-line
function render() { // jshint ignore:line
	// Additional params including the callback, the rest of the params will
	// come from the page-level configuration.
	var additionalParams = {
		callback: signInCallback,
	};
	// Attach a click listener to a button to trigger the flow.
	var signinButton = document.getElementById( 'googleplus_button' );
	signinButton.addEventListener( 'click', function() {
		gapi.auth.signIn( additionalParams ); // Will use page level configuration
		jQuery( '#googleplus_button' ).animate({ opacity: 0.5 });
	});
}
