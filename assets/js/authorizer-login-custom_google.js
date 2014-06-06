(function () {
	var po = document.createElement( 'script' );
	po.type = 'text/javascript';
	po.async = true;
	po.src = 'https://plus.google.com/js/client:plusone.js?onload=render';
	var s = document.getElementsByTagName( 'script' )[0];
	s.parentNode.insertBefore( po, s );
})();

/* Executed when the APIs finish loading */
function render() {

	// Additional params including the callback, the rest of the params will
	// come from the page-level configuration.
	var additionalParams = {
		'callback': signInCallback
	};

	// Attach a click listener to a button to trigger the flow.
	var signinButton = document.getElementById( 'googleplus_button' );
	signinButton.addEventListener( 'click', function() {
		gapi.auth.signIn( additionalParams ); // Will use page level configuration
		jQuery( '#login' ).animate({ opacity: 0.2 }).after( '<div id="signin_overlay"><span class="spinner"></span></div>' );
	});
}
