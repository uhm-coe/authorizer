/**
 * Displays an alert for anonymous users at the top of pages marked 'public'
 * instructing them to log in. Example alert: "Notice: You are browsing this
 * site anonymously, and only have access to a portion of its content."
 */

/* global document, auth */
( function( $ ) {

	$( document ).ready( function() {
		$( '#main' ).prepend(
			'<div id="alert" class="alert alert-info auth-alert" style="margin: 0 0 20px;">' +
				'<button type="button" class="close" data-dismiss="alert">&times;</button>' +
				auth.anonymousNotice +
				'<a class="button" href="' + auth.wpLoginUrl + '">' + auth.logIn + '</a>' +
			'</div>'
		);
	} );

} )( jQuery );
