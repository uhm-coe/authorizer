/**
 * Small style tweaks for login form, and show a counter if user triggered login
 * protections (too many failed attempts).
 */

/* global document */
/* eslint-env browser */
( function( $ ) {

	$( document ).ready( function() {
		// Move any external service buttons into top of login form.
		var loginform = document.getElementById( 'loginform' );
		var externals = document.getElementById( 'auth-external-service-login' );
		if ( null !== loginform && null !== externals ) {
			loginform.insertBefore( externals, loginform.firstChild );
		}

		// Decrement seconds counter if it exists
		var secondsElement = document.getElementById( 'seconds_remaining' );
		if ( null !== secondsElement ) {
			var secondsInterval = setInterval( function() {
				var seconds = secondsElement.getAttribute( 'data-seconds' );
				if ( 1 > seconds ) {
					clearInterval( secondsInterval );
					return;
				}
				seconds = parseInt( seconds, 10 ) - 1;
				secondsElement.innerHTML = secondsAsSentence( seconds );
				secondsElement.setAttribute( 'data-seconds', seconds );
			}, 1000 );
		}
	});

	function secondsAsSentence( seconds ) {
		var units = {
			week: 3600 * 24 * 7,
			day: 3600 * 24,
			hour: 3600,
			minute: 60,
			second: 1,
		};

		// specifically handle zero
		if ( 0 === seconds ) {
			return '0 seconds';
		}

		// Construct sentence, e.g., '1 week, 2 hours, 5 minutes, 10 seconds, '
		var phrase = '';
		for ( var name in units ) {
			if ( units.hasOwnProperty( name ) ) {
				var divisor = units[name];
				var quot = Math.floor( seconds / divisor );
				if ( quot ) {
					phrase += quot + ' ' + name;
					if ( 1 < Math.abs( quot ) ) {
						phrase += 's';
					}
					phrase += ', ';
					seconds -= quot * divisor;
				}
			}
		}

		return phrase.substring( 0, phrase.length - 2 ); // trim off last ', '
	}

} )( jQuery );
