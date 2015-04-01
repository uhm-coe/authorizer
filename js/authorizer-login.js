jQuery( document ).ready( function( $ ) {
	// Move any external service buttons into top of login form.
	var loginform = document.getElementById( 'loginform' );
	var externals = document.getElementById( 'auth-external-service-login' );
	loginform.insertBefore( externals, loginform.firstChild );

	// Decrement seconds counter if it exists
	var seconds_element = document.getElementById( 'seconds_remaining' );
	if ( seconds_element !== null ) {
		var seconds_interval = setInterval( function() {
			var seconds = seconds_element.getAttribute( 'data-seconds' );
			if ( seconds < 1 ) {
				clearInterval( 'seconds_interval' );
				return;
			}
			seconds = parseInt( seconds ) - 1;
			seconds_element.innerHTML = seconds_as_sentence( seconds );
			seconds_element.setAttribute( 'data-seconds', seconds );
		}, 1000 );
	}
});

function seconds_as_sentence( seconds ) {
	var units = {
		week   : 7 * 24 * 3600,
		day    :     24 * 3600,
		hour   :          3600,
		minute :            60,
		second :             1
	};

	// specifically handle zero
	if ( seconds === 0 ) {
		return '0 seconds';
	}

	// Construct sentence, e.g., '1 week, 2 hours, 5 minutes, 10 seconds, '
	var s = '';
	for ( var name in units ) {
		var divisor = units[name];
		var quot = Math.floor( seconds / divisor );
		if ( quot ) {
			s += quot + ' ' + name;
			if ( Math.abs( quot ) > 1 ) {
				s += 's';
			}
			s += ', ';
			seconds -= quot * divisor;
		}
	}

	return s.substring( 0, s.length - 2 ); // trim off last ', '
}
