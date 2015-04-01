jQuery( document ).ready( function( $ ) {
	auth.wp_login_url = typeof auth.wp_login_url !== 'undefined' ? auth.wp_login_url : '/wp-login.php';
	auth.public_warning = typeof auth.public_warning !== 'undefined' ? auth.public_warning : false;
	if ( auth.public_warning ) {
		$( '#main' ).prepend(' \
			<div id="alert" class="alert alert-info auth-alert"> \
				<button type="button" class="close" data-dismiss="alert">&times;</button> \
				<strong>Notice</strong>: You are browsing this site anonymously, and only have access to a portion of its content. Please <a href="' + auth.wp_login_url + '">log in</a> in order to access all the materials. \
			</div> \
		');
	}
});
