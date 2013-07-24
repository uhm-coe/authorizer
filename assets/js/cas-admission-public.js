jQuery(document).ready(function($) {
  cas.wp_login_url = typeof cas.wp_login_url !== 'undefined' ? cas.wp_login_url : '/wp-login.php';
  cas.public_warning = typeof cas.public_warning !== 'undefined' ? cas.public_warning : false;
  if (cas.public_warning) {
		$('#main').prepend('<div id="alert" class="alert alert-info cas-alert"><button type="button" class="close" data-dismiss="alert">&times;</button><strong>Notice</strong>: You are browsing this site anonymously, and only have access to a portion of its content. Please <a href="' + cas.wp_login_url + '">log in</a> in order to access all the materials.</div>')
	}
});
