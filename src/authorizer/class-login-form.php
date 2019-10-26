<?php
/**
 * Authorizer
 *
 * @license  GPL-2.0+
 * @link     https://github.com/uhm-coe/authorizer
 * @package  authorizer
 */

namespace Authorizer;

use Authorizer\Helper;
use Authorizer\Options;

/**
 * Contains modifications to the WordPress login form.
 */
class Login_Form extends Static_Instance {

	/**
	 * Load external resources for the public-facing site.
	 *
	 * Action: wp_enqueue_scripts
	 */
	public function auth_public_scripts() {
		// Load (and localize) public scripts.
		$options      = Options::get_instance();
		$current_path = ! empty( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : home_url();
		wp_enqueue_script( 'auth_public_scripts', plugins_url( '/js/authorizer-public.js', plugin_root() ), array( 'jquery' ), '2.8.0', false );
		$auth_localized = array(
			'wpLoginUrl'      => wp_login_url( $current_path ),
			'publicWarning'   => get_option( 'auth_settings_advanced_public_notice' ),
			'anonymousNotice' => $options->get( 'access_redirect_to_message' ),
			'logIn'           => esc_html__( 'Log In', 'authorizer' ),
		);
		wp_localize_script( 'auth_public_scripts', 'auth', $auth_localized );

		// Load public css.
		wp_register_style( 'authorizer-public-css', plugins_url( 'css/authorizer-public.css', plugin_root() ), array(), '2.8.0' );
		wp_enqueue_style( 'authorizer-public-css' );
	}


	/**
	 * Enqueue JS scripts and CSS styles appearing on wp-login.php.
	 *
	 * Action: login_enqueue_scripts
	 *
	 * @return void
	 */
	public function login_enqueue_scripts_and_styles() {
		// Grab plugin settings.
		$options       = Options::get_instance();
		$auth_settings = $options->get_all( Helper::SINGLE_CONTEXT, 'allow override' );

		// Enqueue scripts appearing on wp-login.php.
		wp_enqueue_script( 'auth_login_scripts', plugins_url( '/js/authorizer-login.js', plugin_root() ), array( 'jquery' ), '2.8.0', false );

		// Enqueue styles appearing on wp-login.php.
		wp_register_style( 'authorizer-login-css', plugins_url( '/css/authorizer-login.css', plugin_root() ), array(), '2.9.8' );
		wp_enqueue_style( 'authorizer-login-css' );

		/**
		 * Developers can use the `authorizer_add_branding_option` filter
		 * to add a radio button for "Custom WordPress login branding"
		 * under the "Advanced" tab in Authorizer options. Example:
		 * function my_authorizer_add_branding_option( $branding_options ) {
		 *   $new_branding_option = array(
		 *    'value' => 'your_brand'
		 *    'description' => 'Custom Your Brand Login Screen',
		 *    'css_url' => 'http://url/to/your_brand.css',
		 *    'js_url' => 'http://url/to/your_brand.js',
		 *   );
		 *   array_push( $branding_options, $new_branding_option );
		 *   return $branding_options;
		 * }
		 * add_filter( 'authorizer_add_branding_option', 'my_authorizer_add_branding_option' );
		 */
		$branding_options = array();
		$branding_options = apply_filters( 'authorizer_add_branding_option', $branding_options );
		foreach ( $branding_options as $branding_option ) {
			// Make sure the custom brands have the required values.
			if ( ! ( is_array( $branding_option ) && array_key_exists( 'value', $branding_option ) && array_key_exists( 'css_url', $branding_option ) && array_key_exists( 'js_url', $branding_option ) ) ) {
				continue;
			}
			if ( $auth_settings['advanced_branding'] === $branding_option['value'] ) {
				wp_enqueue_script( 'auth_login_custom_scripts-' . sanitize_title( $branding_option['value'] ), $branding_option['js_url'], array( 'jquery' ), '2.8.0', false );
				wp_register_style( 'authorizer-login-custom-css-' . sanitize_title( $branding_option['value'] ), $branding_option['css_url'], array(), '2.8.0' );
				wp_enqueue_style( 'authorizer-login-custom-css-' . sanitize_title( $branding_option['value'] ) );
			}
		}

		// If we're using Google logins, load those resources.
		if ( '1' === $auth_settings['google'] ) {
			wp_enqueue_script( 'authorizer-login-custom-google', plugins_url( '/js/authorizer-login-custom_google.js', plugin_root() ), array( 'jquery' ), '2.8.0', false ); ?>
			<meta name="google-signin-clientid" content="<?php echo esc_attr( $auth_settings['google_clientid'] ); ?>" />
			<meta name="google-signin-scope" content="email" />
			<meta name="google-signin-cookiepolicy" content="single_host_origin" />
			<?php
		}
	}


	/**
	 * Load external resources in the footer of the wp-login.php page.
	 *
	 * Action: login_footer
	 */
	public function load_login_footer_js() {
		// Grab plugin settings.
		$options       = Options::get_instance();
		$auth_settings = $options->get_all( Helper::SINGLE_CONTEXT, 'allow override' );
		$ajaxurl       = admin_url( 'admin-ajax.php' );
		if ( '1' === $auth_settings['google'] ) :
			?>
<script type="text/javascript">
/* global location, window */
// Reload login page if reauth querystring param exists,
// since reauth interrupts external logins (e.g., google).
if ( location.search.indexOf( 'reauth=1' ) >= 0 ) {
	location.href = location.href.replace( 'reauth=1', '' );
}

// eslint-disable-next-line no-implicit-globals
function authUpdateQuerystringParam( uri, key, value ) {
	var re = new RegExp( '([?&])' + key + '=.*?(&|$)', 'i' );
	var separator = uri.indexOf( '?' ) !== -1 ? '&' : '?';
	if ( uri.match( re ) ) {
		return uri.replace( re, '$1' + key + '=' + value + '$2' );
	} else {
		return uri + separator + key + '=' + value;
	}
}

// eslint-disable-next-line
function signInCallback( authResult ) { // jshint ignore:line
	var $ = jQuery;
	if ( authResult.status && authResult.status.signed_in ) {
		// Hide the sign-in button now that the user is authorized, for example:
		$( '#googleplus_button' ).attr( 'style', 'display: none' );

		// Send the code to the server
		var ajaxurl = '<?php echo esc_attr( $ajaxurl ); ?>';
		$.post(ajaxurl, {
			action: 'process_google_login',
			code: authResult.code,
			nonce: $('#nonce_google_auth-<?php echo esc_attr( Helper::get_cookie_value() ); ?>' ).val(),
		}, function() {
			// Handle or verify the server response if necessary.
			// console.log( response );

			// Reload wp-login.php to continue the authentication process.
			var newHref = authUpdateQuerystringParam( location.href, 'external', 'google' );
			if ( location.href === newHref ) {
				location.reload();
			} else {
				location.href = newHref;
			}
		});
	} else {
		// Update the app to reflect a signed out user
		// Possible error values:
		//   "user_signed_out" - User is signed-out
		//   "access_denied" - User denied access to your app
		//   "immediate_failed" - Could not automatically log in the user
		// console.log('Sign-in state: ' + authResult['error']);

		// If user denies access, reload the login page.
		if ( authResult.error === 'access_denied' || authResult.error === 'user_signed_out' ) {
			window.location.reload();
		}
	}
}
</script>
			<?php
		endif;
	}


	/**
	 * Create links for any external authentication services that are enabled.
	 *
	 * Action: login_form
	 */
	public function login_form_add_external_service_links() {
		// Grab plugin settings.
		$options       = Options::get_instance();
		$auth_settings = $options->get_all( Helper::SINGLE_CONTEXT, 'allow override' );
		?>
		<div id="auth-external-service-login">
			<?php if ( '1' === $auth_settings['google'] ) : ?>
				<p><a id="googleplus_button" class="button button-primary button-external button-google"><span class="dashicons dashicons-googleplus"></span><span class="label"><?php esc_html_e( 'Sign in with Google', 'authorizer' ); ?></span></a></p>
				<?php wp_nonce_field( 'google_csrf_nonce', 'nonce_google_auth-' . Helper::get_cookie_value() ); ?>
			<?php endif; ?>

			<?php if ( '1' === $auth_settings['cas'] ) : ?>
				<p><a class="button button-primary button-external button-cas" href="<?php echo esc_attr( Helper::modify_current_url_for_cas_login() ); ?>">
					<span class="dashicons dashicons-lock"></span>
					<span class="label">
						<?php
						echo esc_html(
							sprintf(
								/* TRANSLATORS: %s: Custom CAS label from authorizer options */
								__( 'Sign in with %s', 'authorizer' ),
								$auth_settings['cas_custom_label']
							)
						);
						?>
					</span>
				</a></p>
			<?php endif; ?>

			<?php if ( isset( $auth_settings['advanced_hide_wp_login'] ) && '1' === $auth_settings['advanced_hide_wp_login'] && isset( $_SERVER['QUERY_STRING'] ) && false === strpos( $_SERVER['QUERY_STRING'], 'external=wordpress' ) ) :  // phpcs:ignore WordPress.Security.ValidatedSanitizedInput ?>
				<style type="text/css">
					body.login-action-login form {
						padding-bottom: 8px;
					}
					body.login-action-login form p > label,
					body.login-action-login form .forgetmenot,
					body.login-action-login form .submit,
					body.login-action-login #nav { /* csslint allow: ids */
						display: none;
					}
				</style>
			<?php elseif ( '1' === $auth_settings['cas'] || '1' === $auth_settings['google'] ) : ?>
				<h3> &mdash; <?php esc_html_e( 'or', 'authorizer' ); ?> &mdash; </h3>
			<?php endif; ?>
		</div>
		<?php
	}


	/**
	 * Redirect to CAS login when visiting login page (only if option is
	 * enabled, CAS is the only service, and WordPress logins are hidden).
	 * Note: hook into wp_login_errors filter so this fires after the
	 * authenticate hook (where the redirect to CAS happens), but before html
	 * output is started (so the redirect header doesn't complain about data
	 * already being sent).
	 *
	 * Filter: wp_login_errors
	 *
	 * @param  object $errors      WP Error object.
	 * @param  string $redirect_to Where to redirect on error.
	 * @return WP_Error|void       WP Error object or void on redirect.
	 */
	public function wp_login_errors__maybe_redirect_to_cas( $errors, $redirect_to ) {
		// Grab plugin settings.
		$options       = Options::get_instance();
		$auth_settings = $options->get_all( Helper::SINGLE_CONTEXT, 'allow override' );

		// Check whether we should redirect to CAS.
		if (
			isset( $_SERVER['QUERY_STRING'] ) &&
			strpos( $_SERVER['QUERY_STRING'], 'external=wordpress' ) === false && // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			array_key_exists( 'cas_auto_login', $auth_settings ) && '1' === $auth_settings['cas_auto_login'] &&
			array_key_exists( 'cas', $auth_settings ) && '1' === $auth_settings['cas'] &&
			( ! array_key_exists( 'ldap', $auth_settings ) || '1' !== $auth_settings['ldap'] ) &&
			( ! array_key_exists( 'google', $auth_settings ) || '1' !== $auth_settings['google'] ) &&
			array_key_exists( 'advanced_hide_wp_login', $auth_settings ) && '1' === $auth_settings['advanced_hide_wp_login']
		) {
			wp_redirect( Helper::modify_current_url_for_cas_login() ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
			exit;
		}

		return $errors;
	}


	/**
	 * Set a unique cookie to add to Google auth nonce to avoid CSRF detection.
	 * Note: hook into login_init so this fires at the start of the visit to
	 * wp-login.php, but before any html output is started (so setting the
	 * cookie header doesn't complain about data already being sent).
	 *
	 * Action: login_init
	 *
	 * @return void
	 */
	public function login_init__maybe_set_google_nonce_cookie() {
		// Grab plugin settings.
		$options       = Options::get_instance();
		$auth_settings = $options->get_all( Helper::SINGLE_CONTEXT, 'allow override' );

		// If Google logins are enabled, make sure the cookie is set.
		if ( array_key_exists( 'google', $auth_settings ) && '1' === $auth_settings['google'] ) {
			if ( ! isset( $_COOKIE['login_unique'] ) ) {
				setcookie( 'login_unique', Helper::get_cookie_value(), time() + 1800, '/', defined( 'COOKIE_DOMAIN' ) ? COOKIE_DOMAIN : '' );
				$_COOKIE['login_unique'] = Helper::get_cookie_value();
			}
		}
	}


	/**
	 * Implements hook: do_action( 'wp_login_failed', $username );
	 * Update the user meta for the user that just failed logging in.
	 * Keep track of time of last failed attempt and number of failed attempts.
	 *
	 * Action: wp_login_failed
	 *
	 * @param  string $username Username to update login count for.
	 * @return void
	 */
	public function update_login_failed_count( $username ) {
		// Grab plugin settings.
		$options       = Options::get_instance();
		$auth_settings = $options->get_all( Helper::SINGLE_CONTEXT, 'allow override' );

		// Get user trying to log in.
		// If this isn't a real user, update the global failed attempt
		// variables. We'll use these global variables to institute the
		// lockouts on nonexistent accounts. We do this so an attacker
		// won't be able to determine which accounts are real by which
		// accounts get locked out on multiple invalid attempts.
		$user = get_user_by( 'login', $username );

		if ( false !== $user ) {
			$last_attempt = get_user_meta( $user->ID, 'auth_settings_advanced_lockouts_time_last_failed', true );
			$num_attempts = get_user_meta( $user->ID, 'auth_settings_advanced_lockouts_failed_attempts', true );
		} else {
			$last_attempt = get_option( 'auth_settings_advanced_lockouts_time_last_failed' );
			$num_attempts = get_option( 'auth_settings_advanced_lockouts_failed_attempts' );
		}

		// Make sure $last_attempt (time) and $num_attempts are positive integers.
		// Note: this addresses resetting them if either is unset from above.
		$last_attempt = abs( intval( $last_attempt ) );
		$num_attempts = abs( intval( $num_attempts ) );

		// Reset the failed attempt count if the time since the last
		// failed attempt is greater than the reset duration.
		$time_since_last_fail = time() - $last_attempt;
		$reset_duration       = $auth_settings['advanced_lockouts']['reset_duration'] * 60; // minutes to seconds.
		if ( $time_since_last_fail > $reset_duration ) {
			$num_attempts = 0;
		}

		// Set last failed time to now and increment last failed count.
		if ( false !== $user ) {
			update_user_meta( $user->ID, 'auth_settings_advanced_lockouts_time_last_failed', time() );
			update_user_meta( $user->ID, 'auth_settings_advanced_lockouts_failed_attempts', $num_attempts + 1 );
		} else {
			update_option( 'auth_settings_advanced_lockouts_time_last_failed', time() );
			update_option( 'auth_settings_advanced_lockouts_failed_attempts', $num_attempts + 1 );
		}
	}


	/**
	 * Overwrite the URL for the lost password link on the login form.
	 * If we're authenticating against an external service, standard
	 * WordPress password resets won't work.
	 *
	 * Filter: lostpassword_url
	 *
	 * @param  string $lostpassword_url URL to reset password.
	 * @return string                   URL to reset password.
	 */
	public function custom_lostpassword_url( $lostpassword_url ) {
		// Grab plugin settings.
		$options       = Options::get_instance();
		$auth_settings = $options->get_all( Helper::SINGLE_CONTEXT, 'allow override' );

		if (
			array_key_exists( 'ldap_lostpassword_url', $auth_settings ) &&
			filter_var( $auth_settings['ldap_lostpassword_url'], FILTER_VALIDATE_URL )
		) {
			$lostpassword_url = $auth_settings['ldap_lostpassword_url'];
		}
		return $lostpassword_url;
	}


	/**
	 * Add custom error message to login screen.
	 *
	 * Filter: login_errors
	 *
	 * @param  string $errors Error description.
	 * @return string         Error description with Authorizer errors added.
	 */
	public function show_advanced_login_error( $errors ) {
		$error = get_option( 'auth_settings_advanced_login_error' );
		delete_option( 'auth_settings_advanced_login_error' );
		$errors = '    ' . $error . "<br />\n";
		return $errors;
	}

}
