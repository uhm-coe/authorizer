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
class Login_Form extends Singleton {

	/**
	 * Load script to display message to anonymous users browing a site (only
	 * enqueue if configured to only allow logged in users to view the site and
	 * show a warning to anonymous users).
	 *
	 * Action: wp_enqueue_scripts
	 */
	public function auth_public_scripts() {
		// Load (and localize) public scripts.
		$options = Options::get_instance();
		if (
			'logged_in_users' === $options->get( 'access_who_can_view' ) &&
			'warning' === $options->get( 'access_public_warning' ) &&
			get_option( 'auth_settings_advanced_public_notice' )
		) {
			$current_path = ! empty( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : home_url();
			wp_enqueue_script( 'auth_public_scripts', plugins_url( '/js/authorizer-public.js', plugin_root() ), array( 'jquery' ), '3.2.2', false );
			$auth_localized = array(
				'wpLoginUrl'      => wp_login_url( $current_path ),
				'anonymousNotice' => $options->get( 'access_redirect_to_message' ),
				'logIn'           => esc_html__( 'Log In', 'authorizer' ),
			);
			wp_localize_script( 'auth_public_scripts', 'auth', $auth_localized );
		}
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
		wp_register_style( 'authorizer-login-css', plugins_url( '/css/authorizer-login.css', plugin_root() ), array(), '3.2.0' );
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
<script>
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
function signInCallback( credentialResponse ) { // jshint ignore:line
	var $ = jQuery;

	if ( credentialResponse.hasOwnProperty( 'credential' ) ) {
		// Send the JWT to the server
		var ajaxurl = '<?php echo esc_attr( $ajaxurl ); ?>';
		$.post(ajaxurl, {
			action: 'process_google_login',
			credential: credentialResponse.credential,
			nonce: $('#g_id_onload' ).data( 'nonce' ),
		}, function() {
			// Reload wp-login.php to continue the authentication process.
			var newHref = authUpdateQuerystringParam( location.href, 'external', 'google' );

			// If we have a login form embedded via [authorizer_login_form], we are
			// not on wp-login.php, so change the location to wp-login.php.
			if ( 'undefined' !== typeof auth && auth.hasOwnProperty( 'wpLoginUrl' ) ) {
				newHref = authUpdateQuerystringParam( auth.wpLoginUrl, 'external', 'google' );
			}

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
		// console.log('Sign-in state: ' + credentialResponse['error']);

		// If user denies access, reload the login page.
		if ( credentialResponse.error === 'access_denied' || credentialResponse.error === 'user_signed_out' ) {
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
				<script src="https://accounts.google.com/gsi/client" async defer></script>
				<div id="g_id_onload"
					data-use_fedcm_for_prompt="true"
					data-client_id="<?php echo esc_attr( trim( $auth_settings['google_clientid'] ) ); ?>"
					data-context="signin"
					data-ux_mode="popup"
					data-nonce="<?php echo esc_attr( wp_create_nonce( 'google_csrf_nonce' ) ); ?>"
					data-callback="signInCallback">
				</div>
				<div class="g_id_signin"
					data-type="standard"
					data-shape="pill"
					data-theme="filled_blue"
					data-text="signin_with"
					data-size="large"
					data-logo_alignment="left"
					data-width="270">
				</div>
				<br>
			<?php endif; ?>

			<?php if ( '1' === $auth_settings['oauth2'] ) : ?>
				<p><a class="button button-primary button-external button-<?php echo esc_attr( $auth_settings['oauth2_provider'] ); ?>" href="<?php echo esc_attr( Helper::modify_current_url_for_external_login( 'oauth2' ) ); ?>">
					<span class="dashicons dashicons-lock"></span>
					<span class="label">
						<?php
						echo esc_html(
							sprintf(
								/* TRANSLATORS: %s: Custom OAuth2 label from authorizer options */
								__( 'Sign in with %s', 'authorizer' ),
								$auth_settings['oauth2_custom_label']
							)
						);
						?>
					</span>
				</a></p>
			<?php endif; ?>

			<?php if ( '1' === $auth_settings['cas'] ) : ?>
				<p><a class="button button-primary button-external button-cas" href="<?php echo esc_attr( Helper::modify_current_url_for_external_login( 'cas' ) ); ?>">
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
				<?php
				if ( empty( $auth_settings['cas_num_servers'] ) ) :
					$auth_settings['cas_num_servers'] = 1;
				endif;
				if ( $auth_settings['cas_num_servers'] > 1 ) :
					for ( $i = 2; $i <= $auth_settings['cas_num_servers']; $i++ ) :
						if ( empty( $auth_settings[ 'cas_host_' . $i ] ) ) :
							continue;
						endif;
						?>
						<p><a class="button button-primary button-external button-cas" href="<?php echo esc_attr( Helper::modify_current_url_for_external_login( 'cas', $i ) ); ?>">
							<span class="dashicons dashicons-lock"></span>
							<span class="label">
								<?php
								echo esc_html(
									sprintf(
										/* TRANSLATORS: %s: Custom CAS label from authorizer options */
										__( 'Sign in with %s', 'authorizer' ),
										$auth_settings[ 'cas_custom_label_' . $i ]
									)
								);
								?>
							</span>
						</a></p>
					<?php endfor; ?>
				<?php endif; ?>
			<?php endif; ?>

			<?php if ( ( isset( $auth_settings['advanced_hide_wp_login'] ) && '1' === $auth_settings['advanced_hide_wp_login'] && isset( $_SERVER['QUERY_STRING'] ) && false === strpos( $_SERVER['QUERY_STRING'], 'external=wordpress' ) ) || ( isset( $auth_settings['advanced_disable_wp_login'] ) && '1' === $auth_settings['advanced_disable_wp_login'] && '1' !== $auth_settings['ldap'] && ( '1' === $auth_settings['cas'] || '1' === $auth_settings['google'] ) ) ) : // phpcs:ignore WordPress.Security.ValidatedSanitizedInput ?>
				<style type="text/css">
					body.login-action-login form {
						padding-bottom: 8px;
					}
					body.login-action-login form p > label,
					body.login-action-login form #user_login,
					body.login-action-login form .user-pass-wrap,
					body.login-action-login form .forgetmenot,
					body.login-action-login form .submit,
					body.login-action-login #nav { /* csslint allow: ids */
						display: none;
					}
				</style>
			<?php elseif ( '1' === $auth_settings['cas'] || '1' === $auth_settings['google'] || '1' === $auth_settings['oauth2'] ) : ?>
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
		// If the query string 'checkemail=confirm' is set, we do not want to automatically redirect to
		// the CAS login screen using 'external=cas', and instead want to directly access the check email
		// confirmation page.  So we will instead set the URL parameter 'external=wordpress' and redirect.
		// This is to prevent issues when going through the normal WordPress password reset process.
		if (
			isset( $_REQUEST['checkemail'] ) && // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			'confirm' === $_REQUEST['checkemail'] && // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			isset( $_SERVER['QUERY_STRING'] ) &&
			strpos( $_SERVER['QUERY_STRING'], 'external=wordpress' ) === false // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		) {
					wp_redirect( Helper::modify_current_url_for_external_login( 'wordpress' ) );  // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
					exit;
		}

		// Grab plugin settings.
		$options       = Options::get_instance();
		$auth_settings = $options->get_all( Helper::SINGLE_CONTEXT, 'allow override' );

		// Check whether we should redirect to CAS.
		if (
			isset( $_SERVER['QUERY_STRING'] ) &&
			strpos( $_SERVER['QUERY_STRING'], 'external=wordpress' ) === false && // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			array_key_exists( 'cas_auto_login', $auth_settings ) && in_array( intval( $auth_settings['cas_auto_login'] ), range( 1, 10 ), true ) &&
			array_key_exists( 'cas', $auth_settings ) && '1' === $auth_settings['cas'] &&
			( ! array_key_exists( 'ldap', $auth_settings ) || '1' !== $auth_settings['ldap'] ) &&
			( ! array_key_exists( 'google', $auth_settings ) || '1' !== $auth_settings['google'] ) &&
			( ! array_key_exists( 'oauth2', $auth_settings ) || '1' !== $auth_settings['oauth2'] ) &&
			array_key_exists( 'advanced_hide_wp_login', $auth_settings ) && '1' === $auth_settings['advanced_hide_wp_login']
		) {
			wp_redirect( Helper::modify_current_url_for_external_login( 'cas', intval( $auth_settings['cas_auto_login'] ) ) ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
			exit;
		}

		return $errors;
	}


	/**
	 * Redirect to OAuth2 login when visiting login page (only if option is
	 * enabled, OAuth2 is the only service, and WordPress logins are hidden).
	 * Note: hook into wp_login_errors filter so this fires after the
	 * authenticate hook (where the redirect to OAuth2 happens), but before html
	 * output is started (so the redirect header doesn't complain about data
	 * already being sent).
	 *
	 * Filter: wp_login_errors
	 *
	 * @param  object $errors      WP Error object.
	 * @param  string $redirect_to Where to redirect on error.
	 * @return WP_Error|void       WP Error object or void on redirect.
	 */
	public function wp_login_errors__maybe_redirect_to_oauth2( $errors, $redirect_to ) {
		// If the query string 'checkemail=confirm' is set, we do not want to automatically redirect to
		// the OAuth2 login screen using 'external=oauth2', and instead want to directly access the check email
		// confirmation page.  So we will instead set the URL parameter 'external=wordpress' and redirect.
		// This is to prevent issues when going through the normal WordPress password reset process.
		if (
			isset( $_REQUEST['checkemail'] ) && // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			'confirm' === $_REQUEST['checkemail'] && // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			isset( $_SERVER['QUERY_STRING'] ) &&
			strpos( $_SERVER['QUERY_STRING'], 'external=wordpress' ) === false // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		) {
					wp_redirect( Helper::modify_current_url_for_external_login( 'wordpress' ) );  // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
					exit;
		}

		// Grab plugin settings.
		$options       = Options::get_instance();
		$auth_settings = $options->get_all( Helper::SINGLE_CONTEXT, 'allow override' );

		// Check whether we should redirect to OAuth2.
		if (
			isset( $_SERVER['QUERY_STRING'] ) &&
			strpos( $_SERVER['QUERY_STRING'], 'external=wordpress' ) === false && // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			array_key_exists( 'oauth2_auto_login', $auth_settings ) && '1' === $auth_settings['oauth2_auto_login'] &&
			array_key_exists( 'oauth2', $auth_settings ) && '1' === $auth_settings['oauth2'] &&
			( ! array_key_exists( 'ldap', $auth_settings ) || '1' !== $auth_settings['ldap'] ) &&
			( ! array_key_exists( 'google', $auth_settings ) || '1' !== $auth_settings['google'] ) &&
			( ! array_key_exists( 'cas', $auth_settings ) || '1' !== $auth_settings['cas'] ) &&
			array_key_exists( 'advanced_hide_wp_login', $auth_settings ) && '1' === $auth_settings['advanced_hide_wp_login']
		) {
			wp_redirect( Helper::modify_current_url_for_external_login( 'oauth2' ) ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
			exit;
		}

		return $errors;
	}


	/**
	 * Implements hook: do_action( 'wp_login_failed', $username );
	 * Update the user meta for the user that just failed logging in.
	 * Keep track of time of last failed attempt and number of failed attempts.
	 *
	 * Action: wp_login_failed
	 *
	 * @param  string $username Username or email address.
	 * @return void
	 */
	public function update_login_failed_count( $username ) {
		// Grab plugin settings.
		$options       = Options::get_instance();
		$auth_settings = $options->get_all( Helper::SINGLE_CONTEXT, 'allow override' );

		// Get user trying to log in.
		$user = get_user_by( 'login', $username );

		// If user not found, check if logging in with an email address.
		if ( false === $user ) {
			$user = get_user_by( 'email', $username );
		}

		if ( false !== $user ) {
			$last_attempt = get_user_meta( $user->ID, 'auth_settings_advanced_lockouts_time_last_failed', true );
			$num_attempts = get_user_meta( $user->ID, 'auth_settings_advanced_lockouts_failed_attempts', true );
		} else {
			// If this isn't a real user, update the global failed attempt
			// variables. We'll use these global variables to institute the
			// lockouts on nonexistent accounts. We do this so an attacker
			// won't be able to determine which accounts are real by which
			// accounts get locked out on multiple invalid attempts.
			$last_attempt = get_option( 'auth_settings_advanced_lockouts_time_last_failed' );
			$num_attempts = get_option( 'auth_settings_advanced_lockouts_failed_attempts' );
		}

		// Make sure $last_attempt (time) and $num_attempts are positive integers.
		// Note: this addresses resetting them if either is unset from above.
		$last_attempt = absint( $last_attempt );
		$num_attempts = absint( $num_attempts );

		// Reset the failed attempt count if the time since the last
		// failed attempt is greater than the reset duration.
		$time_since_last_fail = time() - $last_attempt;
		$reset_duration       = absint( $auth_settings['advanced_lockouts']['reset_duration'] ) * 60; // minutes to seconds.
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

		// Log a lockout if we hit the configured limit (via Simple History plugin).
		$lockouts                   = $auth_settings['advanced_lockouts'];
		$num_attempts_short_lockout = absint( $lockouts['attempts_1'] );
		$num_attempts_long_lockout  = absint( $lockouts['attempts_1'] ) + absint( $lockouts['attempts_2'] );
		if ( $num_attempts >= $num_attempts_short_lockout ) {
			$lockout_length_in_seconds = $num_attempts >= $num_attempts_long_lockout ? absint( $lockouts['duration_2'] ) * 60 : absint( $lockouts['duration_1'] ) * 60;

			if ( false !== $user ) {
				/* TRANSLATORS: 1: duration of lockout 2: username 3: ordinal number of invalid attempts */
				$lockout_log_message = __( 'Authorizer lockout triggered for %1$s on user %2$s after the %3$s invalid attempt.', 'authorizer' );
			} else {
				/* TRANSLATORS: 1: duration of lockout 2: username 3: ordinal number of invalid attempts */
				$lockout_log_message = __( 'Authorizer lockout triggered for %1$s on all non-existent user names after the %3$s invalid attempt (triggered by non-existent user name: %2$s).', 'authorizer' );
			}

			apply_filters(
				'simple_history_log_warning',
				sprintf(
					$lockout_log_message,
					Helper::seconds_as_sentence( $lockout_length_in_seconds ),
					$username,
					Helper::ordinal( $num_attempts )
				),
				array(
					'seconds'  => $lockout_length_in_seconds,
					'username' => $username,
					'attempts' => $num_attempts,
				)
			);
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
	 * Ensure that whenever we are on a wp-login.php page for WordPress and there is a log in link, it properly
	 * generates a wp-login.php URL with the additional "wordpress=external" URL parameter.
	 * Only affects the URL if the Hide WordPress Logins option is enabled.
	 *
	 * Filter:  wp_login_url https://developer.wordpress.org/reference/functions/wp_login_url/
	 *
	 * @param  string $login_url URL for the log in page.
	 * @return string            URL for the log in page.
	 */
	public function maybe_add_external_wordpress_to_log_in_links( $login_url ) {
		// Initial check to make sure that we are on a wp-login.php page.
		if ( isset( $GLOBALS['pagenow'] ) && site_url( $GLOBALS['pagenow'], 'login' ) === $login_url ) {
			// Do a check in here within the $_REQUEST params to narrow down the scope of where we'll modify the URL
			// We need to check against the following:  action=lostpassword, checkemail=confirm, action=rp, and action=resetpass.
			if (
				(
					isset( $_REQUEST['action'] ) && // phpcs:ignore WordPress.Security.NonceVerification.Recommended
					(
						'lostpassword' === $_REQUEST['action'] || // phpcs:ignore WordPress.Security.NonceVerification.Recommended
						'rp' === $_REQUEST['action'] || // phpcs:ignore WordPress.Security.NonceVerification.Recommended
						'resetpass' === $_REQUEST['action'] // phpcs:ignore WordPress.Security.NonceVerification.Recommended
					)
				) || (
					isset( $_REQUEST['checkemail'] ) && // phpcs:ignore WordPress.Security.NonceVerification.Recommended
					'confirm' === $_REQUEST['checkemail'] // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				)
			) {
				// Grab plugins settings.
				$options       = Options::get_instance();
				$auth_settings = $options->get_all( HELPER::SINGLE_CONTEXT, 'allow override' );

				// Only change the Log in URL if the Hide WordPress Logins option is enabled in Authorizer.
				if (
					array_key_exists( 'advanced_hide_wp_login', $auth_settings ) &&
					'1' === $auth_settings['advanced_hide_wp_login']
				) {
					// Need to determine if existing URL has params already or not, then add the param and value.
					if ( strpos( $login_url, '?' ) === false ) {
						$login_url = $login_url . '?external=wordpress';
					} else {
						$login_url = $login_url . '&external=wordpress';
					}
				}
			}
		}
		return $login_url;
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


	/**
	 * Render the [authorizer_login_form] shortcode.
	 *
	 * Shortcode: authorizer_login_form
	 */
	public function shortcode_authorizer_login_form() {
		ob_start();

		$this->login_enqueue_scripts_and_styles();
		$this->login_form_add_external_service_links();
		$this->load_login_footer_js();

		wp_login_form();

		return ob_get_clean();
	}

	/**
	 * Hide "Lost your password?" link if WordPress logins are disabled and at
	 * least one external service is enabled. Note: don't hide the link if LDAP
	 * logins are enabled and a custom lost password URL is provided.
	 *
	 * Filter: lost_password_html_link
	 */
	public function maybe_hide_lost_password_link( $html_link ) {
		// Grab plugin settings.
		$options       = Options::get_instance();
		$auth_settings = $options->get_all( Helper::SINGLE_CONTEXT, 'allow override' );

		if (
			array_key_exists( 'advanced_disable_wp_login', $auth_settings ) &&
			'1' === $auth_settings['advanced_disable_wp_login'] &&
			(
				'1' === $auth_settings['cas'] ||
				'1' === $auth_settings['oauth2'] ||
				'1' === $auth_settings['google'] ||
				'1' === $auth_settings['ldap']
			) && ! (
				'1' === $auth_settings['ldap'] &&
				array_key_exists( 'ldap_lostpassword_url', $auth_settings ) &&
				strlen( $auth_settings['ldap_lostpassword_url'] ) > 0
			)
		) {
			$html_link = '';
		}

		return $html_link;
	}


	/**
	 * Disable password reset form if WordPress logins are disabled and at least
	 * one external service is enabled.
	 *
	 * Action: lost_password
	 */
	public function maybe_hide_lost_password_form( $errors ) {
		// Grab plugin settings.
		$options       = Options::get_instance();
		$auth_settings = $options->get_all( Helper::SINGLE_CONTEXT, 'allow override' );

		if (
			array_key_exists( 'advanced_disable_wp_login', $auth_settings ) &&
			'1' === $auth_settings['advanced_disable_wp_login'] &&
			(
				'1' === $auth_settings['cas'] ||
				'1' === $auth_settings['oauth2'] ||
				'1' === $auth_settings['google'] ||
				'1' === $auth_settings['ldap']
			)
		) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}
	}

	/**
	 * Ensure password retrieval emails are prevented from being sent if WordPress
	 * logins are disabled and at least one external service is enabled.
	 *
	 * Filter: lostpassword_errors
	 */
	public function maybe_prevent_password_reset( $errors ) {
		// Grab plugin settings.
		$options       = Options::get_instance();
		$auth_settings = $options->get_all( Helper::SINGLE_CONTEXT, 'allow override' );

		if (
			is_wp_error( $errors ) && ! $errors->has_errors() &&
			array_key_exists( 'advanced_disable_wp_login', $auth_settings ) &&
			'1' === $auth_settings['advanced_disable_wp_login'] &&
			(
				'1' === $auth_settings['cas'] ||
				'1' === $auth_settings['oauth2'] ||
				'1' === $auth_settings['google'] ||
				'1' === $auth_settings['ldap']
			)
		) {
			$errors->add( 'logins_disabled', __( '<strong>ERROR</strong>: The username field is empty.' ) );
		}

		return $errors;
	}
}
