<?php
/**
 * Plugin Name: Authorizer
 * Description: Authorizer limits login attempts, restricts access to specified users, and authenticates against external sources (e.g., Google, LDAP, or CAS).
 * Author: Paul Ryan <prar@hawaii.edu>
 * Plugin URI: https://github.com/uhm-coe/authorizer
 * Text Domain: authorizer
 * Domain Path: /languages
 * License: GPL2
 * Version: 2.8.6
 *
 * @package authorizer
 */

/**
 * Portions forked from Restricted Site Access plugin: http://wordpress.org/plugins/restricted-site-access/
 * Portions forked from wpCAS plugin: http://wordpress.org/extend/plugins/cas-authentication/
 * Portions forked from Limit Login Attempts: http://wordpress.org/plugins/limit-login-attempts/
 */

/**
 * Add phpCAS library if it's not included.
 *
 * @see https://wiki.jasig.org/display/CASC/phpCAS+installation+guide
 */
if ( ! defined( 'PHPCAS_VERSION' ) ) {
	require_once dirname( __FILE__ ) . '/vendor/phpCAS-1.3.6/CAS.php';
}


if ( ! class_exists( 'WP_Plugin_Authorizer' ) ) {
	/**
	 * Define class for plugin: Authorizer.
	 *
	 * @category Authentication
	 * @package  Authorizer
	 * @author   Paul Ryan <prar@hawaii.edu>
	 * @license  http://www.gnu.org/licenses/gpl-2.0.html GPL2
	 * @link     http://hawaii.edu/coe/dcdc/wordpress/authorizer/doc/
	 */
	class WP_Plugin_Authorizer {

		/**
		 * Constants for determining our admin context (network or individual site).
		 */
		const NETWORK_CONTEXT = 'multisite_admin';
		const SINGLE_CONTEXT  = 'single_admin';

		/**
		 * Current site ID (Multisite).
		 *
		 * @var string
		 */
		public $current_site_blog_id = 1;

		/**
		 * HTML allowed when rendering translatable strings in the Authorizer UI.
		 * This is passed to wp_kses() when sanitizing HMTL strings.
		 *
		 * @var array
		 */
		private $allowed_html = array(
			'a'      => array(
				'class'  => array(),
				'href'   => array(),
				'style'  => array(),
				'target' => array(),
				'title'  => array(),
			),
			'b'      => array(),
			'br'     => array(),
			'div'    => array(
				'class' => array(),
			),
			'em'     => array(),
			'hr'     => array(),
			'i'      => array(),
			'input'  => array(
				'aria-describedby' => array(),
				'class'            => array(),
				'id'               => array(),
				'name'             => array(),
				'size'             => array(),
				'type'             => array(),
				'value'            => array(),
			),
			'label'  => array(
				'class' => array(),
				'for'   => array(),
			),
			'p'      => array(
				'style' => array(),
			),
			'span'   => array(
				'aria-hidden' => array(),
				'class'       => array(),
				'id'          => array(),
				'style'       => array(),
			),
			'strong' => array(),
		);

		/**
		 * Constructor.
		 */
		public function __construct() {
			// Save reference to current blog id in the network (support deprecated
			// constant BLOGID_CURRENT_SITE).
			if ( defined( 'BLOG_ID_CURRENT_SITE' ) ) {
				$this->current_site_blog_id = BLOG_ID_CURRENT_SITE;
			} elseif ( defined( 'BLOGID_CURRENT_SITE' ) ) { // deprecated.
				$this->current_site_blog_id = BLOGID_CURRENT_SITE;
			}

			// Installation and uninstallation hooks.
			register_activation_hook( __FILE__, array( $this, 'activate' ) );
			register_deactivation_hook( __FILE__, array( $this, 'deactivate' ) );

			/**
			 * Register filters.
			 */

			// Custom wp authentication routine using external service.
			add_filter( 'authenticate', array( $this, 'custom_authenticate' ), 1, 3 );

			// Custom logout action using external service.
			add_action( 'wp_logout', array( $this, 'custom_logout' ) );

			// Create settings link on Plugins page.
			add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), array( $this, 'plugin_settings_link' ) );
			add_filter( 'network_admin_plugin_action_links_' . plugin_basename( __FILE__ ), array( $this, 'network_admin_plugin_settings_link' ) );

			// Modify login page with a custom password url (if option is set).
			add_filter( 'lostpassword_url', array( $this, 'custom_lostpassword_url' ) );

			// If we have a custom login error, add the filter to show it.
			$error = get_option( 'auth_settings_advanced_login_error' );
			if ( $error && strlen( $error ) > 0 ) {
				add_filter( 'login_errors', array( $this, 'show_advanced_login_error' ) );
			}

			/**
			 * Register actions.
			 */

			// Enable localization. Translation files stored in /languages.
			add_action( 'plugins_loaded', array( $this, 'load_textdomain' ) );

			// Perform plugin updates if newer version installed.
			add_action( 'plugins_loaded', array( $this, 'auth_update_check' ) );

			// Update the user meta with this user's failed login attempt.
			add_action( 'wp_login_failed', array( $this, 'update_login_failed_count' ) );

			// Add users who successfully login to the approved list.
			add_action( 'wp_login', array( $this, 'ensure_wordpress_user_in_approved_list_on_login' ), 10, 2 );

			// Create menu item in Settings.
			add_action( 'admin_menu', array( $this, 'add_plugin_page' ) );

			// Create options page.
			add_action( 'admin_init', array( $this, 'page_init' ) );

			// Update user role in approved list if it's changed in the WordPress edit user page.
			add_action( 'user_profile_update_errors', array( $this, 'edit_user_profile_update_role' ), 10, 3 );

			// Update user email in approved list if it's changed in the WordPress edit user page.
			add_filter( 'send_email_change_email', array( $this, 'edit_user_profile_update_email' ), 10, 3 );

			// Enqueue javascript and css on the plugin's options page, the
			// dashboard (for the widget), and the network admin.
			add_action( 'load-settings_page_authorizer', array( $this, 'load_options_page' ) );
			add_action( 'admin_head-index.php', array( $this, 'load_options_page' ) );
			add_action( 'load-toplevel_page_authorizer', array( $this, 'load_options_page' ) );

			// Add custom css and js to wp-login.php.
			add_action( 'login_enqueue_scripts', array( $this, 'login_enqueue_scripts_and_styles' ) );
			add_action( 'login_footer', array( $this, 'load_login_footer_js' ) );

			// Create google nonce cookie when loading wp-login.php if Google is enabled.
			add_action( 'login_init', array( $this, 'login_init__maybe_set_google_nonce_cookie' ) );

			// Modify login page with external auth links (if enabled; e.g., google or cas).
			add_action( 'login_form', array( $this, 'login_form_add_external_service_links' ) );

			// Redirect to CAS login when visiting login page (only if option is
			// enabled, CAS is the only service, and WordPress logins are hidden).
			// Note: hook into wp_login_errors filter so this fires after the
			// authenticate hook (where the redirect to CAS happens), but before html
			// output is started (so the redirect header doesn't complain about data
			// already being sent).
			add_filter( 'wp_login_errors', array( $this, 'wp_login_errors__maybe_redirect_to_cas' ), 10, 2 );

			// Verify current user has access to page they are visiting.
			add_action( 'parse_request', array( $this, 'restrict_access' ), 9 );
			add_action( 'init', array( $this, 'init__maybe_add_network_approved_user' ) );

			// AJAX: Save options from dashboard widget.
			add_action( 'wp_ajax_update_auth_user', array( $this, 'ajax_update_auth_user' ) );

			// AJAX: Save options from multisite options page.
			add_action( 'wp_ajax_save_auth_multisite_settings', array( $this, 'ajax_save_auth_multisite_settings' ) );

			// AJAX: Save usermeta from options page.
			add_action( 'wp_ajax_update_auth_usermeta', array( $this, 'ajax_update_auth_usermeta' ) );

			// AJAX: Verify google login.
			add_action( 'wp_ajax_process_google_login', array( $this, 'ajax_process_google_login' ) );
			add_action( 'wp_ajax_nopriv_process_google_login', array( $this, 'ajax_process_google_login' ) );

			// AJAX: Refresh approved user list.
			add_action( 'wp_ajax_refresh_approved_user_list', array( $this, 'ajax_refresh_approved_user_list' ) );

			// Add dashboard widget so instructors can add/edit users with access.
			// Hint: For Multisite Network Admin Dashboard use wp_network_dashboard_setup instead of wp_dashboard_setup.
			add_action( 'wp_dashboard_setup', array( $this, 'add_dashboard_widgets' ) );

			// If we have a custom admin message, add the action to show it.
			$notice = get_option( 'auth_settings_advanced_admin_notice' );
			if ( $notice && strlen( $notice ) > 0 ) {
				add_action( 'admin_notices', array( $this, 'show_advanced_admin_notice' ) );
				add_action( 'network_admin_notices', array( $this, 'show_advanced_admin_notice' ) );
			}

			// Load custom javascript for the main site (e.g., for displaying alerts).
			add_action( 'wp_enqueue_scripts', array( $this, 'auth_public_scripts' ), 20 );

			// Multisite-specific actions.
			if ( is_multisite() ) {
				// Add network admin options page (global settings for all sites).
				add_action( 'network_admin_menu', array( $this, 'network_admin_menu' ) );
			}

			// Remove user from authorizer lists when that user is deleted in WordPress.
			add_action( 'delete_user', array( $this, 'remove_user_from_authorizer_when_deleted' ) );
			if ( is_multisite() ) {
				// Remove multisite user from authorizer lists when that user is deleted from Network Users.
				add_action( 'remove_user_from_blog', array( $this, 'remove_network_user_from_site_when_removed' ), 10, 2 );
				add_action( 'wpmu_delete_user', array( $this, 'remove_network_user_from_authorizer_when_deleted' ) );
			}

			// Add user to authorizer approved list when that user is added to a blog from the Users screen.
			// Multisite: invite_user action fired when adding (inviting) an existing network user to the current site (with email confirmation).
			add_action( 'invite_user', array( $this, 'add_existing_user_to_authorizer_when_created' ), 10, 3 );
			// Multisite: added_existing_user action fired when adding an existing network user to the current site (without email confirmation).
			add_action( 'added_existing_user', array( $this, 'add_existing_user_to_authorizer_when_created_noconfirmation' ), 10, 2 );
			// Multisite: after_signup_user action fired when adding a new user to the site (with or without email confirmation).
			add_action( 'after_signup_user', array( $this, 'add_new_user_to_authorizer_when_created' ), 10, 4 );
			// Single site: edit_user_created_user action fired when adding a new user to the site (with or without email notification).
			add_action( 'edit_user_created_user', array( $this, 'add_new_user_to_authorizer_when_created_single_site' ), 10, 2 );

			// Add user to network approved users (and remove from individual sites)
			// when user is elevated to super admin status.
			add_action( 'grant_super_admin', array( $this, 'grant_super_admin__add_to_network_approved' ) );
			// Remove user from network approved users (and add them to the approved
			// list on sites they are already on) when super admin status is removed.
			add_action( 'revoke_super_admin', array( $this, 'revoke_super_admin__remove_from_network_approved' ) );

		}


		/**
		 * Plugin activation hook.
		 * Will also activate the plugin for all sites/blogs if this is a "Network enable."
		 *
		 * @return void
		 */
		public function activate( $network_wide ) {
			global $wpdb;

			// If we're in a multisite environment, run the plugin activation for each
			// site when network enabling.
			// Note: wp-cli does not use nonces, so we skip the nonce check here to
			// allow the "wp plugin activate authorizer" command.
			// phpcs:ignore WordPress.CSRF.NonceVerification.NoNonceVerification
			if ( is_multisite() && $network_wide ) {

				// Add super admins to the multisite approved list.
				$auth_multisite_settings_access_users_approved               = get_blog_option( $this->current_site_blog_id, 'auth_multisite_settings_access_users_approved', array() );
				$should_update_auth_multisite_settings_access_users_approved = false;
				foreach ( get_super_admins() as $super_admin ) {
					$user = get_user_by( 'login', $super_admin );
					// Add to approved list if not there.
					if ( ! $this->in_multi_array( $user->user_email, $auth_multisite_settings_access_users_approved ) ) {
						$approved_user = array(
							'email'      => $this->lowercase( $user->user_email ),
							'role'       => count( $user->roles ) > 0 ? $user->roles[0] : 'administrator',
							'date_added' => date( 'M Y', strtotime( $user->user_registered ) ),
							'local_user' => true,
						);
						array_push( $auth_multisite_settings_access_users_approved, $approved_user );
						$should_update_auth_multisite_settings_access_users_approved = true;
					}
				}
				if ( $should_update_auth_multisite_settings_access_users_approved ) {
					update_blog_option( $this->current_site_blog_id, 'auth_multisite_settings_access_users_approved', $auth_multisite_settings_access_users_approved );
				}

				// Run plugin activation on each site in the network.
				$current_blog_id = $wpdb->blogid;
				// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
				$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
				foreach ( $sites as $site ) {
					$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
					switch_to_blog( $blog_id );
					// Set default plugin options and add current users to approved list.
					$this->set_default_options();
					$this->add_wp_users_to_approved_list();
				}
				switch_to_blog( $current_blog_id );

			} else {
				// Set default plugin options and add current users to approved list.
				$this->set_default_options();
				$this->add_wp_users_to_approved_list();
			}

		}


		/**
		 * Adds all WordPress users in the current site to the approved list,
		 * unless they are already in the blocked list. Also removes them
		 * from the pending list if they are there.
		 *
		 * Runs in plugin activation hook.
		 *
		 * @return void
		 */
		private function add_wp_users_to_approved_list() {
			// Add current WordPress users to the approved list.
			$auth_multisite_settings_access_users_approved = is_multisite() ? get_blog_option( $this->current_site_blog_id, 'auth_multisite_settings_access_users_approved', array() ) : array();
			$auth_settings_access_users_pending            = $this->get_plugin_option( 'access_users_pending', WP_Plugin_Authorizer::SINGLE_CONTEXT );
			$auth_settings_access_users_approved           = $this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::SINGLE_CONTEXT );
			$auth_settings_access_users_blocked            = $this->get_plugin_option( 'access_users_blocked', WP_Plugin_Authorizer::SINGLE_CONTEXT );
			$updated                                       = false;
			foreach ( get_users() as $user ) {
				// Skip if user is in blocked list.
				if ( $this->in_multi_array( $user->user_email, $auth_settings_access_users_blocked ) ) {
					continue;
				}
				// Remove from pending list if there.
				foreach ( $auth_settings_access_users_pending as $key => $pending_user ) {
					if ( 0 === strcasecmp( $pending_user['email'], $user->user_email ) ) {
						unset( $auth_settings_access_users_pending[ $key ] );
						$updated = true;
					}
				}
				// Skip if user is in multisite approved list.
				if ( $this->in_multi_array( $user->user_email, $auth_multisite_settings_access_users_approved ) ) {
					continue;
				}
				// Add to approved list if not there.
				if ( ! $this->in_multi_array( $user->user_email, $auth_settings_access_users_approved ) ) {
					$approved_user = array(
						'email'      => $this->lowercase( $user->user_email ),
						'role'       => count( $user->roles ) > 0 ? $user->roles[0] : '',
						'date_added' => date( 'M Y', strtotime( $user->user_registered ) ),
						'local_user' => true,
					);
					array_push( $auth_settings_access_users_approved, $approved_user );
					$updated = true;
				}
			}
			if ( $updated ) {
				update_option( 'auth_settings_access_users_pending', $auth_settings_access_users_pending );
				update_option( 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
			}
		}


		/**
		 * Plugin deactivation.
		 *
		 * @return void
		 */
		public function deactivate() {
			// Do nothing.
		}



		/**
		 * ***************************
		 * External Authentication
		 * ***************************
		 */



		/**
		 * Authenticate against an external service.
		 *
		 * Filter: authenticate
		 *
		 * @param WP_User $user     user to authenticate.
		 * @param string  $username optional username to authenticate.
		 * @param string  $password optional password to authenticate.
		 * @return WP_User|WP_Error WP_User on success, WP_Error on failure.
		 */
		public function custom_authenticate( $user, $username, $password ) {
			// Pass through if already authenticated.
			if ( is_a( $user, 'WP_User' ) ) {
				return $user;
			} else {
				$user = null;
			}

			// If username and password are blank, this isn't a log in attempt.
			$is_login_attempt = strlen( $username ) > 0 && strlen( $password ) > 0;

			// Check to make sure that $username is not locked out due to too
			// many invalid login attempts. If it is, tell the user how much
			// time remains until they can try again.
			$unauthenticated_user            = $is_login_attempt ? get_user_by( 'login', $username ) : false;
			$unauthenticated_user_is_blocked = false;
			if ( $is_login_attempt && false !== $unauthenticated_user ) {
				$last_attempt = get_user_meta( $unauthenticated_user->ID, 'auth_settings_advanced_lockouts_time_last_failed', true );
				$num_attempts = get_user_meta( $unauthenticated_user->ID, 'auth_settings_advanced_lockouts_failed_attempts', true );
				// Also check the auth_blocked user_meta flag (users in blocked list will get this flag).
				$unauthenticated_user_is_blocked = get_user_meta( $unauthenticated_user->ID, 'auth_blocked', true ) === 'yes';
			} else {
				$last_attempt = get_option( 'auth_settings_advanced_lockouts_time_last_failed' );
				$num_attempts = get_option( 'auth_settings_advanced_lockouts_failed_attempts' );
			}

			// Inactive users should be treated like deleted users (we just
			// do this to preserve any content they created, but here we should
			// pretend they don't exist).
			if ( $unauthenticated_user_is_blocked ) {
				remove_filter( 'authenticate', 'wp_authenticate_username_password', 20, 3 );
				return new WP_Error( 'empty_password', __( '<strong>ERROR</strong>: Incorrect username or password.', 'authorizer' ) );
			}

			// Grab plugin settings.
			$auth_settings = $this->get_plugin_options( WP_Plugin_Authorizer::SINGLE_CONTEXT, 'allow override' );

			// Make sure $last_attempt (time) and $num_attempts are positive integers.
			// Note: this addresses resetting them if either is unset from above.
			$last_attempt = abs( intval( $last_attempt ) );
			$num_attempts = abs( intval( $num_attempts ) );

			// Create semantic lockout variables.
			$lockouts                        = $auth_settings['advanced_lockouts'];
			$time_since_last_fail            = time() - $last_attempt;
			$reset_duration                  = $lockouts['reset_duration'] * 60; // minutes to seconds.
			$num_attempts_long_lockout       = $lockouts['attempts_1'] + $lockouts['attempts_2'];
			$num_attempts_short_lockout      = $lockouts['attempts_1'];
			$seconds_remaining_long_lockout  = $lockouts['duration_2'] * 60 - $time_since_last_fail;
			$seconds_remaining_short_lockout = $lockouts['duration_1'] * 60 - $time_since_last_fail;

			// Check if we need to institute a lockout delay.
			if ( $is_login_attempt && $time_since_last_fail > $reset_duration ) {
				// Enough time has passed since the last invalid attempt and
				// now that we can reset the failed attempt count, and let this
				// login attempt go through.
				$num_attempts = 0; // This does nothing, but include it for semantic meaning.
			} elseif ( $is_login_attempt && $num_attempts > $num_attempts_long_lockout && $seconds_remaining_long_lockout > 0 ) {
				// Stronger lockout (1st/2nd round of invalid attempts reached)
				// Note: set the error code to 'empty_password' so it doesn't
				// trigger the wp_login_failed hook, which would continue to
				// increment the failed attempt count.
				remove_filter( 'authenticate', 'wp_authenticate_username_password', 20, 3 );
				return new WP_Error(
					'empty_password',
					sprintf(
						/* TRANSLATORS: 1: username 2: duration of lockout in seconds 3: duration of lockout as a phrase 4: lost password URL */
						__( '<strong>ERROR</strong>: There have been too many invalid login attempts for the username <strong>%1$s</strong>. Please wait <strong id="seconds_remaining" data-seconds="%2$s">%3$s</strong> before trying again. <a href="%4$s" title="Password Lost and Found">Lost your password</a>?', 'authorizer' ),
						$username,
						$seconds_remaining_long_lockout,
						$this->seconds_as_sentence( $seconds_remaining_long_lockout ),
						wp_lostpassword_url()
					)
				);
			} elseif ( $is_login_attempt && $num_attempts > $num_attempts_short_lockout && $seconds_remaining_short_lockout > 0 ) {
				// Normal lockout (1st round of invalid attempts reached)
				// Note: set the error code to 'empty_password' so it doesn't
				// trigger the wp_login_failed hook, which would continue to
				// increment the failed attempt count.
				remove_filter( 'authenticate', 'wp_authenticate_username_password', 20, 3 );
				return new WP_Error(
					'empty_password',
					sprintf(
						/* TRANSLATORS: 1: username 2: duration of lockout in seconds 3: duration of lockout as a phrase 4: lost password URL */
						__( '<strong>ERROR</strong>: There have been too many invalid login attempts for the username <strong>%1$s</strong>. Please wait <strong id="seconds_remaining" data-seconds="%2$s">%3$s</strong> before trying again. <a href="%4$s" title="Password Lost and Found">Lost your password</a>?', 'authorizer' ),
						$username,
						$seconds_remaining_short_lockout,
						$this->seconds_as_sentence( $seconds_remaining_short_lockout ),
						wp_lostpassword_url()
					)
				);
			}

			// Start external authentication.
			$externally_authenticated_emails = array();
			$authenticated_by                = '';
			$result                          = null;

			// Try Google authentication if it's enabled and we don't have a
			// successful login yet.
			if (
				'1' === $auth_settings['google'] &&
				0 === count( $externally_authenticated_emails ) &&
				! is_wp_error( $result )
			) {
				$result = $this->custom_authenticate_google( $auth_settings );
				if ( ! is_null( $result ) && ! is_wp_error( $result ) ) {
					if ( is_array( $result['email'] ) ) {
						$externally_authenticated_emails = $result['email'];
					} else {
						$externally_authenticated_emails[] = $result['email'];
					}
					$authenticated_by = $result['authenticated_by'];
				}
			}

			// Try CAS authentication if it's enabled and we don't have a
			// successful login yet.
			if (
				'1' === $auth_settings['cas'] &&
				0 === count( $externally_authenticated_emails ) &&
				! is_wp_error( $result )
			) {
				$result = $this->custom_authenticate_cas( $auth_settings );
				if ( ! is_null( $result ) && ! is_wp_error( $result ) ) {
					if ( is_array( $result['email'] ) ) {
						$externally_authenticated_emails = $result['email'];
					} else {
						$externally_authenticated_emails[] = $result['email'];
					}
					$authenticated_by = $result['authenticated_by'];
				}
			}

			// Try LDAP authentication if it's enabled and we don't have an
			// authenticated user yet.
			if (
				'1' === $auth_settings['ldap'] &&
				0 === count( $externally_authenticated_emails ) &&
				! is_wp_error( $result )
			) {
				$result = $this->custom_authenticate_ldap( $auth_settings, $username, $password );
				if ( ! is_null( $result ) && ! is_wp_error( $result ) ) {
					if ( is_array( $result['email'] ) ) {
						$externally_authenticated_emails = $result['email'];
					} else {
						$externally_authenticated_emails[] = $result['email'];
					}
					$authenticated_by = $result['authenticated_by'];
				}
			}

			// Skip to WordPress authentication if we don't have an externally
			// authenticated user.
			if ( count( array_filter( $externally_authenticated_emails ) ) < 1 ) {
				return $result;
			}

			// Remove duplicate and blank emails, if any.
			$externally_authenticated_emails = array_filter( array_unique( $externally_authenticated_emails ) );

			/**
			 * If we've made it this far, we should have an externally
			 * authenticated user. The following should be set:
			 *   $externally_authenticated_emails
			 *   $authenticated_by
			 */

			// Get the external user's WordPress account by email address.
			foreach ( $externally_authenticated_emails as $externally_authenticated_email ) {
				$user = get_user_by( 'email', $this->lowercase( $externally_authenticated_email ) );

				// If we've already found a WordPress user associated with one
				// of the supplied email addresses, don't keep examining other
				// email addresses associated with the externally authenticated user.
				if ( false !== $user ) {
					break;
				}
			}

			// Check this external user's access against the access lists
			// (pending, approved, blocked).
			$result = $this->check_user_access( $user, $externally_authenticated_emails, $result );

			// Fail with message if there was an error creating/adding the user.
			if ( is_wp_error( $result ) || 0 === $result ) {
				return $result;
			}

			// If we have a valid user from check_user_access(), log that user in.
			if ( get_class( $result ) === 'WP_User' ) {
				$user = $result;
			}

			// We'll track how this user was authenticated in user meta.
			if ( $user ) {
				update_user_meta( $user->ID, 'authenticated_by', $authenticated_by );
			}

			// If we haven't exited yet, we have a valid/approved user, so authenticate them.
			return $user;
		}


		/**
		 * This function will fail with a wp_die() message to the user if they
		 * don't have access.
		 *
		 * @param WP_User $user        User to check.
		 * @param array   $user_emails Array of user's plaintext emails (in case current user doesn't have a WP account).
		 * @param array   $user_data   Array of keys for email, username, first_name, last_name,
		 *                             authenticated_by, google_attributes, cas_attributes, ldap_attributes.
		 * @return WP_Error|void|WP_User
		 *                             WP_Error if there was an error on user creation / adding user to blog.
		 *                             wp_die() if user does not have access.
		 *                             WP_User if user has access.
		 */
		private function check_user_access( $user, $user_emails, $user_data = array() ) {
			// Grab plugin settings.
			$auth_settings                              = $this->get_plugin_options( WP_Plugin_Authorizer::SINGLE_CONTEXT, 'allow override' );
			$auth_settings_access_users_pending         = $this->sanitize_user_list(
				$this->get_plugin_option( 'access_users_pending', WP_Plugin_Authorizer::SINGLE_CONTEXT )
			);
			$auth_settings_access_users_approved_single = $this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::SINGLE_CONTEXT );
			$auth_settings_access_users_approved_multi  = $this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::NETWORK_CONTEXT );
			$auth_settings_access_users_approved        = $this->sanitize_user_list(
				array_merge(
					$auth_settings_access_users_approved_single,
					$auth_settings_access_users_approved_multi
				)
			);

			/**
			 * Filter whether to block the currently logging in user based on any of
			 * their user attributes.
			 *
			 * @param bool $allow_login Whether to block the currently logging in user.
			 * @param array $user_data User data returned from external service.
			 */
			$allow_login       = apply_filters( 'authorizer_allow_login', true, $user_data );
			$blocked_by_filter = ! $allow_login; // Use this for better readability.

			// Check our externally authenticated user against the block list.
			// If any of their email addresses are blocked, set the relevant user
			// meta field, and show them an error screen.
			foreach ( $user_emails as $user_email ) {
				if ( $blocked_by_filter || $this->is_email_in_list( $user_email, 'blocked' ) ) {

					// Add user to blocked list if it was blocked via the filter.
					if ( $blocked_by_filter && ! $this->is_email_in_list( $user_email, 'blocked' ) ) {
						$auth_settings_access_users_blocked = $this->sanitize_user_list(
							$this->get_plugin_option( 'access_users_blocked', WP_Plugin_Authorizer::SINGLE_CONTEXT )
						);
						array_push(
							$auth_settings_access_users_blocked, array(
								'email'      => $this->lowercase( $user_email ),
								'date_added' => date( 'M Y' ),
							)
						);
						update_option( 'auth_settings_access_users_blocked', $auth_settings_access_users_blocked );
					}

					// If the blocked external user has a WordPress account, mark it as
					// blocked (enforce block in this->authenticate()).
					if ( $user ) {
						update_user_meta( $user->ID, 'auth_blocked', 'yes' );
					}

					// Notify user about blocked status and return without authenticating them.
					// phpcs:ignore WordPress.CSRF.NonceVerification.NoNonceVerification
					$redirect_to = ! empty( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : home_url();
					$page_title  = sprintf(
						/* TRANSLATORS: %s: Name of blog */
						__( '%s - Access Restricted', 'authorizer' ),
						get_bloginfo( 'name' )
					);
					$error_message =
						apply_filters( 'the_content', $auth_settings['access_blocked_redirect_to_message'] ) .
						'<hr />' .
						'<p style="text-align: center;">' .
						'<a class="button" href="' . wp_logout_url( $redirect_to ) . '">' .
						__( 'Back', 'authorizer' ) .
						'</a></p>';
					update_option( 'auth_settings_advanced_login_error', $error_message );
					wp_die( wp_kses( $error_message, $this->allowed_html ), esc_html( $page_title ) );
				}
			}

			// Get the default role for this user (or their current role, if they
			// already have an account).
			$default_role = $user && is_array( $user->roles ) && count( $user->roles ) > 0 ? $user->roles[0] : $auth_settings['access_default_role'];
			/**
			 * Filter the role of the user currently logging in. The role will be
			 * set to the default (specified in Authorizer options) for new users,
			 * or the user's current role for existing users. This filter allows
			 * changing user roles based on custom CAS/LDAP attributes.
			 *
			 * @param bool $role Role of the user currently logging in.
			 * @param array $user_data User data returned from external service.
			 */
			$approved_role = apply_filters( 'authorizer_custom_role', $default_role, $user_data );

			/**
			 * Filter whether to automatically approve the currently logging in user
			 * based on any of their user attributes.
			 *
			 * @param bool  $automatically_approve_login
			 *   Whether to automatically approve the currently logging in user.
			 * @param array $user_data User data returned from external service.
			 */
			$automatically_approve_login = apply_filters( 'authorizer_automatically_approve_login', false, $user_data );

			// Iterate through each of the email addresses provided by the external
			// service and determine if any of them have access.
			$last_email = end( $user_emails );
			reset( $user_emails );
			foreach ( $user_emails as $user_email ) {
				$is_newly_approved_user = false;

				// If this externally authenticated user is an existing administrator
				// (administrator in single site mode, or super admin in network mode),
				// and is not in the blocked list, let them in.
				if ( $user && is_super_admin( $user->ID ) ) {
					return $user;
				}

				// If this externally authenticated user isn't in the approved list
				// and login access is set to "All authenticated users," or if they were
				// automatically approved in the "authorizer_approve_login" filter
				// above, then add them to the approved list (they'll get an account
				// created below if they don't have one yet).
				if (
					! $this->is_email_in_list( $user_email, 'approved' ) &&
					( 'external_users' === $auth_settings['access_who_can_login'] || $automatically_approve_login )
				) {
					$is_newly_approved_user = true;

					// If this user happens to be in the pending list (rare),
					// remove them from pending before adding them to approved.
					if ( $this->is_email_in_list( $user_email, 'pending' ) ) {
						foreach ( $auth_settings_access_users_pending as $key => $pending_user ) {
							if ( 0 === strcasecmp( $pending_user['email'], $user_email ) ) {
								unset( $auth_settings_access_users_pending[ $key ] );
								update_option( 'auth_settings_access_users_pending', $auth_settings_access_users_pending );
								break;
							}
						}
					}

					// Add this user to the approved list.
					$approved_user = array(
						'email'      => $this->lowercase( $user_email ),
						'role'       => $approved_role,
						'date_added' => date( 'Y-m-d H:i:s' ),
					);
					array_push( $auth_settings_access_users_approved, $approved_user );
					array_push( $auth_settings_access_users_approved_single, $approved_user );
					update_option( 'auth_settings_access_users_approved', $auth_settings_access_users_approved_single );
				}

				// Check our externally authenticated user against the approved
				// list. If they are approved, log them in (and create their account
				// if necessary).
				if ( $is_newly_approved_user || $this->is_email_in_list( $user_email, 'approved' ) ) {
					$user_info = $is_newly_approved_user ? $approved_user : $this->get_user_info_from_list( $user_email, $auth_settings_access_users_approved );

					// If this user's role was modified above (in the
					// authorizer_custom_role filter), use that value instead of
					// whatever is specified in the approved list.
					if ( $default_role !== $approved_role ) {
						$user_info['role'] = $approved_role;
					}

					// If the approved external user does not have a WordPress account, create it.
					if ( ! $user ) {
						// If there's already a user with this username (e.g.,
						// johndoe/johndoe@gmail.com exists, and we're trying to add
						// johndoe/johndoe@example.com), use the full email address
						// as the username.
						if ( array_key_exists( 'username', $user_data ) ) {
							$username = $user_data['username'];
						} else {
							$username = explode( '@', $user_info['email'] );
							$username = $username[0];
						}
						if ( get_user_by( 'login', $username ) !== false ) {
							$username = $user_info['email'];
						}
						$result = wp_insert_user(
							array(
								'user_login'      => strtolower( $username ),
								'user_pass'       => wp_generate_password(), // random password.
								'first_name'      => array_key_exists( 'first_name', $user_data ) ? $user_data['first_name'] : '',
								'last_name'       => array_key_exists( 'last_name', $user_data ) ? $user_data['last_name'] : '',
								'user_email'      => $this->lowercase( $user_info['email'] ),
								'user_registered' => date( 'Y-m-d H:i:s' ),
								'role'            => $user_info['role'],
							)
						);

						// Fail with message if error.
						if ( is_wp_error( $result ) || 0 === $result ) {
							return $result;
						}

						// Authenticate as new user.
						$user = new WP_User( $result );

						/**
						 * Fires after an external user is authenticated for the first time
						 * and a new WordPress account is created for them.
						 *
						 * @since 2.8.0
						 *
						 * @param WP_User $user      User object.
						 * @param array   $user_data User data from external service.
						 *
						 * Example $user_data:
						 * array(
						 *   'email'            => 'user@example.edu',
						 *   'username'         => 'user',
						 *   'first_name'       => 'First',
						 *   'last_name'        => 'Last',
						 *   'authenticated_by' => 'cas',
						 *   'cas_attributes'   => array( ... ),
						 * );
						 */
						do_action( 'authorizer_user_register', $user, $user_data );

						// If multisite, iterate through all sites in the network and add the user
						// currently logging in to any of them that have the user on the approved list.
						// Note: this is useful for first-time logins--some users will have access
						// to multiple sites, and this prevents them from having to log into each
						// site individually to get access.
						if ( is_multisite() ) {
							$site_ids_of_user = array_map(
								function ( $site_of_user ) {
									return intval( $site_of_user->userblog_id );
								},
								get_blogs_of_user( $user->ID )
							);

							// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
							$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
							foreach ( $sites as $site ) {
								$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];

								// Skip if user is already added to this site.
								if ( in_array( intval( $blog_id ), $site_ids_of_user, true ) ) {
									continue;
								}

								// Check if user is on the approved list of this site they are not added to.
								$other_auth_settings_access_users_approved = get_blog_option( $blog_id, 'auth_settings_access_users_approved', array() );
								if ( $this->in_multi_array( $user->user_email, $other_auth_settings_access_users_approved ) ) {
									$other_user_info = $this->get_user_info_from_list( $user->user_email, $other_auth_settings_access_users_approved );
									// Add user to other site.
									add_user_to_blog( $blog_id, $user->ID, $other_user_info['role'] );
								}
							}
						}

						// Check if this new user has any preassigned usermeta
						// values in their approved list entry, and apply them to
						// their new WordPress account.
						if ( array_key_exists( 'usermeta', $user_info ) && is_array( $user_info['usermeta'] ) ) {
							$meta_key = $this->get_plugin_option( 'advanced_usermeta' );

							if ( array_key_exists( 'meta_key', $user_info['usermeta'] ) && array_key_exists( 'meta_value', $user_info['usermeta'] ) ) {
								// Only update the usermeta if the stored value matches
								// the option set in authorizer settings (if they don't
								// match it's probably old data).
								if ( $meta_key === $user_info['usermeta']['meta_key'] ) {
									// Update user's usermeta value for usermeta key stored in authorizer options.
									if ( strpos( $meta_key, 'acf___' ) === 0 && class_exists( 'acf' ) ) {
										// We have an ACF field value, so use the ACF function to update it.
										update_field( str_replace( 'acf___', '', $meta_key ), $user_info['usermeta']['meta_value'], 'user_' . $user->ID );
									} else {
										// We have a normal usermeta value, so just update it via the WordPress function.
										update_user_meta( $user->ID, $meta_key, $user_info['usermeta']['meta_value'] );
									}
								}
							} elseif ( is_multisite() && count( $user_info['usermeta'] ) > 0 ) {
								// Update usermeta for each multisite blog defined for this user.
								foreach ( $user_info['usermeta'] as $blog_id => $usermeta ) {
									if ( array_key_exists( 'meta_key', $usermeta ) && array_key_exists( 'meta_value', $usermeta ) ) {
										// Add this new user to the blog before we create their user meta (this step typically happens below, but we need it to happen early so we can create user meta here).
										if ( ! is_user_member_of_blog( $user->ID, $blog_id ) ) {
											add_user_to_blog( $blog_id, $user->ID, $user_info['role'] );
										}
										switch_to_blog( $blog_id );
										// Update user's usermeta value for usermeta key stored in authorizer options.
										if ( strpos( $meta_key, 'acf___' ) === 0 && class_exists( 'acf' ) ) {
											// We have an ACF field value, so use the ACF function to update it.
											update_field( str_replace( 'acf___', '', $meta_key ), $usermeta['meta_value'], 'user_' . $user->ID );
										} else {
											// We have a normal usermeta value, so just update it via the WordPress function.
											update_user_meta( $user->ID, $meta_key, $usermeta['meta_value'] );
										}
										restore_current_blog();
									}
								}
							}
						}
					} else {
						// Update first/last names of WordPress user from external
						// service if that option is set.
						if ( ( array_key_exists( 'authenticated_by', $user_data ) && 'cas' === $user_data['authenticated_by'] && array_key_exists( 'cas_attr_update_on_login', $auth_settings ) && 1 === intval( $auth_settings['cas_attr_update_on_login'] ) ) || ( array_key_exists( 'authenticated_by', $user_data ) && 'ldap' === $user_data['authenticated_by'] && array_key_exists( 'ldap_attr_update_on_login', $auth_settings ) && 1 === intval( $auth_settings['ldap_attr_update_on_login'] ) ) ) {
							if ( array_key_exists( 'first_name', $user_data ) && 0 < strlen( $user_data['first_name'] ) ) {
								wp_update_user(
									array(
										'ID'         => $user->ID,
										'first_name' => $user_data['first_name'],
									)
								);
							}
							if ( array_key_exists( 'last_name', $user_data ) && strlen( $user_data['last_name'] ) > 0 ) {
								wp_update_user(
									array(
										'ID'        => $user->ID,
										'last_name' => $user_data['last_name'],
									)
								);
							}
						}

						// Update this user's role if it was modified in the
						// authorizer_custom_role filter.
						if ( $default_role !== $approved_role ) {
							// Update user's role in WordPress.
							$user->set_role( $approved_role );

							// Update user's role in this site's approved list and save.
							foreach ( $auth_settings_access_users_approved_single as $key => $existing_user ) {
								if ( 0 === strcasecmp( $user->user_email, $existing_user['email'] ) ) {
									$auth_settings_access_users_approved_single[ $key ]['role'] = $approved_role;
									break;
								}
							}
							update_option( 'auth_settings_access_users_approved', $auth_settings_access_users_approved_single );
						}
					}

					// If this is multisite, add new user to current blog.
					if ( is_multisite() && ! is_user_member_of_blog( $user->ID ) ) {
						$result = add_user_to_blog( get_current_blog_id(), $user->ID, $user_info['role'] );

						// Fail with message if error.
						if ( is_wp_error( $result ) ) {
							return $result;
						}
					}

					// Ensure user has the same role as their entry in the approved list.
					if ( $user_info && ! in_array( $user_info['role'], $user->roles, true ) ) {
						$user->set_role( $user_info['role'] );
					}

					return $user;

				} elseif ( 0 === strcasecmp( $user_email, $last_email ) ) {
					/**
					 * Note: only do this for the last email address we are checking (we need
					 * to iterate through them all to make sure one of them isn't approved).
					 */

					// User isn't an admin, is not blocked, and is not approved.
					// Add them to the pending list and notify them and their instructor.
					if ( strlen( $user_email ) > 0 && ! $this->is_email_in_list( $user_email, 'pending' ) ) {
						$pending_user               = array();
						$pending_user['email']      = $this->lowercase( $user_email );
						$pending_user['role']       = $approved_role;
						$pending_user['date_added'] = '';
						array_push( $auth_settings_access_users_pending, $pending_user );
						update_option( 'auth_settings_access_users_pending', $auth_settings_access_users_pending );

						// Create strings used in the email notification.
						$site_name              = get_bloginfo( 'name' );
						$site_url               = get_bloginfo( 'url' );
						$authorizer_options_url = 'settings' === $auth_settings['advanced_admin_menu'] ? admin_url( 'options-general.php?page=authorizer' ) : admin_url( '?page=authorizer' );

						// Notify users with the role specified in "Which role should
						// receive email notifications about pending users?".
						if ( strlen( $auth_settings['access_role_receive_pending_emails'] ) > 0 ) {
							foreach ( get_users( array( 'role' => $auth_settings['access_role_receive_pending_emails'] ) ) as $user_recipient ) {
								wp_mail(
									$user_recipient->user_email,
									sprintf(
										/* TRANSLATORS: 1: User email 2: Name of site */
										__( 'Action required: Pending user %1$s at %2$s', 'authorizer' ),
										$pending_user['email'],
										$site_name
									),
									sprintf(
										/* TRANSLATORS: 1: Name of site 2: URL of site 3: URL of authorizer */
										__( "A new user has tried to access the %1\$s site you manage at:\n%2\$s\n\nPlease log in to approve or deny their request:\n%3\$s\n", 'authorizer' ),
										$site_name,
										$site_url,
										$authorizer_options_url
									)
								);
							}
						}
					}

					// Notify user about pending status and return without authenticating them.
					// phpcs:ignore WordPress.CSRF.NonceVerification.NoNonceVerification
					$redirect_to   = ! empty( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : home_url();
					$page_title    = get_bloginfo( 'name' ) . ' - Access Pending';
					$error_message =
						apply_filters( 'the_content', $auth_settings['access_pending_redirect_to_message'] ) .
						'<hr />' .
						'<p style="text-align: center;">' .
						'<a class="button" href="' . wp_logout_url( $redirect_to ) . '">' .
						__( 'Back', 'authorizer' ) .
						'</a></p>';
					update_option( 'auth_settings_advanced_login_error', $error_message );
					wp_die( wp_kses( $error_message, $this->allowed_html ), esc_html( $page_title ) );
				}
			}

			// Sanity check: if we made it here without returning, something has gone wrong.
			return new WP_Error( 'invalid_login', __( 'Invalid login attempted.', 'authorizer' ) );

		}


		/**
		 * Verify the Google login and set a session token.
		 *
		 * Flow: "Sign in with Google" button clicked; JS Google library
		 * called; JS function signInCallback() fired with results from Google;
		 * signInCallback() posts code and nonce (via AJAX) to this function;
		 * This function checks the token using the Google PHP library, and
		 * saves it to a session variable if it's authentic; control passes
		 * back to signInCallback(), which will reload the current page
		 * (wp-login.php) on success; wp-login.php reloads; custom_authenticate
		 * hooked into authenticate action fires again, and
		 * custom_authenticate_google() runs to verify the token; once verified
		 * custom_authenticate proceeds as normal with the google email address
		 * as a successfully authenticated external user.
		 *
		 * Action: wp_ajax_process_google_login
		 * Action: wp_ajax_nopriv_process_google_login
		 *
		 * @return void, but die with the value to return to the success() function in AJAX call signInCallback().
		 */
		public function ajax_process_google_login() {
			// Nonce check.
			if (
				! isset( $_POST['nonce'] ) ||
				! wp_verify_nonce( sanitize_key( $_POST['nonce'] ), 'google_csrf_nonce' )
			) {
				die( '' );
			}

			// Google authentication token.
			// phpcs:ignore WordPress.VIP.ValidatedSanitizedInput.InputNotSanitized
			$code = isset( $_POST['code'] ) ? wp_unslash( $_POST['code'] ) : null;

			// Grab plugin settings.
			$auth_settings = $this->get_plugin_options( WP_Plugin_Authorizer::SINGLE_CONTEXT, 'allow override' );

			/**
			 * Add Google API PHP Client.
			 *
			 * @see https://github.com/google/google-api-php-client branch:v1-master
			 */
			require_once dirname( __FILE__ ) . '/vendor/google-api-php-client/src/Google/autoload.php';

			// Build the Google Client.
			$client = new Google_Client();
			$client->setApplicationName( 'WordPress' );
			$client->setClientId( $auth_settings['google_clientid'] );
			$client->setClientSecret( $auth_settings['google_clientsecret'] );
			$client->setRedirectUri( 'postmessage' );

			/**
			 * If the hosted domain parameter is set, restrict logins to that domain.
			 *
			 * Note: Will have to upgrade to google-api-php-client v2 or higher for
			 * this to function server-side; it's not complete in v1, so this check
			 * is performed manually below.
			 *
			 * if (
			 *   array_key_exists( 'google_hosteddomain', $auth_settings ) &&
			 *   strlen( $auth_settings['google_hosteddomain'] ) > 0
			 * ) {
			 *   $google_hosteddomains = explode( "\n", str_replace( "\r", '', $auth_settings['google_hosteddomain'] ) );
			 *   $google_hosteddomain = trim( $google_hosteddomains[0] );
			 *   $client->setHostedDomain( $google_hosteddomain );
			 * }
			 */

			// Get one time use token (if it doesn't exist, we'll create one below).
			session_start();
			$token = array_key_exists( 'token', $_SESSION ) ? json_decode( $_SESSION['token'] ) : null;

			if ( empty( $token ) ) {
				// Exchange the OAuth 2.0 authorization code for user credentials.
				$client->authenticate( $code );
				$token = json_decode( $client->getAccessToken() );

				// Store the token in the session for later use.
				$_SESSION['token'] = wp_json_encode( $token );

				$response = 'Successfully authenticated.';
			} else {
				$client->setAccessToken( wp_json_encode( $token ) );

				$response = 'Already authenticated.';
			}

			die( esc_html( $response ) );
		}


		/**
		 * Validate this user's credentials against Google.
		 *
		 * @param  array $auth_settings Plugin settings.
		 * @return array|WP_Error       Array containing email, authenticated_by, first_name,
		 *                              last_name, and username strings for the successfully
		 *                              authenticated user, or WP_Error() object on failure,
		 *                              or null if not attempting a google login.
		 */
		private function custom_authenticate_google( $auth_settings ) {
			// Move on if Google auth hasn't been requested here.
			// phpcs:ignore WordPress.CSRF.NonceVerification.NoNonceVerification
			if ( empty( $_GET['external'] ) || 'google' !== $_GET['external'] ) {
				return null;
			}

			// Get one time use token.
			session_start();
			$token = array_key_exists( 'token', $_SESSION ) ? json_decode( $_SESSION['token'] ) : null;

			// No token, so this is not a succesful Google login.
			if ( is_null( $token ) ) {
				return null;
			}

			/**
			 * Add Google API PHP Client.
			 *
			 * @see https://github.com/google/google-api-php-client branch:v1-master
			 */
			require_once dirname( __FILE__ ) . '/vendor/google-api-php-client/src/Google/autoload.php';

			// Build the Google Client.
			$client = new Google_Client();
			$client->setApplicationName( 'WordPress' );
			$client->setClientId( $auth_settings['google_clientid'] );
			$client->setClientSecret( $auth_settings['google_clientsecret'] );
			$client->setRedirectUri( 'postmessage' );

			/**
			 * If the hosted domain parameter is set, restrict logins to that domain.
			 * Note: Will have to upgrade to google-api-php-client v2 or higher for
			 * this to function server-side; it's not complete in v1, so this check
			 * is performed manually later.
			 * if (
			 *   array_key_exists( 'google_hosteddomain', $auth_settings ) &&
			 *   strlen( $auth_settings['google_hosteddomain'] ) > 0
			 * ) {
			 *   $google_hosteddomains = explode( "\n", str_replace( "\r", '', $auth_settings['google_hosteddomain'] ) );
			 *   $google_hosteddomain = trim( $google_hosteddomains[0] );
			 *   $client->setHostedDomain( $google_hosteddomain );
			 * }
			 */

			// Verify this is a successful Google authentication.
			try {
				$ticket = $client->verifyIdToken( $token->id_token, $auth_settings['google_clientid'] );
			} catch ( Google_Auth_Exception $e ) {
				// Invalid ticket, so this in not a successful Google login.
				return new WP_Error( 'invalid_google_login', __( 'Invalid Google credentials provided.', 'authorizer' ) );
			}

			// Invalid ticket, so this in not a successful Google login.
			if ( ! $ticket ) {
				return new WP_Error( 'invalid_google_login', __( 'Invalid Google credentials provided.', 'authorizer' ) );
			}

			// Get email address.
			$attributes   = $ticket->getAttributes();
			$email        = $this->lowercase( $attributes['payload']['email'] );
			$email_domain = substr( strrchr( $email, '@' ), 1 );
			$username     = current( explode( '@', $email ) );

			/**
			 * Fail if hd param is set and the logging in user's email address doesn't
			 * match the allowed hosted domain.
			 *
			 * See: https://developers.google.com/identity/protocols/OpenIDConnect#hd-param
			 * See: https://github.com/google/google-api-php-client/blob/v1-master/src/Google/Client.php#L407-L416
			 *
			 * Note: Will have to upgrade to google-api-php-client v2 or higher for
			 * this to function server-side; it's not complete in v1, so this check
			 * is only performed here.
			 */
			if ( array_key_exists( 'google_hosteddomain', $auth_settings ) && strlen( $auth_settings['google_hosteddomain'] ) > 0 ) {
				// Allow multiple whitelisted domains.
				$google_hosteddomains = explode( "\n", str_replace( "\r", '', $auth_settings['google_hosteddomain'] ) );
				if ( ! in_array( $email_domain, $google_hosteddomains, true ) ) {
					$this->custom_logout();
					return new WP_Error( 'invalid_google_login', __( 'Google credentials do not match the allowed hosted domain', 'authorizer' ) );
				}
			}

			return array(
				'email'             => $email,
				'username'          => $username,
				'first_name'        => '',
				'last_name'         => '',
				'authenticated_by'  => 'google',
				'google_attributes' => $attributes,
			);
		}


		/**
		 * Validate this user's credentials against CAS.
		 *
		 * @param  array $auth_settings Plugin settings.
		 * @return array|WP_Error       Array containing 'email' and 'authenticated_by' strings
		 *                              for the successfully authenticated user, or WP_Error()
		 *                              object on failure, or null if not attempting a CAS login.
		 */
		private function custom_authenticate_cas( $auth_settings ) {
			// Move on if CAS hasn't been requested here.
			// phpcs:ignore WordPress.CSRF.NonceVerification.NoNonceVerification
			if ( empty( $_GET['external'] ) || 'cas' !== $_GET['external'] ) {
				return null;
			}

			/**
			 * Get the CAS server version (default to SAML_VERSION_1_1).
			 *
			 * @see: https://developer.jasig.org/cas-clients/php/1.3.4/docs/api/group__public.html
			 */
			$cas_version = SAML_VERSION_1_1;
			if ( 'CAS_VERSION_3_0' === $auth_settings['cas_version'] ) {
				$cas_version = CAS_VERSION_3_0;
			} elseif ( 'CAS_VERSION_2_0' === $auth_settings['cas_version'] ) {
				$cas_version = CAS_VERSION_2_0;
			} elseif ( 'CAS_VERSION_1_0' === $auth_settings['cas_version'] ) {
				$cas_version = CAS_VERSION_1_0;
			}

			// Set the CAS client configuration.
			phpCAS::client( $cas_version, $auth_settings['cas_host'], intval( $auth_settings['cas_port'] ), $auth_settings['cas_path'] );

			// Allow redirects at the CAS server endpoint (e.g., allow connections
			// at an old CAS URL that redirects to a newer CAS URL).
			phpCAS::setExtraCurlOption( CURLOPT_FOLLOWLOCATION, true );

			// Update server certificate bundle if it doesn't exist or is older
			// than 6 months, then use it to ensure CAS server is legitimate.
			// Note: only try to update if the system has the php_openssl extension.
			$cacert_url        = 'https://curl.haxx.se/ca/cacert.pem';
			$cacert_path       = plugin_dir_path( __FILE__ ) . 'vendor/cacert.pem';
			$time_180_days     = 180 * 24 * 60 * 60; // days * hours * minutes * seconds.
			$time_180_days_ago = time() - $time_180_days;
			if (
				extension_loaded( 'openssl' ) &&
				( ! file_exists( $cacert_path ) || filemtime( $cacert_path ) < $time_180_days_ago )
			) {
				// Get new cacert.pem file from https://curl.haxx.se/ca/cacert.pem.
				$response = wp_safe_remote_get( $cacert_url );
				if (
					is_wp_error( $response ) ||
					200 !== wp_remote_retrieve_response_code( $response ) ||
					! array_key_exists( 'body', $response )
				) {
					new WP_Error( 'cannot_update_cacert', __( 'Unable to update outdated server certificates from https://curl.haxx.se/ca/cacert.pem.', 'authorizer' ) );
				}
				$cacert_contents = $response['body'];

				// Write out the updated certs to the plugin directory.
				// Note: Don't use WP_Filesystem because we are not in an admin context
				// and don't want to potentially prompt the end user for credentials.
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_file_put_contents
				file_put_contents( $cacert_path, $cacert_contents );
			}
			phpCAS::setCasServerCACert( $cacert_path );

			// Set the CAS service URL (including the redirect URL for WordPress when it comes back from CAS).
			$cas_service_url   = site_url( '/wp-login.php?external=cas' );
			$login_querystring = array();
			if ( isset( $_SERVER['QUERY_STRING'] ) ) {
				parse_str( $_SERVER['QUERY_STRING'], $login_querystring ); // phpcs:ignore WordPress.VIP.ValidatedSanitizedInput
			}
			if ( isset( $login_querystring['redirect_to'] ) ) {
				$cas_service_url .= '&redirect_to=' . rawurlencode( $login_querystring['redirect_to'] );
			}
			phpCAS::setFixedServiceURL( $cas_service_url );

			// Authenticate against CAS.
			try {
				phpCAS::forceAuthentication();
			} catch ( CAS_AuthenticationException $e ) {
				// CAS server threw an error in isAuthenticated(), potentially because
				// the cached ticket is outdated. Try renewing the authentication.
				error_log( __( 'CAS server returned an Authentication Exception. Details:', 'authorizer' ) ); // phpcs:ignore
				error_log( print_r( $e, true ) ); // phpcs:ignore

				// CAS server is throwing errors on this login, so try logging the
				// user out of CAS and redirecting them to the login page.
				phpCAS::logoutWithRedirectService( wp_login_url() );
				die();
			}

			// Get username (as specified by the CAS server).
			$username = phpCAS::getUser();

			// Get email that successfully authenticated against the external service (CAS).
			$externally_authenticated_email = strtolower( $username );
			if ( ! filter_var( $externally_authenticated_email, FILTER_VALIDATE_EMAIL ) ) {
				// If we can't get the user's email address from a CAS attribute,
				// try to guess the domain from the CAS server hostname. This will only
				// be used if we can't discover the email address from CAS attributes.
				$domain_guess                   = preg_match( '/[^.]*\.[^.]*$/', $auth_settings['cas_host'], $matches ) === 1 ? $matches[0] : '';
				$externally_authenticated_email = $this->lowercase( $username ) . '@' . $domain_guess;
			}

			// Retrieve the user attributes (e.g., email address, first name, last name) from the CAS server.
			$cas_attributes = phpCAS::getAttributes();

			// Get user email if it is specified in another field.
			if ( array_key_exists( 'cas_attr_email', $auth_settings ) && strlen( $auth_settings['cas_attr_email'] ) > 0 ) {
				// If the email attribute starts with an at symbol (@), assume that the
				// email domain is manually entered there (instead of a reference to a
				// CAS attribute), and combine that with the username to create the email.
				// Otherwise, look up the CAS attribute for email.
				if ( substr( $auth_settings['cas_attr_email'], 0, 1 ) === '@' ) {
					$externally_authenticated_email = $this->lowercase( $username . $auth_settings['cas_attr_email'] );
				} elseif (
					// If a CAS attribute has been specified as containing the email address, use that instead.
					// Email attribute can be a string or an array of strings.
					array_key_exists( $auth_settings['cas_attr_email'], $cas_attributes ) && (
						(
							is_array( $cas_attributes[ $auth_settings['cas_attr_email'] ] ) &&
							count( $cas_attributes[ $auth_settings['cas_attr_email'] ] ) > 0
						) || (
							is_string( $cas_attributes[ $auth_settings['cas_attr_email'] ] ) &&
							strlen( $cas_attributes[ $auth_settings['cas_attr_email'] ] ) > 0
						)
					)
				) {
					// Each of the emails in the array needs to be set to lowercase.
					if ( is_array( $cas_attributes[ $auth_settings['cas_attr_email'] ] ) ) {
						$externally_authenticated_email = array();
						foreach ( $cas_attributes[ $auth_settings['cas_attr_email'] ] as $external_email ) {
							$externally_authenticated_email[] = $this->lowercase( $external_email );
						}
					} else {
						$externally_authenticated_email = $this->lowercase( $cas_attributes[ $auth_settings['cas_attr_email'] ] );
					}
				}
			}

			// Get user first name and last name.
			$first_name = array_key_exists( 'cas_attr_first_name', $auth_settings ) && strlen( $auth_settings['cas_attr_first_name'] ) > 0 && array_key_exists( $auth_settings['cas_attr_first_name'], $cas_attributes ) && strlen( $cas_attributes[ $auth_settings['cas_attr_first_name'] ] ) > 0 ? $cas_attributes[ $auth_settings['cas_attr_first_name'] ] : '';
			$last_name  = array_key_exists( 'cas_attr_last_name', $auth_settings ) && strlen( $auth_settings['cas_attr_last_name'] ) > 0 && array_key_exists( $auth_settings['cas_attr_last_name'], $cas_attributes ) && strlen( $cas_attributes[ $auth_settings['cas_attr_last_name'] ] ) > 0 ? $cas_attributes[ $auth_settings['cas_attr_last_name'] ] : '';

			return array(
				'email'            => $externally_authenticated_email,
				'username'         => $username,
				'first_name'       => $first_name,
				'last_name'        => $last_name,
				'authenticated_by' => 'cas',
				'cas_attributes'   => $cas_attributes,
			);
		}


		/**
		 * Validate this user's credentials against LDAP.
		 *
		 * @param  array  $auth_settings Plugin settings.
		 * @param  string $username      Attempted username from authenticate action.
		 * @param  string $password      Attempted password from authenticate action.
		 * @return array|WP_Error        Array containing 'email' and 'authenticated_by' strings
		 *                               for the successfully authenticated user, or WP_Error()
		 *                               object on failure, or null if skipping LDAP auth and
		 *                               falling back to WP auth.
		 */
		private function custom_authenticate_ldap( $auth_settings, $username, $password ) {
			// Get LDAP search base(s).
			$search_bases = explode( "\n", str_replace( "\r", '', trim( $auth_settings['ldap_search_base'] ) ) );

			// Fail silently (fall back to WordPress authentication) if no search base specified.
			if ( count( $search_bases ) < 1 ) {
				return null;
			}

			// Get the FQDN from the first LDAP search base domain components (dc). For
			// example, ou=people,dc=example,dc=edu,dc=uk would yield user@example.edu.uk.
			$search_base_components = explode( ',', trim( $search_bases[0] ) );
			$domain                 = array();
			foreach ( $search_base_components as $search_base_component ) {
				$component = explode( '=', $search_base_component );
				if ( 2 === count( $component ) && 'dc' === $component[0] ) {
					$domain[] = $component[1];
				}
			}
			$domain = implode( '.', $domain );

			// If we can't get the logging in user's email address from an LDAP attribute,
			// just use the domain from the LDAP host. This will only be used if we
			// can't discover the email address from an LDAP attribute.
			if ( empty( $domain ) ) {
				$domain = preg_match( '/[^.]*\.[^.]*$/', $auth_settings['ldap_host'], $matches ) === 1 ? $matches[0] : '';
			}

			// remove @domain if it exists in the username (i.e., if user entered their email).
			$username = str_replace( '@' . $domain, '', $username );

			// Fail silently (fall back to WordPress authentication) if both username
			// and password are empty (this will be the case when visiting wp-login.php
			// for the first time, or when clicking the Log In button without filling
			// out either field.
			if ( empty( $username ) && empty( $password ) ) {
				return null;
			}

			// Fail with error message if username or password is blank.
			if ( empty( $username ) ) {
				return new WP_Error( 'empty_username', __( 'You must provide a username or email.', 'authorizer' ) );
			}
			if ( empty( $password ) ) {
				return new WP_Error( 'empty_password', __( 'You must provide a password.', 'authorizer' ) );
			}

			// If php5-ldap extension isn't installed on server, fall back to WP auth.
			if ( ! function_exists( 'ldap_connect' ) ) {
				return null;
			}

			// Authenticate against LDAP using options provided in plugin settings.
			$result       = false;
			$ldap_user_dn = '';
			$first_name   = '';
			$last_name    = '';
			$email        = '';

			// Construct LDAP connection parameters. ldap_connect() takes either a
			// hostname or a full LDAP URI as its first parameter (works with OpenLDAP
			// 2.x.x or later). If it's an LDAP URI, the second parameter, $port, is
			// ignored, and port must be specified in the full URI. An LDAP URI is of
			// the form ldap://hostname:port or ldaps://hostname:port.
			$ldap_host   = $auth_settings['ldap_host'];
			$ldap_port   = intval( $auth_settings['ldap_port'] );
			$parsed_host = wp_parse_url( $ldap_host );
			// Fail (fall back to WordPress auth) if invalid host is specified.
			if ( false === $parsed_host ) {
				return null;
			}
			// If a scheme is in the LDAP host, use full LDAP URI instead of just hostname.
			if ( array_key_exists( 'scheme', $parsed_host ) ) {
				// If the port isn't in the LDAP URI, use the one in the LDAP port field.
				if ( ! array_key_exists( 'port', $parsed_host ) ) {
					$parsed_host['port'] = $ldap_port;
				}
				$ldap_host = $this->build_url( $parsed_host );
			}

			// Establish LDAP connection.
			$ldap = ldap_connect( $ldap_host, $ldap_port );
			ldap_set_option( $ldap, LDAP_OPT_PROTOCOL_VERSION, 3 );
			if ( 1 === intval( $auth_settings['ldap_tls'] ) ) {
				if ( ! ldap_start_tls( $ldap ) ) {
					return null;
				}
			}

			// Set bind credentials; attempt an anonymous bind if not provided.
			$bind_rdn      = null;
			$bind_password = null;
			if ( strlen( $auth_settings['ldap_user'] ) > 0 ) {
				$bind_rdn      = $auth_settings['ldap_user'];
				$bind_password = $this->decrypt( $auth_settings['ldap_password'] );
			}

			// Attempt LDAP bind.
			$result = @ldap_bind( $ldap, $bind_rdn, stripslashes( $bind_password ) ); // phpcs:ignore
			if ( ! $result ) {
				// Can't connect to LDAP, so fall back to WordPress authentication.
				return null;
			}
			// Look up the bind DN (and first/last name) of the user trying to
			// log in by performing an LDAP search for the login username in
			// the field specified in the LDAP settings. This setup is common.
			$ldap_attributes_to_retrieve = array( 'dn' );
			if ( array_key_exists( 'ldap_attr_first_name', $auth_settings ) && strlen( $auth_settings['ldap_attr_first_name'] ) > 0 ) {
				array_push( $ldap_attributes_to_retrieve, $auth_settings['ldap_attr_first_name'] );
			}
			if ( array_key_exists( 'ldap_attr_last_name', $auth_settings ) && strlen( $auth_settings['ldap_attr_last_name'] ) > 0 ) {
				array_push( $ldap_attributes_to_retrieve, $auth_settings['ldap_attr_last_name'] );
			}
			if ( array_key_exists( 'ldap_attr_email', $auth_settings ) && strlen( $auth_settings['ldap_attr_email'] ) > 0 && substr( $auth_settings['ldap_attr_email'], 0, 1 ) !== '@' ) {
				array_push( $ldap_attributes_to_retrieve, $this->lowercase( $auth_settings['ldap_attr_email'] ) );
			}

			// Create default LDAP search filter (uid=$username).
			$search_filter = '(' . $auth_settings['ldap_uid'] . '=' . $username . ')';

			/**
			 * Filter LDAP search filter.
			 *
			 * Allows for custom LDAP authentication rules (e.g., restricting login
			 * access to users in multiple groups, or having certain attributes).
			 *
			 * @param string $search_filter The filter to pass to ldap_search().
			 * @param string $ldap_uid      The attribute to compare username against (from Authorizer Settings).
			 * @param string $username      The username attempting to log in.
			 */
			$search_filter = apply_filters( 'authorizer_ldap_search_filter', $search_filter, $auth_settings['ldap_uid'], $username );

			// Multiple search bases can be provided, so iterate through them until a match is found.
			foreach ( $search_bases as $search_base ) {
				$ldap_search  = ldap_search(
					$ldap,
					$search_base,
					$search_filter,
					$ldap_attributes_to_retrieve
				);
				$ldap_entries = ldap_get_entries( $ldap, $ldap_search );
				if ( $ldap_entries['count'] > 0 ) {
					break;
				}
			}

			// If we didn't find any users in ldap, fall back to WordPress authentication.
			if ( $ldap_entries['count'] < 1 ) {
				return null;
			}

			// Get the bind dn and first/last names; if there are multiple results returned, just get the last one.
			for ( $i = 0; $i < $ldap_entries['count']; $i++ ) {
				$ldap_user_dn = $ldap_entries[ $i ]['dn'];

				// Get user first name and last name.
				$ldap_attr_first_name = array_key_exists( 'ldap_attr_first_name', $auth_settings ) ? $this->lowercase( $auth_settings['ldap_attr_first_name'] ) : '';
				if ( strlen( $ldap_attr_first_name ) > 0 && array_key_exists( $ldap_attr_first_name, $ldap_entries[ $i ] ) && $ldap_entries[ $i ][ $ldap_attr_first_name ]['count'] > 0 && strlen( $ldap_entries[ $i ][ $ldap_attr_first_name ][0] ) > 0 ) {
					$first_name = $ldap_entries[ $i ][ $ldap_attr_first_name ][0];
				}
				$ldap_attr_last_name = array_key_exists( 'ldap_attr_last_name', $auth_settings ) ? $this->lowercase( $auth_settings['ldap_attr_last_name'] ) : '';
				if ( strlen( $ldap_attr_last_name ) > 0 && array_key_exists( $ldap_attr_last_name, $ldap_entries[ $i ] ) && $ldap_entries[ $i ][ $ldap_attr_last_name ]['count'] > 0 && strlen( $ldap_entries[ $i ][ $ldap_attr_last_name ][0] ) > 0 ) {
					$last_name = $ldap_entries[ $i ][ $ldap_attr_last_name ][0];
				}
				// Get user email if it is specified in another field.
				$ldap_attr_email = array_key_exists( 'ldap_attr_email', $auth_settings ) ? $this->lowercase( $auth_settings['ldap_attr_email'] ) : '';
				if ( strlen( $ldap_attr_email ) > 0 ) {
					// If the email attribute starts with an at symbol (@), assume that the
					// email domain is manually entered there (instead of a reference to an
					// LDAP attribute), and combine that with the username to create the email.
					// Otherwise, look up the LDAP attribute for email.
					if ( substr( $ldap_attr_email, 0, 1 ) === '@' ) {
						$email = $this->lowercase( $username . $ldap_attr_email );
					} elseif ( array_key_exists( $ldap_attr_email, $ldap_entries[ $i ] ) && $ldap_entries[ $i ][ $ldap_attr_email ]['count'] > 0 && strlen( $ldap_entries[ $i ][ $ldap_attr_email ][0] ) > 0 ) {
						$email = $this->lowercase( $ldap_entries[ $i ][ $ldap_attr_email ][0] );
					}
				}
			}

			$result = @ldap_bind( $ldap, $ldap_user_dn, stripslashes( $password ) ); // phpcs:ignore
			if ( ! $result ) {
				// We have a real ldap user, but an invalid password. Pass
				// through to wp authentication after failing LDAP (since
				// this could be a local account that happens to be the
				// same name as an LDAP user).
				return null;
			}

			// User successfully authenticated against LDAP, so set the relevant variables.
			$externally_authenticated_email = $this->lowercase( $username . '@' . $domain );

			// If an LDAP attribute has been specified as containing the email address, use that instead.
			if ( strlen( $email ) > 0 ) {
				$externally_authenticated_email = $this->lowercase( $email );
			}

			return array(
				'email'            => $externally_authenticated_email,
				'username'         => $username,
				'first_name'       => $first_name,
				'last_name'        => $last_name,
				'authenticated_by' => 'ldap',
				'ldap_attributes'  => $ldap_entries,
			);
		}


		/**
		 * Log out of the attached external service.
		 *
		 * Action: wp_logout
		 *
		 * @return void
		 */
		public function custom_logout() {
			// Grab plugin settings.
			$auth_settings = $this->get_plugin_options( WP_Plugin_Authorizer::SINGLE_CONTEXT, 'allow override' );

			// Reset option containing old error messages.
			delete_option( 'auth_settings_advanced_login_error' );

			if ( session_id() === '' ) {
				session_start();
			}

			$current_user_authenticated_by = get_user_meta( get_current_user_id(), 'authenticated_by', true );

			// If logged in to CAS, Log out of CAS.
			if ( 'cas' === $current_user_authenticated_by && '1' === $auth_settings['cas'] ) {
				if ( ! array_key_exists( 'PHPCAS_CLIENT', $GLOBALS ) || ! array_key_exists( 'phpCAS', $_SESSION ) ) {

					/**
					 * Get the CAS server version (default to SAML_VERSION_1_1).
					 *
					 * @see: https://developer.jasig.org/cas-clients/php/1.3.4/docs/api/group__public.html
					 */
					$cas_version = SAML_VERSION_1_1;
					if ( 'CAS_VERSION_3_0' === $auth_settings['cas_version'] ) {
						$cas_version = CAS_VERSION_3_0;
					} elseif ( 'CAS_VERSION_2_0' === $auth_settings['cas_version'] ) {
						$cas_version = CAS_VERSION_2_0;
					} elseif ( 'CAS_VERSION_1_0' === $auth_settings['cas_version'] ) {
						$cas_version = CAS_VERSION_1_0;
					}

					// Set the CAS client configuration if it hasn't been set already.
					phpCAS::client( $cas_version, $auth_settings['cas_host'], intval( $auth_settings['cas_port'] ), $auth_settings['cas_path'] );
					// Allow redirects at the CAS server endpoint (e.g., allow connections
					// at an old CAS URL that redirects to a newer CAS URL).
					phpCAS::setExtraCurlOption( CURLOPT_FOLLOWLOCATION, true );
					// Restrict logout request origin to the CAS server only (prevent DDOS).
					phpCAS::handleLogoutRequests( true, array( $auth_settings['cas_host'] ) );
				}
				if ( phpCAS::isAuthenticated() || phpCAS::isInitialized() ) {
					// Redirect to home page, or specified page if it's been provided.
					$redirect_to = site_url( '/' );
					if ( ! empty( $_REQUEST['redirect_to'] ) && isset( $_REQUEST['_wpnonce'] ) && wp_verify_nonce( sanitize_key( $_REQUEST['_wpnonce'] ), 'log-out' ) ) {
						$redirect_to = esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) );
					}

					phpCAS::logoutWithRedirectService( $redirect_to );
				}
			}

			// If session token set, log out of Google.
			if ( 'google' === $current_user_authenticated_by || array_key_exists( 'token', $_SESSION ) ) {
				$token = json_decode( $_SESSION['token'] )->access_token;

				/**
				 * Add Google API PHP Client.
				 *
				 * @see https://github.com/google/google-api-php-client branch:v1-master
				 */
				require_once dirname( __FILE__ ) . '/vendor/google-api-php-client/src/Google/autoload.php';

				// Build the Google Client.
				$client = new Google_Client();
				$client->setApplicationName( 'WordPress' );
				$client->setClientId( $auth_settings['google_clientid'] );
				$client->setClientSecret( $auth_settings['google_clientsecret'] );
				$client->setRedirectUri( 'postmessage' );

				// Revoke the token.
				$client->revokeToken( $token );

				// Remove the credentials from the user's session.
				unset( $_SESSION['token'] );
			}

		}



		/**
		 * ***************************
		 * Access Restriction
		 * ***************************
		 */



		/**
		 * Restrict access to WordPress site based on settings (everyone, logged_in_users).
		 *
		 * Action: parse_request
		 *
		 * @param  array $wp WordPress object.
		 * @return WP|void   WP object when passing through to WordPress authentication, or void.
		 */
		public function restrict_access( $wp ) {
			// Grab plugin settings.
			$auth_settings = $this->get_plugin_options( WP_Plugin_Authorizer::SINGLE_CONTEXT, 'allow override' );

			// Grab current user.
			$current_user = wp_get_current_user();

			$has_access = (
				// Always allow access if WordPress is installing.
				// phpcs:ignore WordPress.CSRF.NonceVerification.NoNonceVerification
				( defined( 'WP_INSTALLING' ) && isset( $_GET['key'] ) ) ||
				// Always allow access to admins.
				( current_user_can( 'create_users' ) ) ||
				// Allow access if option is set to 'everyone'.
				( 'everyone' === $auth_settings['access_who_can_view'] ) ||
				// Allow access to approved external users and logged in users if option is set to 'logged_in_users'.
				( 'logged_in_users' === $auth_settings['access_who_can_view'] && $this->is_user_logged_in_and_blog_user() && $this->is_email_in_list( $current_user->user_email, 'approved' ) ) ||
				// Allow access for requests to /wp-json/oauth1 so oauth clients can authenticate to use the REST API.
				( property_exists( $wp, 'matched_query' ) && stripos( $wp->matched_query, 'rest_oauth1=' ) === 0 ) ||
				// Allow access for non-GET requests to /wp-json/*, since REST API authentication already covers them.
				( property_exists( $wp, 'matched_query' ) && 0 === stripos( $wp->matched_query, 'rest_route=' ) && isset( $_SERVER['REQUEST_METHOD'] ) && 'GET' !== $_SERVER['REQUEST_METHOD'] ) ||
				// Allow access for GET requests to /wp-json/ (root), since REST API discovery calls rely on this.
				( property_exists( $wp, 'matched_query' ) && 'rest_route=/' === $wp->matched_query )
				// Note that GET requests to a rest endpoint will be restricted by authorizer. In that case, error messages will be returned as JSON.
			);

			/**
			 * Developers can use the `authorizer_has_access` filter to override
			 * restricted access on certain pages. Note that the restriction checks
			 * happens before WordPress executes any queries, so use the $wp variable
			 * to investigate what the visitor is trying to load.
			 *
			 * For example, to unblock an RSS feed, place the following PHP code in
			 * the theme's functions.php file or in a simple plug-in:
			 *
			 *   function my_feed_access_override( $has_access, $wp ) {
			 *     // Check query variables to see if this is the feed.
			 *     if ( ! empty( $wp->query_vars['feed'] ) ) {
			 *       $has_access = true;
			 *     }
			 *
			 *     return $has_access;
			 *   }
			 *   add_filter( 'authorizer_has_access', 'my_feed_access_override', 10, 2 );
			 */
			if ( apply_filters( 'authorizer_has_access', $has_access, $wp ) === true ) {
				// Turn off the public notice about browsing anonymously.
				update_option( 'auth_settings_advanced_public_notice', false );

				// We've determined that the current user has access, so simply return to grant access.
				return $wp;
			}

			// Allow HEAD requests to the root (usually discovery from a REST client).
			if ( 'HEAD' === $_SERVER['REQUEST_METHOD'] && empty( $wp->request ) && empty( $wp->matched_query ) ) {
				return $wp;
			}

			/* We've determined that the current user doesn't have access, so we deal with them now. */

			// Fringe case: In a multisite, a user of a different blog can successfully
			// log in, but they aren't on the 'approved' whitelist for this blog.
			// If that's the case, add them to the pending list for this blog.
			if ( is_multisite() && is_user_logged_in() && ! $has_access ) {
				$current_user = wp_get_current_user();

				// Check user access; block if not, add them to pending list if open, let them through otherwise.
				$result = $this->check_user_access( $current_user, array( $current_user->user_email ) );
			}

			// Check to see if the requested page is public. If so, show it.
			if ( empty( $wp->request ) ) {
				$current_page_id = 'home';
			} else {
				$request_query   = isset( $wp->query_vars ) ? new WP_Query( $wp->query_vars ) : null;
				$current_page_id = isset( $request_query->post_count ) && $request_query->post_count > 0 ? $request_query->post->ID : '';
			}
			if ( ! array_key_exists( 'access_public_pages', $auth_settings ) || ! is_array( $auth_settings['access_public_pages'] ) ) {
				$auth_settings['access_public_pages'] = array();
			}
			if ( in_array( strval( $current_page_id ), $auth_settings['access_public_pages'], true ) ) {
				if ( 'no_warning' === $auth_settings['access_public_warning'] ) {
					update_option( 'auth_settings_advanced_public_notice', false );
				} else {
					update_option( 'auth_settings_advanced_public_notice', true );
				}
				return $wp;
			}

			// Check to see if any category assigned to the requested page is public. If so, show it.
			$current_page_categories = wp_get_post_categories( $current_page_id, array( 'fields' => 'slugs' ) );
			foreach ( $current_page_categories as $current_page_category ) {
				if ( in_array( 'cat_' . $current_page_category, $auth_settings['access_public_pages'], true ) ) {
					if ( 'no_warning' === $auth_settings['access_public_warning'] ) {
						update_option( 'auth_settings_advanced_public_notice', false );
					} else {
						update_option( 'auth_settings_advanced_public_notice', true );
					}
					return $wp;
				}
			}

			// Check to see if this page can't be found. If so, allow showing the 404 page.
			if ( strlen( $current_page_id ) < 1 ) {
				if ( in_array( 'auth_public_404', $auth_settings['access_public_pages'], true ) ) {
					if ( 'no_warning' === $auth_settings['access_public_warning'] ) {
						update_option( 'auth_settings_advanced_public_notice', false );
					} else {
						update_option( 'auth_settings_advanced_public_notice', true );
					}
					return $wp;
				}
			}

			// Check to see if the requested category is public. If so, show it.
			$current_category_name = property_exists( $wp, 'query_vars' ) && array_key_exists( 'category_name', $wp->query_vars ) && strlen( $wp->query_vars['category_name'] ) > 0 ? $wp->query_vars['category_name'] : '';
			if ( $current_category_name ) {
				$current_category_name = end( explode( '/', $current_category_name ) );
				if ( in_array( 'cat_' . $current_category_name, $auth_settings['access_public_pages'], true ) ) {
					if ( 'no_warning' === $auth_settings['access_public_warning'] ) {
						update_option( 'auth_settings_advanced_public_notice', false );
					} else {
						update_option( 'auth_settings_advanced_public_notice', true );
					}
					return $wp;
				}
			}

			// User is denied access, so show them the error message. Render as JSON
			// if this is a REST API call; otherwise, show the error message via
			// wp_die() (rendered html), or redirect to the login URL.
			$current_path = ! empty( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : home_url();
			if ( property_exists( $wp, 'matched_query' ) && stripos( $wp->matched_query, 'rest_route=' ) === 0 && 'GET' === $_SERVER['REQUEST_METHOD'] ) {
				wp_send_json(
					array(
						'code'    => 'rest_cannot_view',
						'message' => strip_tags( $auth_settings['access_redirect_to_message'] ),
						'data'    => array(
							'status' => 401,
						),
					)
				);
			} elseif ( 'message' === $auth_settings['access_redirect'] ) {
				$page_title = sprintf(
					/* TRANSLATORS: %s: Name of blog */
					__( '%s - Access Restricted', 'authorizer' ),
					get_bloginfo( 'name' )
				);
				$error_message =
					apply_filters( 'the_content', $auth_settings['access_redirect_to_message'] ) .
					'<hr />' .
					'<p style="text-align: center;margin-bottom: -15px;">' .
					'<a class="button" href="' . wp_login_url( $current_path ) . '">' .
					__( 'Log In', 'authorizer' ) .
					'</a></p>';
				wp_die( wp_kses( $error_message, $this->allowed_html ), esc_html( $page_title ) );
			} else {
				wp_redirect( wp_login_url( $current_path ), 302 );
				exit;
			}

			// Sanity check: we should never get here.
			wp_die( '<p>Access denied.</p>', 'Site Access Restricted' );
		}


		/**
		 * On an admin page load, check for edge case (network-approved user who has
		 * not yet been added to this particular blog in a multisite). Note: we do
		 * this because check_user_access() runs on the parse_request hook, which
		 * does not fire on wp-admin pages.
		 *
		 * Action: init
		 *
		 * @return void
		 */
		public function init__maybe_add_network_approved_user() {
			global $current_user;

			// If this is a multisite install and we have a logged in user that's not
			// a member of this blog, but is (network) approved, add them to this blog.
			if (
				is_admin() &&
				is_multisite() &&
				is_user_logged_in() &&
				! is_user_member_of_blog() &&
				$this->is_email_in_list( $current_user->user_email, 'approved' )
			) {
				// Get all approved users.
				$auth_settings_access_users_approved = $this->sanitize_user_list(
					array_merge(
						$this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::SINGLE_CONTEXT ),
						$this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::NETWORK_CONTEXT )
					)
				);

				// Get user info (we need user role).
				$user_info = $this->get_user_info_from_list(
					$current_user->user_email,
					$auth_settings_access_users_approved
				);

				// Add user to blog.
				add_user_to_blog( get_current_blog_id(), $current_user->ID, $user_info['role'] );

				// Refresh user permissions.
				$current_user = new WP_User( $current_user->ID ); // phpcs:ignore WordPress.Variables.GlobalVariables.OverrideProhibited
			}
		}



		/**
		 * ***************************
		 * Login page (wp-login.php)
		 * ***************************
		 */



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
		 * Load external resources for the public-facing site.
		 *
		 * Action: wp_enqueue_scripts
		 */
		public function auth_public_scripts() {
			// Load (and localize) public scripts.
			$current_path = ! empty( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : home_url();
			wp_enqueue_script( 'auth_public_scripts', plugins_url( '/js/authorizer-public.js', __FILE__ ), array( 'jquery' ), '2.8.0' );
			$auth_localized = array(
				'wpLoginUrl'      => wp_login_url( $current_path ),
				'publicWarning'   => get_option( 'auth_settings_advanced_public_notice' ),
				'anonymousNotice' => $this->get_plugin_option( 'access_redirect_to_message' ),
				'logIn'           => esc_html__( 'Log In', 'authorizer' ),
			);
			wp_localize_script( 'auth_public_scripts', 'auth', $auth_localized );

			// Load public css.
			wp_register_style( 'authorizer-public-css', plugins_url( 'css/authorizer-public.css', __FILE__ ), array(), '2.8.0' );
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
			$auth_settings = $this->get_plugin_options( WP_Plugin_Authorizer::SINGLE_CONTEXT, 'allow override' );

			// Enqueue scripts appearing on wp-login.php.
			wp_enqueue_script( 'auth_login_scripts', plugins_url( '/js/authorizer-login.js', __FILE__ ), array( 'jquery' ), '2.8.0' );

			// Enqueue styles appearing on wp-login.php.
			wp_register_style( 'authorizer-login-css', plugins_url( '/css/authorizer-login.css', __FILE__ ), array(), '2.8.0' );
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
					wp_enqueue_script( 'auth_login_custom_scripts-' . sanitize_title( $branding_option['value'] ), $branding_option['js_url'], array( 'jquery' ), '2.8.0' );
					wp_register_style( 'authorizer-login-custom-css-' . sanitize_title( $branding_option['value'] ), $branding_option['css_url'], array(), '2.8.0' );
					wp_enqueue_style( 'authorizer-login-custom-css-' . sanitize_title( $branding_option['value'] ) );
				}
			}

			// If we're using Google logins, load those resources.
			if ( '1' === $auth_settings['google'] ) {
				wp_enqueue_script( 'authorizer-login-custom-google', plugins_url( '/js/authorizer-login-custom_google.js', __FILE__ ), array( 'jquery' ), '2.8.0' ); ?>
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
			$auth_settings = $this->get_plugin_options( WP_Plugin_Authorizer::SINGLE_CONTEXT, 'allow override' );
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
			nonce: $('#nonce_google_auth-<?php echo esc_attr( $this->get_cookie_value() ); ?>' ).val(),
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
			$auth_settings = $this->get_plugin_options( WP_Plugin_Authorizer::SINGLE_CONTEXT, 'allow override' );
			?>
			<div id="auth-external-service-login">
				<?php if ( '1' === $auth_settings['google'] ) : ?>
					<p><a id="googleplus_button" class="button button-primary button-external button-google"><span class="dashicons dashicons-googleplus"></span><span class="label"><?php esc_html_e( 'Sign in with Google', 'authorizer' ); ?></span></a></p>
					<?php wp_nonce_field( 'google_csrf_nonce', 'nonce_google_auth-' . $this->get_cookie_value() ); ?>
				<?php endif; ?>

				<?php if ( '1' === $auth_settings['cas'] ) : ?>
					<p><a class="button button-primary button-external button-cas" href="<?php echo esc_attr( $this->modify_current_url_for_cas_login() ); ?>">
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

				<?php if ( '1' === $auth_settings['advanced_hide_wp_login'] && isset( $_SERVER['QUERY_STRING'] ) && false === strpos( $_SERVER['QUERY_STRING'], 'external=wordpress' ) ) :  // phpcs:ignore WordPress.VIP.ValidatedSanitizedInput ?>
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
			$auth_settings = $this->get_plugin_options( WP_Plugin_Authorizer::SINGLE_CONTEXT, 'allow override' );

			// Check whether we should redirect to CAS.
			if (
				isset( $_SERVER['QUERY_STRING'] ) &&
				strpos( $_SERVER['QUERY_STRING'], 'external=wordpress' ) === false && // phpcs:ignore WordPress.VIP.ValidatedSanitizedInput
				array_key_exists( 'cas_auto_login', $auth_settings ) && '1' === $auth_settings['cas_auto_login'] &&
				array_key_exists( 'cas', $auth_settings ) && '1' === $auth_settings['cas'] &&
				( ! array_key_exists( 'ldap', $auth_settings ) || '1' !== $auth_settings['ldap'] ) &&
				( ! array_key_exists( 'google', $auth_settings ) || '1' !== $auth_settings['google'] ) &&
				array_key_exists( 'advanced_hide_wp_login', $auth_settings ) && '1' === $auth_settings['advanced_hide_wp_login']
			) {
				wp_redirect( $this->modify_current_url_for_cas_login() );
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
			$auth_settings = $this->get_plugin_options( WP_Plugin_Authorizer::SINGLE_CONTEXT, 'allow override' );

			// If Google logins are enabled, make sure the cookie is set.
			if ( array_key_exists( 'google', $auth_settings ) && '1' === $auth_settings['google'] ) {
				if ( ! isset( $_COOKIE['login_unique'] ) ) {
					$this->cookie_value = md5( rand() );
					setcookie( 'login_unique', $this->cookie_value, time() + 1800, '/', defined( 'COOKIE_DOMAIN' ) ? COOKIE_DOMAIN : '' );
					$_COOKIE['login_unique'] = $this->cookie_value;
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
			$auth_settings = $this->get_plugin_options( WP_Plugin_Authorizer::SINGLE_CONTEXT, 'allow override' );

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
		 * When they successfully log in, make sure WordPress users are in the approved list.
		 *
		 * Action: wp_login
		 *
		 * @param  string $user_login Username of the user logging in.
		 * @param  object $user       WP_User object of the user logging in.
		 * @return void
		 */
		public function ensure_wordpress_user_in_approved_list_on_login( $user_login, $user ) {
			$this->add_user_to_authorizer_when_created( $user->user_email, $user->user_registered, $user->roles );
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
			$auth_settings = $this->get_plugin_options( WP_Plugin_Authorizer::SINGLE_CONTEXT, 'allow override' );

			if (
				array_key_exists( 'ldap_lostpassword_url', $auth_settings ) &&
				filter_var( $auth_settings['ldap_lostpassword_url'], FILTER_VALIDATE_URL )
			) {
				$lostpassword_url = $auth_settings['ldap_lostpassword_url'];
			}
			return $lostpassword_url;
		}



		/**
		 * ***************************
		 * Options page
		 * ***************************
		 */



		/**
		 * Add a link to this plugin's settings page from the WordPress Plugins page.
		 * Called from "plugin_action_links" filter in __construct() above.
		 *
		 * Filter: plugin_action_links_authorizer.php
		 *
		 * @param  array $links Admin sidebar links.
		 * @return array        Admin sidebar links with Authorizer added.
		 */
		public function plugin_settings_link( $links ) {
			$admin_menu   = $this->get_plugin_option( 'advanced_admin_menu' );
			$settings_url = 'settings' === $admin_menu ? admin_url( 'options-general.php?page=authorizer' ) : admin_url( 'admin.php?page=authorizer' );
			array_unshift( $links, '<a href="' . $settings_url . '">' . __( 'Settings', 'authorizer' ) . '</a>' );
			return $links;
		}


		/**
		 * Add a link to this plugin's network settings page from the WordPress Plugins page.
		 * Called from "network_admin_plugin_action_links" filter in __construct() above.
		 *
		 * Filter: network_admin_plugin_action_links_authorizer.php
		 *
		 * @param  array $links Network admin sidebar links.
		 * @return array        Network admin sidebar links with Authorizer added.
		 */
		public function network_admin_plugin_settings_link( $links ) {
			$settings_link = '<a href="admin.php?page=authorizer">' . __( 'Network Settings', 'authorizer' ) . '</a>';
			array_unshift( $links, $settings_link );
			return $links;
		}


		/**
		 * Create the options page under Dashboard > Settings.
		 *
		 * Action: admin_menu
		 */
		public function add_plugin_page() {
			$admin_menu = $this->get_plugin_option( 'advanced_admin_menu' );
			if ( 'settings' === $admin_menu ) {
				// @see http://codex.wordpress.org/Function_Reference/add_options_page
				add_options_page(
					'Authorizer',
					'Authorizer',
					'create_users',
					'authorizer',
					array( $this, 'create_admin_page' )
				);
			} else {
				// @see http://codex.wordpress.org/Function_Reference/add_menu_page
				add_menu_page(
					'Authorizer',
					'Authorizer',
					'create_users',
					'authorizer',
					array( $this, 'create_admin_page' ),
					'dashicons-groups',
					'99.0018465' // position (decimal is to make overlap with other plugins less likely).
				);
			}
		}


		/**
		 * Output the HTML for the options page.
		 */
		public function create_admin_page() {
			?>
			<div class="wrap">
				<h2><?php esc_html_e( 'Authorizer Settings', 'authorizer' ); ?></h2>
				<form method="post" action="options.php" autocomplete="off">
					<?php
					// This prints out all hidden settings fields.
					settings_fields( 'auth_settings_group' );
					// This prints out all the sections.
					do_settings_sections( 'authorizer' );
					submit_button();
					?>
				</form>
			</div>
			<?php
		}


		/**
		 * Load external resources on this plugin's options page.
		 *
		 * Action: load-settings_page_authorizer
		 * Action: load-toplevel_page_authorizer
		 * Action: admin_head-index.php
		 */
		public function load_options_page() {
			wp_enqueue_script(
				'authorizer',
				plugins_url( 'js/authorizer.js', __FILE__ ),
				array( 'jquery-effects-shake' ), '2.8.6', true
			);
			wp_localize_script(
				'authorizer', 'authL10n', array(
					'baseurl'              => get_bloginfo( 'url' ),
					'saved'                => esc_html__( 'Saved', 'authorizer' ),
					'duplicate'            => esc_html__( 'Duplicate', 'authorizer' ),
					'failed'               => esc_html__( 'Failed', 'authorizer' ),
					'local_wordpress_user' => esc_html__( 'Local WordPress user', 'authorizer' ),
					'block_ban_user'       => esc_html__( 'Block/Ban user', 'authorizer' ),
					'remove_user'          => esc_html__( 'Remove user', 'authorizer' ),
					'no_users_in'          => esc_html__( 'No users in', 'authorizer' ),
					'save_changes'         => esc_html__( 'Save Changes', 'authorizer' ),
					'private_pages'        => esc_html__( 'Private Pages', 'authorizer' ),
					'public_pages'         => esc_html__( 'Public Pages', 'authorizer' ),
					'first_page'           => esc_html__( 'First page' ),
					'previous_page'        => esc_html__( 'Previous page' ),
					'next_page'            => esc_html__( 'Next page' ),
					'last_page'            => esc_html__( 'Last page' ),
					'is_network_admin'     => is_network_admin() ? '1' : '0',
				)
			);

			wp_enqueue_script(
				'jquery-autogrow-textarea',
				plugins_url( 'vendor/jquery.autogrow-textarea/jquery.autogrow-textarea.js', __FILE__ ),
				array( 'jquery' ), '2.7.0', true
			);

			wp_enqueue_script(
				'jquery.multi-select',
				plugins_url( 'vendor/jquery.multi-select/js/jquery.multi-select.js', __FILE__ ),
				array( 'jquery' ), '1.8', true
			);

			wp_register_style( 'authorizer-css', plugins_url( 'css/authorizer.css', __FILE__ ), array(), '2.7.3' );
			wp_enqueue_style( 'authorizer-css' );

			wp_register_style( 'jquery-multi-select-css', plugins_url( 'vendor/jquery.multi-select/css/multi-select.css', __FILE__ ), array(), '1.8' );
			wp_enqueue_style( 'jquery-multi-select-css' );

			add_action( 'admin_notices', array( $this, 'admin_notices' ) ); // Add any notices to the top of the options page.
			add_action( 'admin_head', array( $this, 'admin_head' ) ); // Add help documentation to the options page.
		}


		/**
		 * Show custom admin notice.
		 *
		 * Note: currently unused, but if anywhere we:
		 *   add_option( 'auth_settings_advanced_admin_notice, 'Your message.' );
		 * It will display and then delete that message on the admin dashboard.
		 *
		 * Filter: admin_notices
		 * filter: network_admin_notices
		 */
		public function show_advanced_admin_notice() {
			$notice = get_option( 'auth_settings_advanced_admin_notice' );
			delete_option( 'auth_settings_advanced_admin_notice' );

			if ( $notice && strlen( $notice ) > 0 ) {
				?>
				<div class="error">
					<p><?php echo wp_kses( $notice, $this->allowed_html ); ?></p>
				</div>
				<?php
			}
		}


		/**
		 * Add notices to the top of the options page.
		 *
		 * Action: load-settings_page_authorizer > admin_notices
		 *
		 * Description: Check for invalid settings combinations and show a warning message, e.g.:
		 *   if ( cas url inaccessible ) : ?>
		 *     <div class='updated settings-error'><p>Can't reach CAS server.</p></div>
		 *   <?php endif;
		 */
		public function admin_notices() {
			// Grab plugin settings.
			$auth_settings = $this->get_plugin_options( WP_Plugin_Authorizer::SINGLE_CONTEXT, 'allow override' );

			if ( '1' === $auth_settings['cas'] ) :
				// Check if provided CAS URL is accessible.
				$protocol       = in_array( strval( $auth_settings['cas_port'] ), array( '80', '8080' ), true ) ? 'http' : 'https';
				$cas_url        = $protocol . '://' . $auth_settings['cas_host'] . ':' . $auth_settings['cas_port'] . $auth_settings['cas_path'];
				$legacy_cas_url = trailingslashit( $cas_url ) . 'login'; // Check the specific CAS login endpoint (old; some servers don't register a ./login endpoint, use serviceValidate instead).
				$cas_url        = trailingslashit( $cas_url ) . 'serviceValidate'; // Check the specific CAS login endpoint.
				if ( ! $this->url_is_accessible( $cas_url ) && ! $this->url_is_accessible( $legacy_cas_url ) ) :
					$authorizer_options_url = 'settings' === $auth_settings['advanced_admin_menu'] ? admin_url( 'options-general.php?page=authorizer' ) : admin_url( '?page=authorizer' );
					?>
					<div class='notice notice-warning is-dismissible'>
						<p><?php esc_html_e( "Can't reach CAS server. Please provide", 'authorizer' ); ?> <a href='<?php echo esc_attr( $authorizer_options_url ); ?>&tab=external'><?php esc_html_e( 'accurate CAS settings', 'authorizer' ); ?></a> <?php esc_html_e( 'if you intend to use it.', 'authorizer' ); ?></p>
					</div>
					<?php
				endif;
			endif;
		}


		/**
		 * Create sections and options.
		 *
		 * Action: admin_init
		 */
		public function page_init() {
			/**
			 * Create one setting that holds all the options (array).
			 *
			 * @see http://codex.wordpress.org/Function_Reference/register_setting
			 * @see http://codex.wordpress.org/Function_Reference/add_settings_section
			 * @see http://codex.wordpress.org/Function_Reference/add_settings_field
			 */
			register_setting(
				'auth_settings_group',
				'auth_settings',
				array( $this, 'sanitize_options' )
			);

			add_settings_section(
				'auth_settings_tabs',
				'',
				array( $this, 'print_section_info_tabs' ),
				'authorizer'
			);

			// Create Access Lists section.
			add_settings_section(
				'auth_settings_lists',
				'',
				array( $this, 'print_section_info_access_lists' ),
				'authorizer'
			);

			// Create Login Access section.
			add_settings_section(
				'auth_settings_access_login',
				'',
				array( $this, 'print_section_info_access_login' ),
				'authorizer'
			);
			add_settings_field(
				'auth_settings_access_who_can_login',
				__( 'Who can log into the site?', 'authorizer' ),
				array( $this, 'print_radio_auth_access_who_can_login' ),
				'authorizer',
				'auth_settings_access_login'
			);
			add_settings_field(
				'auth_settings_access_role_receive_pending_emails',
				__( 'Which role should receive email notifications about pending users?', 'authorizer' ),
				array( $this, 'print_select_auth_access_role_receive_pending_emails' ),
				'authorizer',
				'auth_settings_access_login'
			);
			add_settings_field(
				'auth_settings_access_pending_redirect_to_message',
				__( 'What message should pending users see after attempting to log in?', 'authorizer' ),
				array( $this, 'print_wysiwyg_auth_access_pending_redirect_to_message' ),
				'authorizer',
				'auth_settings_access_login'
			);
			add_settings_field(
				'auth_settings_access_blocked_redirect_to_message',
				__( 'What message should blocked users see after attempting to log in?', 'authorizer' ),
				array( $this, 'print_wysiwyg_auth_access_blocked_redirect_to_message' ),
				'authorizer',
				'auth_settings_access_login'
			);
			add_settings_field(
				'auth_settings_access_should_email_approved_users',
				__( 'Send welcome email to new approved users?', 'authorizer' ),
				array( $this, 'print_checkbox_auth_access_should_email_approved_users' ),
				'authorizer',
				'auth_settings_access_login'
			);
			add_settings_field(
				'auth_settings_access_email_approved_users_subject',
				__( 'Welcome email subject', 'authorizer' ),
				array( $this, 'print_text_auth_access_email_approved_users_subject' ),
				'authorizer',
				'auth_settings_access_login'
			);
			add_settings_field(
				'auth_settings_access_email_approved_users_body',
				__( 'Welcome email body', 'authorizer' ),
				array( $this, 'print_wysiwyg_auth_access_email_approved_users_body' ),
				'authorizer',
				'auth_settings_access_login'
			);

			// Create Public Access section.
			add_settings_section(
				'auth_settings_access_public',
				'',
				array( $this, 'print_section_info_access_public' ),
				'authorizer'
			);
			add_settings_field(
				'auth_settings_access_who_can_view',
				__( 'Who can view the site?', 'authorizer' ),
				array( $this, 'print_radio_auth_access_who_can_view' ),
				'authorizer',
				'auth_settings_access_public'
			);
			add_settings_field(
				'auth_settings_access_public_pages',
				__( 'What pages (if any) should be available to everyone?', 'authorizer' ),
				array( $this, 'print_multiselect_auth_access_public_pages' ),
				'authorizer',
				'auth_settings_access_public'
			);
			add_settings_field(
				'auth_settings_access_redirect',
				__( 'What happens to people without access when they visit a private page?', 'authorizer' ),
				array( $this, 'print_radio_auth_access_redirect' ),
				'authorizer',
				'auth_settings_access_public'
			);
			add_settings_field(
				'auth_settings_access_public_warning',
				__( 'What happens to people without access when they visit a public page?', 'authorizer' ),
				array( $this, 'print_radio_auth_access_public_warning' ),
				'authorizer',
				'auth_settings_access_public'
			);
			add_settings_field(
				'auth_settings_access_redirect_to_message',
				__( 'What message should people without access see?', 'authorizer' ),
				array( $this, 'print_wysiwyg_auth_access_redirect_to_message' ),
				'authorizer',
				'auth_settings_access_public'
			);

			// Create External Service Settings section.
			add_settings_section(
				'auth_settings_external',
				'',
				array( $this, 'print_section_info_external' ),
				'authorizer'
			);
			add_settings_field(
				'auth_settings_access_default_role',
				__( 'Default role for new users', 'authorizer' ),
				array( $this, 'print_select_auth_access_default_role' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_external_google',
				__( 'Google Logins', 'authorizer' ),
				array( $this, 'print_checkbox_auth_external_google' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_google_clientid',
				__( 'Google Client ID', 'authorizer' ),
				array( $this, 'print_text_google_clientid' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_google_clientsecret',
				__( 'Google Client Secret', 'authorizer' ),
				array( $this, 'print_text_google_clientsecret' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_google_hosteddomain',
				__( 'Google Hosted Domain', 'authorizer' ),
				array( $this, 'print_text_google_hosteddomain' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_external_cas',
				__( 'CAS Logins', 'authorizer' ),
				array( $this, 'print_checkbox_auth_external_cas' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_cas_custom_label',
				__( 'CAS custom label', 'authorizer' ),
				array( $this, 'print_text_cas_custom_label' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_cas_host',
				__( 'CAS server hostname', 'authorizer' ),
				array( $this, 'print_text_cas_host' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_cas_port',
				__( 'CAS server port', 'authorizer' ),
				array( $this, 'print_text_cas_port' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_cas_path',
				__( 'CAS server path/context', 'authorizer' ),
				array( $this, 'print_text_cas_path' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_cas_version',
				'CAS server version',
				array( $this, 'print_select_cas_version' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_cas_attr_email',
				__( 'CAS attribute containing email address', 'authorizer' ),
				array( $this, 'print_text_cas_attr_email' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_cas_attr_first_name',
				__( 'CAS attribute containing first name', 'authorizer' ),
				array( $this, 'print_text_cas_attr_first_name' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_cas_attr_last_name',
				__( 'CAS attribute containing last name', 'authorizer' ),
				array( $this, 'print_text_cas_attr_last_name' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_cas_attr_update_on_login',
				__( 'CAS attribute update', 'authorizer' ),
				array( $this, 'print_checkbox_cas_attr_update_on_login' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_cas_auto_login',
				__( 'CAS automatic login', 'authorizer' ),
				array( $this, 'print_checkbox_cas_auto_login' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_external_ldap',
				__( 'LDAP Logins', 'authorizer' ),
				array( $this, 'print_checkbox_auth_external_ldap' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_ldap_host',
				__( 'LDAP Host', 'authorizer' ),
				array( $this, 'print_text_ldap_host' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_ldap_port',
				__( 'LDAP Port', 'authorizer' ),
				array( $this, 'print_text_ldap_port' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_ldap_tls',
				__( 'Use TLS', 'authorizer' ),
				array( $this, 'print_checkbox_ldap_tls' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_ldap_search_base',
				__( 'LDAP Search Base', 'authorizer' ),
				array( $this, 'print_text_ldap_search_base' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_ldap_uid',
				__( 'LDAP attribute containing username', 'authorizer' ),
				array( $this, 'print_text_ldap_uid' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_ldap_attr_email',
				__( 'LDAP attribute containing email address', 'authorizer' ),
				array( $this, 'print_text_ldap_attr_email' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_ldap_user',
				__( 'LDAP Directory User', 'authorizer' ),
				array( $this, 'print_text_ldap_user' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_ldap_password',
				__( 'LDAP Directory User Password', 'authorizer' ),
				array( $this, 'print_password_ldap_password' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_ldap_lostpassword_url',
				__( 'Custom lost password URL', 'authorizer' ),
				array( $this, 'print_text_ldap_lostpassword_url' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_ldap_attr_first_name',
				__( 'LDAP attribute containing first name', 'authorizer' ),
				array( $this, 'print_text_ldap_attr_first_name' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_ldap_attr_last_name',
				__( 'LDAP attribute containing last name', 'authorizer' ),
				array( $this, 'print_text_ldap_attr_last_name' ),
				'authorizer',
				'auth_settings_external'
			);
			add_settings_field(
				'auth_settings_ldap_attr_update_on_login',
				__( 'LDAP attribute update', 'authorizer' ),
				array( $this, 'print_checkbox_ldap_attr_update_on_login' ),
				'authorizer',
				'auth_settings_external'
			);

			// Create Advanced Settings section.
			add_settings_section(
				'auth_settings_advanced',
				'',
				array( $this, 'print_section_info_advanced' ),
				'authorizer'
			);
			add_settings_field(
				'auth_settings_advanced_lockouts',
				__( 'Limit invalid login attempts', 'authorizer' ),
				array( $this, 'print_text_auth_advanced_lockouts' ),
				'authorizer',
				'auth_settings_advanced'
			);
			add_settings_field(
				'auth_settings_advanced_hide_wp_login',
				__( 'Hide WordPress Login', 'authorizer' ),
				array( $this, 'print_checkbox_auth_advanced_hide_wp_login' ),
				'authorizer',
				'auth_settings_advanced'
			);
			add_settings_field(
				'auth_settings_advanced_branding',
				__( 'Custom WordPress login branding', 'authorizer' ),
				array( $this, 'print_radio_auth_advanced_branding' ),
				'authorizer',
				'auth_settings_advanced'
			);
			add_settings_field(
				'auth_settings_advanced_admin_menu',
				__( 'Authorizer admin menu item location', 'authorizer' ),
				array( $this, 'print_radio_auth_advanced_admin_menu' ),
				'authorizer',
				'auth_settings_advanced'
			);
			add_settings_field(
				'auth_settings_advanced_usermeta',
				__( 'Show custom usermeta in user list', 'authorizer' ),
				array( $this, 'print_select_auth_advanced_usermeta' ),
				'authorizer',
				'auth_settings_advanced'
			);
			add_settings_field(
				'auth_settings_advanced_users_per_page',
				__( 'Number of users per page', 'authorizer' ),
				array( $this, 'print_text_auth_advanced_users_per_page' ),
				'authorizer',
				'auth_settings_advanced'
			);
			add_settings_field(
				'auth_settings_advanced_users_sort_by',
				__( 'Approved users sort method', 'authorizer' ),
				array( $this, 'print_select_auth_advanced_users_sort_by' ),
				'authorizer',
				'auth_settings_advanced'
			);
			add_settings_field(
				'auth_settings_advanced_users_sort_order',
				__( 'Approved users sort order', 'authorizer' ),
				array( $this, 'print_select_auth_advanced_users_sort_order' ),
				'authorizer',
				'auth_settings_advanced'
			);
			add_settings_field(
				'auth_settings_advanced_widget_enabled',
				__( 'Show dashboard widget to admin users', 'authorizer' ),
				array( $this, 'print_checkbox_auth_advanced_widget_enabled' ),
				'authorizer',
				'auth_settings_advanced'
			);
			// On multisite installs, add an option to override all multisite settings on individual sites.
			if ( is_multisite() ) {
				add_settings_field(
					'auth_settings_advanced_override_multisite',
					__( 'Override multisite options', 'authorizer' ),
					array( $this, 'print_checkbox_auth_advanced_override_multisite' ),
					'authorizer',
					'auth_settings_advanced'
				);
			}
		}


		/**
		 * Set meaningful defaults for the plugin options.
		 *
		 * Note: This function is called on plugin activation.
		 */
		private function set_default_options() {
			global $wp_roles;

			$auth_settings = get_option( 'auth_settings' );
			if ( false === $auth_settings ) {
				$auth_settings = array();
			}

			// Access Lists Defaults.
			$auth_settings_access_users_pending = get_option( 'auth_settings_access_users_pending' );
			if ( false === $auth_settings_access_users_pending ) {
				$auth_settings_access_users_pending = array();
			}
			$auth_settings_access_users_approved = get_option( 'auth_settings_access_users_approved' );
			if ( false === $auth_settings_access_users_approved ) {
				$auth_settings_access_users_approved = array();
			}
			$auth_settings_access_users_blocked = get_option( 'auth_settings_access_users_blocked' );
			if ( false === $auth_settings_access_users_blocked ) {
				$auth_settings_access_users_blocked = array();
			}

			// Login Access Defaults.
			if ( ! array_key_exists( 'access_who_can_login', $auth_settings ) ) {
				$auth_settings['access_who_can_login'] = 'approved_users';
			}
			if ( ! array_key_exists( 'access_role_receive_pending_emails', $auth_settings ) ) {
				$auth_settings['access_role_receive_pending_emails'] = '---';
			}
			if ( ! array_key_exists( 'access_pending_redirect_to_message', $auth_settings ) ) {
				$auth_settings['access_pending_redirect_to_message'] = '<p>' . __( "You're not currently allowed to view this site. Your administrator has been notified, and once he/she has approved your request, you will be able to log in. If you need any other help, please contact your administrator.", 'authorizer' ) . '</p>';
			}
			if ( ! array_key_exists( 'access_blocked_redirect_to_message', $auth_settings ) ) {
				$auth_settings['access_blocked_redirect_to_message'] = '<p>' . __( "You're not currently allowed to log into this site. If you think this is a mistake, please contact your administrator.", 'authorizer' ) . '</p>';
			}
			if ( ! array_key_exists( 'access_should_email_approved_users', $auth_settings ) ) {
				$auth_settings['access_should_email_approved_users'] = '';
			}
			if ( ! array_key_exists( 'access_email_approved_users_subject', $auth_settings ) ) {
				$auth_settings['access_email_approved_users_subject'] = sprintf(
					/* TRANSLATORS: %s: Shortcode for name of site */
					__( 'Welcome to %s!', 'authorizer' ),
					'[site_name]'
				);
			}
			if ( ! array_key_exists( 'access_email_approved_users_body', $auth_settings ) ) {
				$auth_settings['access_email_approved_users_body'] = sprintf(
					/* TRANSLATORS: 1: Shortcode for user email 2: Shortcode for site name 3: Shortcode for site URL */
					__( "Hello %1\$s,\nWelcome to %2\$s! You now have access to all content on the site. Please visit us here:\n%3\$s\n", 'authorizer' ),
					'[user_email]',
					'[site_name]',
					'[site_url]'
				);
			}

			// Public Access to Private Page Defaults.
			if ( ! array_key_exists( 'access_who_can_view', $auth_settings ) ) {
				$auth_settings['access_who_can_view'] = 'everyone';
			}
			if ( ! array_key_exists( 'access_public_pages', $auth_settings ) ) {
				$auth_settings['access_public_pages'] = array();
			}
			if ( ! array_key_exists( 'access_redirect', $auth_settings ) ) {
				$auth_settings['access_redirect'] = 'login';
			}
			if ( ! array_key_exists( 'access_public_warning', $auth_settings ) ) {
				$auth_settings['access_public_warning'] = 'no_warning';
			}
			if ( ! array_key_exists( 'access_redirect_to_message', $auth_settings ) ) {
				$auth_settings['access_redirect_to_message'] = '<p>' . __( 'Notice: You are browsing this site anonymously, and only have access to a portion of its content.', 'authorizer' ) . '</p>';
			}

			// External Service Defaults.
			if ( ! array_key_exists( 'access_default_role', $auth_settings ) ) {
				// Set default role to 'student' if that role exists, 'subscriber' otherwise.
				$all_roles      = $wp_roles->roles;
				$editable_roles = apply_filters( 'editable_roles', $all_roles );
				if ( array_key_exists( 'student', $editable_roles ) ) {
					$auth_settings['access_default_role'] = 'student';
				} else {
					$auth_settings['access_default_role'] = 'subscriber';
				}
			}

			if ( ! array_key_exists( 'google', $auth_settings ) ) {
				$auth_settings['google'] = '';
			}
			if ( ! array_key_exists( 'cas', $auth_settings ) ) {
				$auth_settings['cas'] = '';
			}
			if ( ! array_key_exists( 'ldap', $auth_settings ) ) {
				$auth_settings['ldap'] = '';
			}

			if ( ! array_key_exists( 'google_clientid', $auth_settings ) ) {
				$auth_settings['google_clientid'] = '';
			}
			if ( ! array_key_exists( 'google_clientsecret', $auth_settings ) ) {
				$auth_settings['google_clientsecret'] = '';
			}
			if ( ! array_key_exists( 'google_hosteddomain', $auth_settings ) ) {
				$auth_settings['google_hosteddomain'] = '';
			}

			if ( ! array_key_exists( 'cas_custom_label', $auth_settings ) ) {
				$auth_settings['cas_custom_label'] = 'CAS';
			}
			if ( ! array_key_exists( 'cas_host', $auth_settings ) ) {
				$auth_settings['cas_host'] = '';
			}
			if ( ! array_key_exists( 'cas_port', $auth_settings ) ) {
				$auth_settings['cas_port'] = '';
			}
			if ( ! array_key_exists( 'cas_path', $auth_settings ) ) {
				$auth_settings['cas_path'] = '';
			}
			if ( ! array_key_exists( 'cas_version', $auth_settings ) ) {
				$auth_settings['cas_version'] = 'SAML_VERSION_1_1';
			}
			if ( ! array_key_exists( 'cas_attr_email', $auth_settings ) ) {
				$auth_settings['cas_attr_email'] = '';
			}
			if ( ! array_key_exists( 'cas_attr_first_name', $auth_settings ) ) {
				$auth_settings['cas_attr_first_name'] = '';
			}
			if ( ! array_key_exists( 'cas_attr_last_name', $auth_settings ) ) {
				$auth_settings['cas_attr_last_name'] = '';
			}
			if ( ! array_key_exists( 'cas_attr_update_on_login', $auth_settings ) ) {
				$auth_settings['cas_attr_update_on_login'] = '';
			}
			if ( ! array_key_exists( 'cas_auto_login', $auth_settings ) ) {
				$auth_settings['cas_auto_login'] = '';
			}

			if ( ! array_key_exists( 'ldap_host', $auth_settings ) ) {
				$auth_settings['ldap_host'] = '';
			}
			if ( ! array_key_exists( 'ldap_port', $auth_settings ) ) {
				$auth_settings['ldap_port'] = '389';
			}
			if ( ! array_key_exists( 'ldap_tls', $auth_settings ) ) {
				$auth_settings['ldap_tls'] = '1';
			}
			if ( ! array_key_exists( 'ldap_search_base', $auth_settings ) ) {
				$auth_settings['ldap_search_base'] = '';
			}
			if ( ! array_key_exists( 'ldap_uid', $auth_settings ) ) {
				$auth_settings['ldap_uid'] = 'uid';
			}
			if ( ! array_key_exists( 'ldap_attr_email', $auth_settings ) ) {
				$auth_settings['ldap_attr_email'] = '';
			}
			if ( ! array_key_exists( 'ldap_user', $auth_settings ) ) {
				$auth_settings['ldap_user'] = '';
			}
			if ( ! array_key_exists( 'ldap_password', $auth_settings ) ) {
				$auth_settings['ldap_password'] = '';
			}
			if ( ! array_key_exists( 'ldap_lostpassword_url', $auth_settings ) ) {
				$auth_settings['ldap_lostpassword_url'] = '';
			}
			if ( ! array_key_exists( 'ldap_attr_first_name', $auth_settings ) ) {
				$auth_settings['ldap_attr_first_name'] = '';
			}
			if ( ! array_key_exists( 'ldap_attr_last_name', $auth_settings ) ) {
				$auth_settings['ldap_attr_last_name'] = '';
			}
			if ( ! array_key_exists( 'ldap_attr_update_on_login', $auth_settings ) ) {
				$auth_settings['ldap_attr_update_on_login'] = '';
			}

			// Advanced defaults.
			if ( ! array_key_exists( 'advanced_lockouts', $auth_settings ) ) {
				$auth_settings['advanced_lockouts'] = array(
					'attempts_1'     => 10,
					'duration_1'     => 1,
					'attempts_2'     => 10,
					'duration_2'     => 10,
					'reset_duration' => 120,
				);
			}
			if ( ! array_key_exists( 'advanced_hide_wp_login', $auth_settings ) ) {
				$auth_settings['advanced_hide_wp_login'] = '';
			}
			if ( ! array_key_exists( 'advanced_branding', $auth_settings ) ) {
				$auth_settings['advanced_branding'] = 'default';
			}
			if ( ! array_key_exists( 'advanced_admin_menu', $auth_settings ) ) {
				$auth_settings['advanced_admin_menu'] = 'top';
			}
			if ( ! array_key_exists( 'advanced_usermeta', $auth_settings ) ) {
				$auth_settings['advanced_usermeta'] = '';
			}
			if ( ! array_key_exists( 'advanced_users_per_page', $auth_settings ) ) {
				$auth_settings['advanced_users_per_page'] = 20;
			}
			if ( ! array_key_exists( 'advanced_users_sort_by', $auth_settings ) ) {
				$auth_settings['advanced_users_sort_by'] = 'created';
			}
			if ( ! array_key_exists( 'advanced_users_sort_order', $auth_settings ) ) {
				$auth_settings['advanced_users_sort_order'] = 'asc';
			}
			if ( ! array_key_exists( 'advanced_widget_enabled', $auth_settings ) ) {
				$auth_settings['advanced_widget_enabled'] = '1';
			}
			if ( ! array_key_exists( 'advanced_override_multisite', $auth_settings ) ) {
				$auth_settings['advanced_override_multisite'] = '';
			}

			// Save default options to database.
			update_option( 'auth_settings', $auth_settings );
			update_option( 'auth_settings_access_users_pending', $auth_settings_access_users_pending );
			update_option( 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
			update_option( 'auth_settings_access_users_blocked', $auth_settings_access_users_blocked );

			// Multisite defaults.
			if ( is_multisite() ) {
				$auth_multisite_settings = get_blog_option( $this->current_site_blog_id, 'auth_multisite_settings', array() );

				if ( false === $auth_multisite_settings ) {
					$auth_multisite_settings = array();
				}
				// Global switch for enabling multisite options.
				if ( ! array_key_exists( 'multisite_override', $auth_multisite_settings ) ) {
					$auth_multisite_settings['multisite_override'] = '';
				}
				// Access Lists Defaults.
				$auth_multisite_settings_access_users_approved = get_blog_option( $this->current_site_blog_id, 'auth_multisite_settings_access_users_approved' );
				if ( false === $auth_multisite_settings_access_users_approved ) {
					$auth_multisite_settings_access_users_approved = array();
				}
				// Login Access Defaults.
				if ( ! array_key_exists( 'access_who_can_login', $auth_multisite_settings ) ) {
					$auth_multisite_settings['access_who_can_login'] = 'approved_users';
				}
				// View Access Defaults.
				if ( ! array_key_exists( 'access_who_can_view', $auth_multisite_settings ) ) {
					$auth_multisite_settings['access_who_can_view'] = 'everyone';
				}
				// External Service Defaults.
				if ( ! array_key_exists( 'access_default_role', $auth_multisite_settings ) ) {
					// Set default role to 'student' if that role exists, 'subscriber' otherwise.
					$all_roles      = $wp_roles->roles;
					$editable_roles = apply_filters( 'editable_roles', $all_roles );
					if ( array_key_exists( 'student', $editable_roles ) ) {
						$auth_multisite_settings['access_default_role'] = 'student';
					} else {
						$auth_multisite_settings['access_default_role'] = 'subscriber';
					}
				}
				if ( ! array_key_exists( 'google', $auth_multisite_settings ) ) {
					$auth_multisite_settings['google'] = '';
				}
				if ( ! array_key_exists( 'cas', $auth_multisite_settings ) ) {
					$auth_multisite_settings['cas'] = '';
				}
				if ( ! array_key_exists( 'ldap', $auth_multisite_settings ) ) {
					$auth_multisite_settings['ldap'] = '';
				}
				if ( ! array_key_exists( 'google_clientid', $auth_multisite_settings ) ) {
					$auth_multisite_settings['google_clientid'] = '';
				}
				if ( ! array_key_exists( 'google_clientsecret', $auth_multisite_settings ) ) {
					$auth_multisite_settings['google_clientsecret'] = '';
				}
				if ( ! array_key_exists( 'google_hosteddomain', $auth_multisite_settings ) ) {
					$auth_multisite_settings['google_hosteddomain'] = '';
				}
				if ( ! array_key_exists( 'cas_custom_label', $auth_multisite_settings ) ) {
					$auth_multisite_settings['cas_custom_label'] = 'CAS';
				}
				if ( ! array_key_exists( 'cas_host', $auth_multisite_settings ) ) {
					$auth_multisite_settings['cas_host'] = '';
				}
				if ( ! array_key_exists( 'cas_port', $auth_multisite_settings ) ) {
					$auth_multisite_settings['cas_port'] = '';
				}
				if ( ! array_key_exists( 'cas_path', $auth_multisite_settings ) ) {
					$auth_multisite_settings['cas_path'] = '';
				}
				if ( ! array_key_exists( 'cas_version', $auth_multisite_settings ) ) {
					$auth_multisite_settings['cas_version'] = 'SAML_VERSION_1_1';
				}
				if ( ! array_key_exists( 'cas_attr_email', $auth_multisite_settings ) ) {
					$auth_multisite_settings['cas_attr_email'] = '';
				}
				if ( ! array_key_exists( 'cas_attr_first_name', $auth_multisite_settings ) ) {
					$auth_multisite_settings['cas_attr_first_name'] = '';
				}
				if ( ! array_key_exists( 'cas_attr_last_name', $auth_multisite_settings ) ) {
					$auth_multisite_settings['cas_attr_last_name'] = '';
				}
				if ( ! array_key_exists( 'cas_attr_update_on_login', $auth_multisite_settings ) ) {
					$auth_multisite_settings['cas_attr_update_on_login'] = '';
				}
				if ( ! array_key_exists( 'cas_auto_login', $auth_multisite_settings ) ) {
					$auth_multisite_settings['cas_auto_login'] = '';
				}
				if ( ! array_key_exists( 'ldap_host', $auth_multisite_settings ) ) {
					$auth_multisite_settings['ldap_host'] = '';
				}
				if ( ! array_key_exists( 'ldap_port', $auth_multisite_settings ) ) {
					$auth_multisite_settings['ldap_port'] = '389';
				}
				if ( ! array_key_exists( 'ldap_tls', $auth_multisite_settings ) ) {
					$auth_multisite_settings['ldap_tls'] = '1';
				}
				if ( ! array_key_exists( 'ldap_search_base', $auth_multisite_settings ) ) {
					$auth_multisite_settings['ldap_search_base'] = '';
				}
				if ( ! array_key_exists( 'ldap_uid', $auth_multisite_settings ) ) {
					$auth_multisite_settings['ldap_uid'] = 'uid';
				}
				if ( ! array_key_exists( 'ldap_attr_email', $auth_multisite_settings ) ) {
					$auth_multisite_settings['ldap_attr_email'] = '';
				}
				if ( ! array_key_exists( 'ldap_user', $auth_multisite_settings ) ) {
					$auth_multisite_settings['ldap_user'] = '';
				}
				if ( ! array_key_exists( 'ldap_password', $auth_multisite_settings ) ) {
					$auth_multisite_settings['ldap_password'] = '';
				}
				if ( ! array_key_exists( 'ldap_lostpassword_url', $auth_multisite_settings ) ) {
					$auth_multisite_settings['ldap_lostpassword_url'] = '';
				}
				if ( ! array_key_exists( 'ldap_attr_first_name', $auth_multisite_settings ) ) {
					$auth_multisite_settings['ldap_attr_first_name'] = '';
				}
				if ( ! array_key_exists( 'ldap_attr_last_name', $auth_multisite_settings ) ) {
					$auth_multisite_settings['ldap_attr_last_name'] = '';
				}
				if ( ! array_key_exists( 'ldap_attr_update_on_login', $auth_multisite_settings ) ) {
					$auth_multisite_settings['ldap_attr_update_on_login'] = '';
				}
				// Advanced defaults.
				if ( ! array_key_exists( 'advanced_lockouts', $auth_multisite_settings ) ) {
					$auth_multisite_settings['advanced_lockouts'] = array(
						'attempts_1'     => 10,
						'duration_1'     => 1,
						'attempts_2'     => 10,
						'duration_2'     => 10,
						'reset_duration' => 120,
					);
				}
				if ( ! array_key_exists( 'advanced_hide_wp_login', $auth_multisite_settings ) ) {
					$auth_multisite_settings['advanced_hide_wp_login'] = '';
				}
				if ( ! array_key_exists( 'advanced_users_per_page', $auth_multisite_settings ) ) {
					$auth_multisite_settings['advanced_users_per_page'] = 20;
				}
				if ( ! array_key_exists( 'advanced_users_sort_by', $auth_multisite_settings ) ) {
					$auth_multisite_settings['advanced_users_sort_by'] = 'created';
				}
				if ( ! array_key_exists( 'advanced_users_sort_order', $auth_multisite_settings ) ) {
					$auth_multisite_settings['advanced_users_sort_order'] = 'asc';
				}
				if ( ! array_key_exists( 'advanced_widget_enabled', $auth_multisite_settings ) ) {
					$auth_multisite_settings['advanced_widget_enabled'] = '1';
				}
				// Save default network options to database.
				update_blog_option( $this->current_site_blog_id, 'auth_multisite_settings', $auth_multisite_settings );
				update_blog_option( $this->current_site_blog_id, 'auth_multisite_settings_access_users_approved', $auth_multisite_settings_access_users_approved );
			}

			return $auth_settings;
		}


		/**
		 * List sanitizer.
		 *
		 * @param  array  $list           Array of users to sanitize.
		 * @param  string $side_effect    Set to 'update roles' if role syncing should be performed.
		 * @param  string $multisite_mode Set to 'multisite' to sync roles on all sites the user belongs to.
		 * @return array                  Array of sanitized users.
		 */
		private function sanitize_user_list( $list, $side_effect = 'none', $multisite_mode = 'single' ) {
			// If it's not a list, make it so.
			if ( ! is_array( $list ) ) {
				$list = array();
			}
			foreach ( $list as $key => $user_info ) {
				if ( strlen( $user_info['email'] ) < 1 ) {
					// Make sure there are no empty entries in the list.
					unset( $list[ $key ] );
				} elseif ( 'update roles' === $side_effect ) {
					// Make sure the WordPress user accounts have the same role
					// as that indicated in the list.
					$wp_user = get_user_by( 'email', $user_info['email'] );
					if ( $wp_user ) {
						if ( is_multisite() && 'multisite' === $multisite_mode ) {
							foreach ( get_blogs_of_user( $wp_user->ID ) as $blog ) {
								add_user_to_blog( $blog->userblog_id, $wp_user->ID, $user_info['role'] );
							}
						} else {
							$wp_user->set_role( $user_info['role'] );
						}
					}
				}
			}
			return $list;
		}


		/**
		 * Settings sanitizer callback.
		 *
		 * @param  array $auth_settings Authorizer settings array.
		 * @return array                Sanitized Authorizer settings array.
		 */
		public function sanitize_options( $auth_settings ) {
			// Default to "Approved Users" login access restriction.
			if ( ! in_array( $auth_settings['access_who_can_login'], array( 'external_users', 'approved_users' ), true ) ) {
				$auth_settings['access_who_can_login'] = 'approved_users';
			}

			// Default to "Everyone" view access restriction.
			if ( ! in_array( $auth_settings['access_who_can_view'], array( 'everyone', 'logged_in_users' ), true ) ) {
				$auth_settings['access_who_can_view'] = 'everyone';
			}

			// Default to WordPress login access redirect.
			// Note: this option doesn't exist in multisite options, so we first
			// check to see if it exists.
			if ( array_key_exists( 'access_redirect', $auth_settings ) && ! in_array( $auth_settings['access_redirect'], array( 'login', 'page', 'message' ), true ) ) {
				$auth_settings['access_redirect'] = 'login';
			}

			// Default to warning message for anonymous users on public pages.
			// Note: this option doesn't exist in multisite options, so we first
			// check to see if it exists.
			if ( array_key_exists( 'access_public_warning', $auth_settings ) && ! in_array( $auth_settings['access_public_warning'], array( 'no_warning', 'warning' ), true ) ) {
				$auth_settings['access_public_warning'] = 'no_warning';
			}

			// Sanitize Send welcome email (checkbox: value can only be '1' or empty string).
			$auth_settings['access_should_email_approved_users'] = array_key_exists( 'access_should_email_approved_users', $auth_settings ) && strlen( $auth_settings['access_should_email_approved_users'] ) > 0 ? '1' : '';

			// Sanitize Enable Google Logins (checkbox: value can only be '1' or empty string).
			$auth_settings['google'] = array_key_exists( 'google', $auth_settings ) && strlen( $auth_settings['google'] ) > 0 ? '1' : '';

			// Sanitize Enable CAS Logins (checkbox: value can only be '1' or empty string).
			$auth_settings['cas'] = array_key_exists( 'cas', $auth_settings ) && strlen( $auth_settings['cas'] ) > 0 ? '1' : '';

			// Sanitize CAS Host setting.
			$auth_settings['cas_host'] = filter_var( $auth_settings['cas_host'], FILTER_SANITIZE_URL );

			// Sanitize CAS Port (int).
			$auth_settings['cas_port'] = filter_var( $auth_settings['cas_port'], FILTER_SANITIZE_NUMBER_INT );

			// Sanitize CAS attribute update (checkbox: value can only be '1' or empty string).
			$auth_settings['cas_attr_update_on_login'] = array_key_exists( 'cas_attr_update_on_login', $auth_settings ) && strlen( $auth_settings['cas_attr_update_on_login'] ) > 0 ? '1' : '';

			// Sanitize CAS auto-login (checkbox: value can only be '1' or empty string).
			$auth_settings['cas_auto_login'] = array_key_exists( 'cas_auto_login', $auth_settings ) && strlen( $auth_settings['cas_auto_login'] ) > 0 ? '1' : '';

			// Sanitize Enable LDAP Logins (checkbox: value can only be '1' or empty string).
			$auth_settings['ldap'] = array_key_exists( 'ldap', $auth_settings ) && strlen( $auth_settings['ldap'] ) > 0 ? '1' : '';

			// Sanitize LDAP Host setting.
			$auth_settings['ldap_host'] = filter_var( $auth_settings['ldap_host'], FILTER_SANITIZE_URL );

			// Sanitize LDAP Port (int).
			$auth_settings['ldap_port'] = filter_var( $auth_settings['ldap_port'], FILTER_SANITIZE_NUMBER_INT );

			// Sanitize LDAP TLS (checkbox: value can only be '1' or empty string).
			$auth_settings['ldap_tls'] = array_key_exists( 'ldap_tls', $auth_settings ) && strlen( $auth_settings['ldap_tls'] ) > 0 ? '1' : '';

			// Sanitize LDAP attributes (basically make sure they don't have any parentheses).
			$auth_settings['ldap_uid'] = filter_var( $auth_settings['ldap_uid'], FILTER_SANITIZE_EMAIL );

			// Sanitize LDAP Lost Password URL.
			$auth_settings['ldap_lostpassword_url'] = filter_var( $auth_settings['ldap_lostpassword_url'], FILTER_SANITIZE_URL );

			// Obfuscate LDAP directory user password.
			if ( strlen( $auth_settings['ldap_password'] ) > 0 ) {
				// encrypt the directory user password for some minor obfuscation in the database.
				$auth_settings['ldap_password'] = $this->encrypt( $auth_settings['ldap_password'] );
			}

			// Sanitize LDAP attribute update (checkbox: value can only be '1' or empty string).
			$auth_settings['ldap_attr_update_on_login'] = array_key_exists( 'ldap_attr_update_on_login', $auth_settings ) && strlen( $auth_settings['ldap_attr_update_on_login'] ) > 0 ? '1' : '';

			// Make sure public pages is an empty array if it's empty.
			// Note: this option doesn't exist in multisite options, so we first
			// check to see if it exists.
			if ( array_key_exists( 'access_public_pages', $auth_settings ) && ! is_array( $auth_settings['access_public_pages'] ) ) {
				$auth_settings['access_public_pages'] = array();
			}

			// Make sure all lockout options are integers (attempts_1,
			// duration_1, attempts_2, duration_2, reset_duration).
			foreach ( $auth_settings['advanced_lockouts'] as $key => $value ) {
				$auth_settings['advanced_lockouts'][ $key ] = filter_var( $value, FILTER_SANITIZE_NUMBER_INT );
			}

			// Sanitize Hide WordPress logins (checkbox: value can only be '1' or empty string).
			$auth_settings['advanced_hide_wp_login'] = array_key_exists( 'advanced_hide_wp_login', $auth_settings ) && strlen( $auth_settings['advanced_hide_wp_login'] ) > 0 ? '1' : '';

			// Sanitize Users per page (text: value can only int from 1 to MAX_INT).
			$auth_settings['advanced_users_per_page'] = array_key_exists( 'advanced_users_per_page', $auth_settings ) && intval( $auth_settings['advanced_users_per_page'] ) > 0 ? intval( $auth_settings['advanced_users_per_page'] ) : 1;

			// Sanitize Sort users by (select: value can be 'email', 'role', 'date_added', 'created').
			if ( ! isset( $auth_settings['advanced_users_sort_by'] ) || ! in_array( $auth_settings['advanced_users_sort_by'], array( 'email', 'role', 'date_added', 'created' ), true ) ) {
				$auth_settings['advanced_users_sort_by'] = 'created';
			}

			// Sanitize Sort users order (select: value can be 'asc', 'desc').
			if ( ! isset( $auth_settings['advanced_users_sort_order'] ) || ! in_array( $auth_settings['advanced_users_sort_order'], array( 'asc', 'desc' ), true ) ) {
				$auth_settings['advanced_users_sort_order'] = 'asc';
			}

			// Sanitize Show Dashboard Widget (checkbox: value can only be '1' or empty string).
			$auth_settings['advanced_widget_enabled'] = array_key_exists( 'advanced_widget_enabled', $auth_settings ) && strlen( $auth_settings['advanced_widget_enabled'] ) > 0 ? '1' : '';

			// Sanitize Override multisite options (checkbox: value can only be '1' or empty string).
			$auth_settings['advanced_override_multisite'] = array_key_exists( 'advanced_override_multisite', $auth_settings ) && strlen( $auth_settings['advanced_override_multisite'] ) > 0 ? '1' : '';

			return $auth_settings;
		}


		/**
		 * Keep authorizer approved users' roles in sync with WordPress roles
		 * if someone changes the role via the WordPress Edit User page
		 * (wp-admin/user-edit.php or wp-admin/profile.php).
		 *
		 * Action: user_profile_update_errors
		 *
		 * @param WP_Error $errors Errors object to add any custom errors to (passed by reference).
		 * @param bool     $update True if updating existing user, false if saving a new one.
		 * @param stdClass $user   Updated WP_User object for user being edited (passed by reference).
		 */
		public function edit_user_profile_update_role( &$errors, $update, &$user ) {
			// Do nothing if we're not updating role.
			if ( ! property_exists( $user, 'role' ) ) {
				return;
			}

			// Safety check; will likely not fire if we reach this function.
			if ( ! current_user_can( 'edit_user', $user->ID ) ) {
				return;
			}

			// Don't perform Authorizer updates if we have a WordPress error.
			$errors_on_user_update = $errors->get_error_codes();
			if ( ! empty( $errors_on_user_update ) ) {
				return;
			}

			// Get original user object (fail if not a real WordPress user).
			$userdata = get_userdata( $user->ID );
			if ( ! $userdata ) {
				return;
			}

			// If user is in approved list, update his/her associated role.
			if ( $this->is_email_in_list( $userdata->user_email, 'approved' ) ) {
				$auth_settings_access_users_approved = $this->sanitize_user_list( $this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::SINGLE_CONTEXT ) );
				foreach ( $auth_settings_access_users_approved as $key => $check_user ) {
					if ( 0 === strcasecmp( $check_user['email'], $userdata->user_email ) ) {
						$auth_settings_access_users_approved[ $key ]['role'] = $user->role;
					}
				}
				update_option( 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
			}
		}


		/**
		 * Sync any email address changes to WordPress accounts to the corresponding
		 * entry in the Authorizer approved list.
		 *
		 * Note: This filter fires in wp_update_user() if the update includes an
		 * email address change, and fires after all security and integrity checks
		 * have been performed, so we can simply update the Authorizer approved
		 * list, changing the email address on the approved entry, and removing any
		 * existing entries that also have the new email address (duplicates).
		 *
		 * Filter: send_email_change_email
		 *
		 * @param bool  $send     Whether to send the email.
		 * @param array $user     The original user array.
		 * @param array $userdata The updated user array.
		 */
		public function edit_user_profile_update_email( $send, $user, $userdata ) {
			// If we're in multisite, update the email on all sites in the network
			// (and remove from any subsites if it's a network-approved user).
			if ( is_multisite() ) {
				// If it's a multisite approved user, sync the email there.
				$changed_user_is_multisite_user = false;
				if ( $this->is_email_in_list( $user['user_email'], 'approved', 'multisite' ) ) {
					$changed_user_is_multisite_user                = true;
					$auth_multisite_settings_access_users_approved = $this->sanitize_user_list(
						$this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::NETWORK_CONTEXT )
					);
					foreach ( $auth_multisite_settings_access_users_approved as $key => $check_user ) {
						// Update old user email in approved list to the new email.
						if ( 0 === strcasecmp( $check_user['email'], $user['user_email'] ) ) {
							$auth_multisite_settings_access_users_approved[ $key ]['email'] = $this->lowercase( $userdata['user_email'] );
						}
						// If new user email is already in approved list, remove that entry.
						if ( 0 === strcasecmp( $check_user['email'], $userdata['user_email'] ) ) {
							unset( $auth_multisite_settings_access_users_approved[ $key ] );
						}
					}
					update_blog_option( $this->current_site_blog_id, 'auth_multisite_settings_access_users_approved', $auth_multisite_settings_access_users_approved );
				}

				// Go through all approved lists on individual sites and sync this user there.
				// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
				$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
				foreach ( $sites as $site ) {
					$updated                             = false;
					$blog_id                             = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
					$auth_settings_access_users_approved = get_blog_option( $blog_id, 'auth_settings_access_users_approved', array() );
					foreach ( $auth_settings_access_users_approved as $key => $check_user ) {
						// Update old user email in approved list to the new email.
						if ( 0 === strcasecmp( $check_user['email'], $user['user_email'] ) ) {
							// But if the user is already a multisite user, just remove the entry in the subsite.
							if ( $changed_user_is_multisite_user ) {
								unset( $auth_settings_access_users_approved[ $key ] );
							} else {
								$auth_settings_access_users_approved[ $key ]['email'] = $this->lowercase( $userdata['user_email'] );
							}
							$updated = true;
						}
						// If new user email is already in approved list, remove that entry.
						if ( 0 === strcasecmp( $check_user['email'], $userdata['user_email'] ) ) {
							unset( $auth_settings_access_users_approved[ $key ] );
							$updated = true;
						}
					}
					if ( $updated ) {
						update_blog_option( $blog_id, 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
					}
				}
			} else {
				// In a single site environment, just find the old user in the approved list and update the email.
				if ( $this->is_email_in_list( $user['user_email'], 'approved' ) ) {
					$auth_settings_access_users_approved = $this->sanitize_user_list( $this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::SINGLE_CONTEXT ) );
					foreach ( $auth_settings_access_users_approved as $key => $check_user ) {
						// Update old user email in approved list to the new email.
						if ( 0 === strcasecmp( $check_user['email'], $user['user_email'] ) ) {
							$auth_settings_access_users_approved[ $key ]['email'] = $this->lowercase( $userdata['user_email'] );
						}
						// If new user email is already in approved list, remove that entry.
						if ( 0 === strcasecmp( $check_user['email'], $userdata['user_email'] ) ) {
							unset( $auth_settings_access_users_approved[ $key ] );
						}
					}
					update_option( 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
				}
			}

			// We're hooking into this filter merely for its location in the codebase,
			// so make sure to return the filter value unmodified.
			return $send;
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_section_info_tabs( $args = '' ) {
			if ( WP_Plugin_Authorizer::NETWORK_CONTEXT === $this->get_admin_mode( $args ) ) :
				?>
				<h2 class="nav-tab-wrapper">
					<a class="nav-tab nav-tab-access_lists nav-tab-active" href="javascript:chooseTab('access_lists' );"><?php esc_html_e( 'Access Lists', 'authorizer' ); ?></a>
					<a class="nav-tab nav-tab-external" href="javascript:chooseTab('external' );"><?php esc_html_e( 'External Service', 'authorizer' ); ?></a>
					<a class="nav-tab nav-tab-advanced" href="javascript:chooseTab('advanced' );"><?php esc_html_e( 'Advanced', 'authorizer' ); ?></a>
				</h2>
			<?php else : ?>
				<h2 class="nav-tab-wrapper">
					<a class="nav-tab nav-tab-access_lists nav-tab-active" href="javascript:chooseTab('access_lists' );"><?php esc_html_e( 'Access Lists', 'authorizer' ); ?></a>
					<a class="nav-tab nav-tab-access_login" href="javascript:chooseTab('access_login' );"><?php esc_html_e( 'Login Access', 'authorizer' ); ?></a>
					<a class="nav-tab nav-tab-access_public" href="javascript:chooseTab('access_public' );"><?php esc_html_e( 'Public Access', 'authorizer' ); ?></a>
					<a class="nav-tab nav-tab-external" href="javascript:chooseTab('external' );"><?php esc_html_e( 'External Service', 'authorizer' ); ?></a>
					<a class="nav-tab nav-tab-advanced" href="javascript:chooseTab('advanced' );"><?php esc_html_e( 'Advanced', 'authorizer' ); ?></a>
				</h2>
			<?php
			endif;
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_section_info_access_lists( $args = '' ) {
			$admin_mode = $this->get_admin_mode( $args );
			?>
			<div id="section_info_access_lists" class="section_info">
				<p><?php esc_html_e( 'Manage who has access to this site using these lists.', 'authorizer' ); ?></p>
				<ol>
					<li><?php echo wp_kses( __( "<strong>Pending</strong> users are users who have successfully logged in to the site, but who haven't yet been approved (or blocked) by you.", 'authorizer' ), $this->allowed_html ); ?></li>
					<li><?php echo wp_kses( __( '<strong>Approved</strong> users have access to the site once they successfully log in.', 'authorizer' ), $this->allowed_html ); ?></li>
					<li><?php echo wp_kses( __( '<strong>Blocked</strong> users will receive an error message when they try to visit the site after authenticating.', 'authorizer' ), $this->allowed_html ); ?><br><?php esc_html_e( 'Note: if you want to block all email addresses from a domain, say anyone@example.com, simply add "@example.com" to the blocked list.', 'authorizer' ); ?></li>
				</ol>
			</div>
			<table class="form-table">
				<tbody>
					<tr>
						<th scope="row"><?php esc_html_e( 'Pending Users', 'authorizer' ); ?> <em>(<?php echo esc_html( $this->get_user_count_from_list( 'pending', $admin_mode ) ); ?>)</em></th>
						<td><?php $this->print_combo_auth_access_users_pending(); ?></td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Approved Users', 'authorizer' ); ?> <em>(<?php echo esc_html( $this->get_user_count_from_list( 'approved', $admin_mode ) ); ?>)</em></th>
						<td><?php $this->print_combo_auth_access_users_approved(); ?></td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Blocked Users', 'authorizer' ); ?> <em>(<?php echo esc_html( $this->get_user_count_from_list( 'blocked', $admin_mode ) ); ?>)</em></th>
						<td><?php $this->print_combo_auth_access_users_blocked(); ?></td>
					</tr>
				</tbody>
			</table>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_combo_auth_access_users_pending( $args = '' ) {
			// Get plugin option.
			$option               = 'access_users_pending';
			$auth_settings_option = $this->get_plugin_option( $option );
			$auth_settings_option = is_array( $auth_settings_option ) ? $auth_settings_option : array();

			// Render wrapper div (for aligning pager to width of content).
			?>
			<div class="wrapper_<?php echo esc_attr( $option ); ?>">
				<ul id="list_auth_settings_access_users_pending" style="margin:0;">
					<?php
					if ( count( $auth_settings_option ) > 0 ) :
						foreach ( $auth_settings_option as $key => $pending_user ) :
							if ( empty( $pending_user ) || count( $pending_user ) < 1 ) :
								continue;
							endif;
							$pending_user['is_wp_user'] = false;
							?>
							<li>
								<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>_<?php echo esc_attr( $key ); ?>" value="<?php echo esc_attr( $pending_user['email'] ); ?>" readonly="true" class="auth-email" />
								<select id="auth_settings_<?php echo esc_attr( $option ); ?>_<?php echo esc_attr( $key ); ?>_role" class="auth-role">
									<?php $this->wp_dropdown_permitted_roles( $pending_user['role'] ); ?>
								</select>
								<a href="javascript:void(0);" class="button-primary" id="approve_user_<?php echo esc_attr( $key ); ?>" onclick="authAddUser( this, 'approved', false ); authIgnoreUser( this, 'pending' );"><span class="glyphicon glyphicon-ok"></span> <?php esc_html_e( 'Approve', 'authorizer' ); ?></a>
								<a href="javascript:void(0);" class="button-primary" id="block_user_<?php echo esc_attr( $key ); ?>" onclick="authAddUser( this, 'blocked', false ); authIgnoreUser( this, 'pending' );"><span class="glyphicon glyphicon-ban-circle"></span> <?php esc_html_e( 'Block', 'authorizer' ); ?></a>
								<a href="javascript:void(0);" class="button button-secondary" id="ignore_user_<?php echo esc_attr( $key ); ?>" onclick="authIgnoreUser( this, 'pending' );" title="<?php esc_html_e( 'Remove user', 'authorizer' ); ?>"><span class="glyphicon glyphicon-remove"></span> <?php esc_html_e( 'Ignore', 'authorizer' ); ?></a>
							</li>
						<?php endforeach; ?>
					<?php else : ?>
							<li class="auth-empty"><em><?php esc_html_e( 'No pending users', 'authorizer' ); ?></em></li>
					<?php endif; ?>
				</ul>
			</div>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_combo_auth_access_users_approved( $args = '' ) {
			// Get plugin option.
			$option               = 'access_users_approved';
			$admin_mode           = $this->get_admin_mode( $args );
			$auth_settings_option = $this->get_plugin_option( $option, $admin_mode, 'no override' );
			$auth_settings_option = is_array( $auth_settings_option ) ? $auth_settings_option : array();

			// Get multisite approved users (will be added to top of list, greyed out).
			$auth_override_multisite        = $this->get_plugin_option( 'advanced_override_multisite' );
			$auth_multisite_settings        = $this->get_plugin_options( WP_Plugin_Authorizer::NETWORK_CONTEXT );
			$auth_settings_option_multisite = array();
			if (
				is_multisite() &&
				! is_network_admin() &&
				'1' !== intval( $auth_override_multisite ) &&
				array_key_exists( 'multisite_override', $auth_multisite_settings ) &&
				'1' === $auth_multisite_settings['multisite_override']
			) {
				$auth_settings_option_multisite = $this->get_plugin_option( $option, WP_Plugin_Authorizer::NETWORK_CONTEXT, 'allow override' );
				$auth_settings_option_multisite = is_array( $auth_settings_option_multisite ) ? $auth_settings_option_multisite : array();
				// Add multisite users to the beginning of the main user array.
				foreach ( array_reverse( $auth_settings_option_multisite ) as $approved_user ) {
					$approved_user['multisite_user'] = true;
					array_unshift( $auth_settings_option, $approved_user );
				}
			}

			// Get default role for new user dropdown.
			$access_default_role = $this->get_plugin_option( 'access_default_role', WP_Plugin_Authorizer::SINGLE_CONTEXT, 'allow override' );

			// Get custom usermeta field to show.
			$advanced_usermeta = $this->get_plugin_option( 'advanced_usermeta' );

			// Adjust javascript function prefixes if multisite.
			$js_function_prefix      = WP_Plugin_Authorizer::NETWORK_CONTEXT === $admin_mode ? 'authMultisite' : 'auth';
			$is_multisite_admin_page = WP_Plugin_Authorizer::NETWORK_CONTEXT === $admin_mode;

			// Filter user list to search terms.
			// phpcs:ignore WordPress.CSRF.NonceVerification.NoNonceVerification
			if ( isset( $_REQUEST['search'] ) && strlen( sanitize_text_field( wp_unslash( $_REQUEST['search'] ) ) ) > 0 ) {
				// phpcs:ignore WordPress.CSRF.NonceVerification.NoNonceVerification
				$search_term          = sanitize_text_field( wp_unslash( $_REQUEST['search'] ) );
				$auth_settings_option = array_filter(
					$auth_settings_option, function ( $user ) use ( $search_term ) {
						return stripos( $user['email'], $search_term ) !== false ||
						stripos( $user['role'], $search_term ) !== false ||
						stripos( $user['date_added'], $search_term ) !== false;
					}
				);
			}

			// Sort user list.
			$sort_by        = $this->get_plugin_option( 'advanced_users_sort_by', WP_Plugin_Authorizer::SINGLE_CONTEXT, 'allow override' ); // email, role, date_added (registered), created (date approved).
			$sort_order     = $this->get_plugin_option( 'advanced_users_sort_order', WP_Plugin_Authorizer::SINGLE_CONTEXT, 'allow override' ); // asc or desc.
			$sort_dimension = array();
			if ( in_array( $sort_by, array( 'email', 'role', 'date_added' ), true ) ) {
				foreach ( $auth_settings_option as $key => $user ) {
					if ( 'date_added' === $sort_by ) {
						$sort_dimension[ $key ] = date( 'Ymd', strtotime( $user[ $sort_by ] ) );
					} else {
						$sort_dimension[ $key ] = strtolower( $user[ $sort_by ] );
					}
				}
				$sort_order = 'asc' === $sort_order ? SORT_ASC : SORT_DESC;
				array_multisort( $sort_dimension, $sort_order, $auth_settings_option );
			} elseif ( 'created' === $sort_by && 'asc' !== $sort_order ) {
				// If default sort method and reverse order, just reverse the array.
				$auth_settings_option = array_reverse( $auth_settings_option );
			}

			// Ensure array keys run from 0..max (keys in database will be the original,
			// index, and removing users will not reorder the array keys of other users).
			$auth_settings_option = array_values( $auth_settings_option );

			// Get pager params.
			$total_users    = count( $auth_settings_option );
			$users_per_page = intval( $this->get_plugin_option( 'advanced_users_per_page', WP_Plugin_Authorizer::SINGLE_CONTEXT, 'allow override' ) );
			// phpcs:ignore WordPress.CSRF.NonceVerification.NoNonceVerification
			$current_page = isset( $_REQUEST['paged'] ) ? intval( $_REQUEST['paged'] ) : 1;
			$total_pages  = ceil( $total_users / $users_per_page );
			if ( $total_pages < 1 ) {
				$total_pages = 1;
			}

			// Make sure current_page is between 1 and max pages.
			if ( $current_page < 1 ) {
				$current_page = 1;
			} elseif ( $current_page > $total_pages ) {
				$current_page = $total_pages;
			}

			// Render wrapper div (for aligning pager to width of content).
			?>
			<div class="wrapper_<?php echo esc_attr( $option ); ?>">
				<?php $this->render_user_pager( $current_page, $users_per_page, $total_users, 'top' ); ?>
				<ul id="list_auth_settings_access_users_approved" class="<?php echo strlen( $advanced_usermeta ) > 0 ? 'has-usermeta' : ''; ?>">
					<?php
					$offset = ( $current_page - 1 ) * $users_per_page;
					$max    = min( $offset + $users_per_page, count( $auth_settings_option ) );
					for ( $key = $offset; $key < $max; $key++ ) :
						$approved_user = $auth_settings_option[ $key ];
						if ( empty( $approved_user ) || count( $approved_user ) < 1 ) :
							continue;
						endif;
						$this->render_user_element( $approved_user, $key, $option, $admin_mode, $advanced_usermeta );
					endfor;
					?>
				</ul>

				<div id="new_auth_settings_<?php echo esc_attr( $option ); ?>">
					<textarea id="new_approved_user_email" placeholder="<?php esc_attr_e( 'email address', 'authorizer' ); ?>" class="auth-email new autogrow-short" rows="1"></textarea>
					<select id="new_approved_user_role" class="auth-role">
						<?php $this->wp_dropdown_permitted_roles( $access_default_role, 'not disabled', $admin_mode ); ?>
					</select>
					<div class="btn-group">
						<a href="javascript:void(0);" class="btn button-primary dropdown-toggle button-add-user" id="approve_user_new" onclick="<?php echo esc_attr( $js_function_prefix ); ?>AddUser(this, 'approved' );"><span class="glyphicon glyphicon-ok"></span> <?php esc_html_e( 'Approve', 'authorizer' ); ?></a>
						<button type="button" class="btn button-primary dropdown-toggle" data-toggle="dropdown">
							<span class="caret"></span>
							<span class="sr-only"><?php esc_html_e( 'Toggle Dropdown', 'authorizer' ); ?></span>
						</button>
						<ul class="dropdown-menu" role="menu">
							<li><a href="javascript:void(0);" onclick="<?php echo esc_attr( $js_function_prefix ); ?>AddUser( document.getElementById( 'approve_user_new' ), 'approved', true);"><?php esc_html_e( 'Create a local WordPress account instead, and email the user their password.', 'authorizer' ); ?></a></li>
						</ul>
					</div>
				</div>
				<?php $this->render_user_pager( $current_page, $users_per_page, $total_users, 'bottom' ); ?>
			</div>
			<?php
		}


		/**
		 * Renders the html elements for the pager above and below the Approved User list.
		 *
		 * @param  integer $current_page   Which page we are currently viewing.
		 * @param  integer $users_per_page How many users to show per page.
		 * @param  integer $total_users    Total count of users in list.
		 * @param  string  $which          Where to render the pager ('top' or 'bottom').
		 * @return void
		 */
		private function render_user_pager( $current_page = 1, $users_per_page = 20, $total_users = 0, $which = 'top' ) {
			$total_pages = ceil( $total_users / $users_per_page );
			if ( $total_pages < 1 ) {
				$total_pages = 1;
			}

			/* TRANSLATORS: %s: number of users */
			$output = ' <span class="displaying-num">' . sprintf( _n( '%s user', '%s users', $total_users, 'authorizer' ), number_format_i18n( $total_users ) ) . '</span>';

			$disable_first = $current_page <= 1;
			$disable_prev  = $current_page <= 1;
			$disable_next  = $current_page >= $total_pages;
			$disable_last  = $current_page >= $total_pages;

			$current_url = '';
			if ( isset( $_SERVER['HTTP_HOST'], $_SERVER['REQUEST_URI'] ) ) {
				$current_url = set_url_scheme( esc_url_raw( wp_unslash( $_SERVER['HTTP_HOST'] ) ) . esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) );
				$current_url = remove_query_arg( wp_removable_query_args(), $current_url );
			}

			$page_links = array();

			$total_pages_before = '<span class="paging-input">';
			$total_pages_after  = '</span></span>';

			if ( $disable_first ) {
				$page_links[] = '<span class="first-page tablenav-pages-navspan" aria-hidden="true">&laquo;</span>';
			} else {
				$page_links[] = sprintf(
					"<a class='first-page' href='%s'><span class='screen-reader-text'>%s</span><span aria-hidden='true'>%s</span></a>",
					esc_url( remove_query_arg( 'paged', $current_url ) ),
					__( 'First page' ),
					'&laquo;'
				);
			}

			if ( $disable_prev ) {
				$page_links[] = '<span class="prev-page tablenav-pages-navspan" aria-hidden="true">&lsaquo;</span>';
			} else {
				$page_links[] = sprintf(
					"<a class='prev-page' href='%s'><span class='screen-reader-text'>%s</span><span aria-hidden='true'>%s</span></a>",
					esc_url( add_query_arg( 'paged', max( 1, $current_page - 1 ), $current_url ) ),
					__( 'Previous page' ),
					'&lsaquo;'
				);
			}

			if ( 'bottom' === $which ) {
				$html_current_page  = '<span class="current-page-text">' . $current_page . '</span>';
				$total_pages_before = '<span class="screen-reader-text">' . __( 'Current Page' ) . '</span><span id="table-paging" class="paging-input"><span class="tablenav-paging-text">';
			} else {
				$html_current_page = sprintf(
					"%s<input class='current-page' id='current-page-selector' type='text' name='paged' value='%s' size='%d' aria-describedby='table-paging' /><span class='tablenav-paging-text'>",
					'<label for="current-page-selector" class="screen-reader-text">' . __( 'Current Page' ) . '</label>',
					$current_page,
					strlen( $total_pages )
				);
			}
			/* TRANSLATORS: %s: number of pages */
			$html_total_pages = sprintf( "<span class='total-pages'>%s</span>", number_format_i18n( $total_pages ) );
			/* TRANSLATORS: 1: number of current page 2: number of total pages */
			$page_links[] = $total_pages_before . sprintf( _x( '%1$s of %2$s', 'paging' ), $html_current_page, $html_total_pages ) . $total_pages_after;

			if ( $disable_next ) {
				$page_links[] = '<span class="next-page tablenav-pages-navspan" aria-hidden="true">&rsaquo;</span>';
			} else {
				$page_links[] = sprintf(
					"<a class='next-page' href='%s'><span class='screen-reader-text'>%s</span><span aria-hidden='true'>%s</span></a>",
					esc_url( add_query_arg( 'paged', min( $total_pages, $current_page + 1 ), $current_url ) ),
					__( 'Next page' ),
					'&rsaquo;'
				);
			}

			if ( $disable_last ) {
				$page_links[] = '<span class="last-page tablenav-pages-navspan" aria-hidden="true">&raquo;</span>';
			} else {
				$page_links[] = sprintf(
					"<a class='last-page' href='%s'><span class='screen-reader-text'>%s</span><span aria-hidden='true'>%s</span></a>",
					esc_url( add_query_arg( 'paged', $total_pages, $current_url ) ),
					__( 'Last page' ),
					'&raquo;'
				);
			}

			$pagination_links_class = 'pagination-links';
			$output                .= "\n<span class='$pagination_links_class'>" . join( "\n", $page_links ) . '</span>';

			$search_form = array();
			if ( 'top' === $which ) {
				// phpcs:ignore WordPress.CSRF.NonceVerification.NoNonceVerification
				$search_term   = isset( $_REQUEST['search'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['search'] ) ) : '';
				$search_form[] = '<div class="search-box">';
				$search_form[] = '<label class="screen-reader-text" for="user-search-input">' . __( 'Search Users', 'authorizer' ) . '</label>';
				$search_form[] = '<input type="search" size="14" id="user-search-input" name="search" value="' . $search_term . '">';
				$search_form[] = '<input type="button" id="search-submit" class="button" value="' . __( 'Search', 'authorizer' ) . '">';
				$search_form[] = '</div>';
			}
			$search_form = join( "\n", $search_form );

			$output = "<div class='tablenav-pages'>$output</div>";
			?>
			<div class="tablenav top">
				<?php echo wp_kses( $output, $this->allowed_html ); ?>
				<?php echo wp_kses( $search_form, $this->allowed_html ); ?>
			</div>
			<?php
		}


		/**
		 * Renders the html <li> element for a given user in a list.
		 *
		 * @param array  $approved_user     User array to render.
		 * @param int    $key               Index of user in list of users.
		 * @param string $option            List user is in (e.g., 'access_users_approved').
		 * @param string $admin_mode        Current admin context.
		 * @param string $advanced_usermeta Usermeta field to display.
		 * @return void
		 */
		private function render_user_element( $approved_user, $key, $option, $admin_mode, $advanced_usermeta ) {
			$is_local_user     = array_key_exists( 'local_user', $approved_user ) && 'true' === $approved_user['local_user'];
			$is_multisite_user = array_key_exists( 'multisite_user', $approved_user ) && true === $approved_user['multisite_user'];
			$option_prefix     = $is_multisite_user ? 'auth_multisite_settings_' : 'auth_settings_';
			$option_id         = $option_prefix . $option . '_' . $key;
			$approved_wp_user  = get_user_by( 'email', $approved_user['email'] );
			$is_current_user   = $approved_wp_user && get_current_user_id() === $approved_wp_user->ID;

			// Adjust javascript function prefixes if multisite.
			$js_function_prefix      = WP_Plugin_Authorizer::NETWORK_CONTEXT === $admin_mode ? 'authMultisite' : 'auth';
			$is_multisite_admin_page = WP_Plugin_Authorizer::NETWORK_CONTEXT === $admin_mode;

			if ( ! $approved_wp_user ) :
				$approved_user['is_wp_user'] = false;
			else :
				$approved_user['is_wp_user'] = true;
				$approved_user['email']      = $approved_wp_user->user_email;
				$approved_user['role']       = $is_multisite_admin_page || count( $approved_wp_user->roles ) === 0 ? $approved_user['role'] : array_shift( $approved_wp_user->roles );
				$approved_user['date_added'] = $approved_wp_user->user_registered;

				// Get usermeta field from the WordPress user's real usermeta.
				if ( strlen( $advanced_usermeta ) > 0 ) :
					if ( strpos( $advanced_usermeta, 'acf___' ) === 0 && class_exists( 'acf' ) ) :
						// Get ACF Field value for the user.
						$approved_user['usermeta'] = get_field( str_replace( 'acf___', '', $advanced_usermeta ), 'user_' . $approved_wp_user->ID );
					else :
						// Get regular usermeta value for the user.
						$approved_user['usermeta'] = get_user_meta( $approved_wp_user->ID, $advanced_usermeta, true );
					endif;
					if ( is_array( $approved_user['usermeta'] ) || is_object( $approved_user['usermeta'] ) ) :
						$approved_user['usermeta'] = serialize( $approved_user['usermeta'] );
					endif;
				endif;
			endif;
			if ( ! array_key_exists( 'usermeta', $approved_user ) ) :
				$approved_user['usermeta'] = '';
			endif;
			?>
			<li>
				<input
					type="text"
					id="<?php echo esc_attr( $option_id ); ?>"
					value="<?php echo esc_attr( $approved_user['email'] ); ?>"
					readonly="true"
					class="<?php echo esc_attr( $this->create_class_name( 'email', $is_multisite_user ) ); ?>"
				/>
				<select
					id="<?php echo esc_attr( $option_id ); ?>_role"
					class="<?php echo esc_attr( $this->create_class_name( 'role', $is_multisite_user ) ); ?>"
					onchange="<?php echo esc_attr( $js_function_prefix ); ?>ChangeRole( this );"
					<?php if ( $is_multisite_user ) : ?>
						disabled="disabled"
					<?php endif; ?>
				>
					<?php $disable_input = $is_current_user ? 'disabled' : null; ?>
					<?php $this->wp_dropdown_permitted_roles( $approved_user['role'], $disable_input, $admin_mode ); ?>
				</select>
				<input
					type="text"
					id="<?php echo esc_attr( $option_id ); ?>_date_added"
					value="<?php echo esc_attr( date( 'M Y', strtotime( $approved_user['date_added'] ) ) ); ?>"
					readonly="true"
					class="<?php echo esc_attr( $this->create_class_name( 'date-added', $is_multisite_user ) ); ?>"
				/>
				<?php
				if ( strlen( $advanced_usermeta ) > 0 ) :
					$should_show_usermeta_in_text_field = true; // Fallback renderer for usermeta; try to use a select first.
					if ( strpos( $advanced_usermeta, 'acf___' ) === 0 && class_exists( 'acf' ) ) :
						$field_object = get_field_object( str_replace( 'acf___', '', $advanced_usermeta ) );
						if ( is_array( $field_object ) && array_key_exists( 'type', $field_object ) && 'select' === $field_object['type'] ) :
							$should_show_usermeta_in_text_field = false;
							?>
							<select
								id="<?php echo esc_attr( $option_id ); ?>_usermeta"
								class="<?php echo esc_attr( $this->create_class_name( 'usermeta', $is_multisite_user ) ); ?>"
								onchange="<?php echo esc_attr( $js_function_prefix ); ?>UpdateUsermeta( this );"
							>
								<option value=""<?php selected( empty( $approved_user['usermeta'] ) ); ?>><?php esc_html_e( '-- None --', 'authorizer' ); ?></option>
								<?php foreach ( $field_object['choices'] as $key => $label ) : ?>
									<option value="<?php echo esc_attr( $key ); ?>"<?php selected( $key === $approved_user['usermeta'] || ( isset( $approved_user['usermeta']['meta_value'] ) && $key === $approved_user['usermeta']['meta_value'] ) ); ?>><?php echo esc_html( $label ); ?></option>
								<?php endforeach; ?>
							</select>
						<?php endif; ?>
					<?php endif; ?>
					<?php if ( $should_show_usermeta_in_text_field ) : ?>
						<input
							type="text"
							id="<?php echo esc_attr( $option_id ); ?>_usermeta"
							value="<?php echo esc_attr( $approved_user['usermeta'], ENT_COMPAT ); ?>"
							class="<?php echo esc_attr( $this->create_class_name( 'usermeta', $is_multisite_user ) ); ?>"
						/>
						<a class="button button-small button-primary update-usermeta" id="update_usermeta_<?php echo esc_attr( $key ); ?>" onclick="<?php echo esc_attr( $js_function_prefix ); ?>UpdateUsermeta( this );" title="Update usermeta"><span class="glyphicon glyphicon-floppy-saved"></span></a>
					<?php endif; ?>
				<?php endif; ?>
				<?php if ( ! $is_current_user && ! $is_multisite_user ) : ?>
					<?php if ( ! $is_multisite_admin_page ) : ?>
						<a class="button" id="block_user_<?php echo esc_attr( $key ); ?>" onclick="<?php echo esc_attr( $js_function_prefix ); ?>AddUser( this, 'blocked', false ); <?php echo esc_attr( $js_function_prefix ); ?>IgnoreUser( this, 'approved' );" title="<?php esc_attr_e( 'Block/Ban user', 'authorizer' ); ?>"><span class="glyphicon glyphicon-ban-circle"></span></a>
					<?php endif; ?>
					<a class="button" id="ignore_user_<?php echo esc_attr( $key ); ?>" onclick="<?php echo esc_attr( $js_function_prefix ); ?>IgnoreUser(this, 'approved' );" title="<?php esc_attr_e( 'Remove user', 'authorizer' ); ?>"><span class="glyphicon glyphicon-remove"></span></a>
				<?php endif; ?>
				<?php if ( $is_local_user ) : ?>
					&nbsp;<a title="Local WordPress user" class="auth-local-user"><span class="glyphicon glyphicon-user"></span></a>
				<?php endif; ?>
				<?php if ( $is_multisite_user ) : ?>
					&nbsp;<a title="WordPress Multisite user" class="auth-multisite-user"><span class="glyphicon glyphicon-globe"></span></a>
				<?php endif; ?>
			</li>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_combo_auth_access_users_blocked( $args = '' ) {
			// Get plugin option.
			$option               = 'access_users_blocked';
			$auth_settings_option = $this->get_plugin_option( $option );
			$auth_settings_option = is_array( $auth_settings_option ) ? $auth_settings_option : array();

			// Get default role for new blocked user dropdown.
			$access_default_role = $this->get_plugin_option( 'access_default_role', WP_Plugin_Authorizer::SINGLE_CONTEXT, 'allow override' );

			// Render wrapper div (for aligning pager to width of content).
			?>
			<div class="wrapper_<?php echo esc_attr( $option ); ?>">
				<ul id="list_auth_settings_<?php echo esc_attr( $option ); ?>" style="margin:0;">
					<?php
					foreach ( $auth_settings_option as $key => $blocked_user ) :
						if ( empty( $blocked_user ) || count( $blocked_user ) < 1 ) :
							continue;
						endif;
						$blocked_wp_user = get_user_by( 'email', $blocked_user['email'] );
						if ( $blocked_wp_user ) :
							$blocked_user['email']      = $blocked_wp_user->user_email;
							$blocked_user['role']       = array_shift( $blocked_wp_user->roles );
							$blocked_user['date_added'] = $blocked_wp_user->user_registered;
							$blocked_user['is_wp_user'] = true;
						else :
							$blocked_user['is_wp_user'] = false;
						endif;
						?>
						<li>
							<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>_<?php echo esc_attr( $key ); ?>" value="<?php echo esc_attr( $blocked_user['email'] ); ?>" readonly="true" class="auth-email" />
							<select id="auth_settings_<?php echo esc_attr( $option ); ?>_<?php echo esc_attr( $key ); ?>_role" class="auth-role">
								<?php $this->wp_dropdown_permitted_roles( $blocked_user['role'] ); ?>
							</select>
							<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>_<?php echo esc_attr( $key ); ?>_date_added" value="<?php echo esc_attr( date( 'M Y', strtotime( $blocked_user['date_added'] ) ) ); ?>" readonly="true" class="auth-date-added" />
							<a class="button" id="ignore_user_<?php echo esc_attr( $key ); ?>" onclick="authIgnoreUser( this, 'blocked' );" title="<?php esc_attr_e( 'Remove user', 'authorizer' ); ?>"><span class="glyphicon glyphicon-remove"></span></a>
						</li>
					<?php endforeach; ?>
				</ul>
				<div id="new_auth_settings_<?php echo esc_attr( $option ); ?>">
					<input type="text" id="new_blocked_user_email" placeholder="<?php esc_attr_e( 'email address', 'authorizer' ); ?>" class="auth-email new" />
					<select id="new_blocked_user_role" class="auth-role">
						<option value="<?php echo esc_attr( $access_default_role ); ?>"><?php echo esc_html( ucfirst( $access_default_role ) ); ?></option>
					</select>
					<a href="javascript:void(0);" class="button-primary button-add-user" id="block_user_new" onclick="authAddUser( this, 'blocked' );"><span class="glyphicon glyphicon-ban-circle"></span> <?php esc_html_e( 'Block', 'authorizer' ); ?></a>
				</div>
			</div>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_section_info_access_login( $args = '' ) {
			?>
			<div id="section_info_access_login" class="section_info">
				<?php wp_nonce_field( 'save_auth_settings', 'nonce_save_auth_settings' ); ?>
				<p><?php esc_html_e( 'Choose who is able to log into this site below.', 'authorizer' ); ?></p>
			</div>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_radio_auth_access_who_can_login( $args = '' ) {
			// Get plugin option.
			$option               = 'access_who_can_login';
			$admin_mode           = $this->get_admin_mode( $args );
			$auth_settings_option = $this->get_plugin_option( $option, $admin_mode, 'allow override', 'print overlay' );

			// If this site is configured independently of any multisite overrides, make sure we are not grabbing the multisite value; otherwise, grab the multisite value to show behind the disabled overlay.
			if ( is_multisite() && 1 === intval( $this->get_plugin_option( 'advanced_override_multisite' ) ) ) {
				$auth_settings_option = $this->get_plugin_option( $option );
			} elseif ( is_multisite() && WP_Plugin_Authorizer::SINGLE_CONTEXT === $admin_mode && $this->get_plugin_option( 'multisite_override', WP_Plugin_Authorizer::NETWORK_CONTEXT ) === '1' ) {
				// Workaround: javascript code hides/shows other settings based
				// on the selection in this option. If this option is overridden
				// by a multisite option, it should show that value in order to
				// correctly display the other appropriate options.
				// Side effect: this site option will be overwritten by the
				// multisite option on save. Since this is a 2-item radio, we
				// determined this was acceptable.
				$auth_settings_option = $this->get_plugin_option( $option, WP_Plugin_Authorizer::NETWORK_CONTEXT );
			}

			// Print option elements.
			?>
			<input type="radio" id="radio_auth_settings_<?php echo esc_attr( $option ); ?>_external_users" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="external_users"<?php checked( 'external_users' === $auth_settings_option ); ?> /><label for="radio_auth_settings_<?php echo esc_attr( $option ); ?>_external_users"><?php esc_html_e( 'All authenticated users (All external service users and all WordPress users)', 'authorizer' ); ?></label><br />
			<input type="radio" id="radio_auth_settings_<?php echo esc_attr( $option ); ?>_approved_users" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="approved_users"<?php checked( 'approved_users' === $auth_settings_option ); ?> /><label for="radio_auth_settings_<?php echo esc_attr( $option ); ?>_approved_users"><?php esc_html_e( 'Only', 'authorizer' ); ?> <a href="javascript:chooseTab('access_lists' );" id="dashboard_link_approved_users"><?php esc_html_e( 'approved users', 'authorizer' ); ?></a> <?php esc_html_e( '(Approved external users and all WordPress users)', 'authorizer' ); ?></label><br />
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_select_auth_access_role_receive_pending_emails( $args = '' ) {
			// Get plugin option.
			$option               = 'access_role_receive_pending_emails';
			$auth_settings_option = $this->get_plugin_option( $option );

			// Print option elements.
			?>
			<select id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]">
				<option value="---" <?php selected( $auth_settings_option, '---' ); ?>><?php esc_html_e( "None (Don't send notification emails)", 'authorizer' ); ?></option>
				<?php wp_dropdown_roles( $auth_settings_option ); ?>
			</select>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_wysiwyg_auth_access_pending_redirect_to_message( $args = '' ) {
			// Get plugin option.
			$option               = 'access_pending_redirect_to_message';
			$auth_settings_option = $this->get_plugin_option( $option );

			// Print option elements.
			wp_editor(
				wpautop( $auth_settings_option ),
				"auth_settings_$option",
				array(
					'media_buttons' => false,
					'textarea_name' => "auth_settings[$option]",
					'textarea_rows' => 5,
					'tinymce'       => true,
					'teeny'         => true,
					'quicktags'     => false,
				)
			);
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_wysiwyg_auth_access_blocked_redirect_to_message( $args = '' ) {
			// Get plugin option.
			$option               = 'access_blocked_redirect_to_message';
			$auth_settings_option = $this->get_plugin_option( $option );

			// Print option elements.
			wp_editor(
				wpautop( $auth_settings_option ),
				"auth_settings_$option",
				array(
					'media_buttons' => false,
					'textarea_name' => "auth_settings[$option]",
					'textarea_rows' => 5,
					'tinymce'       => true,
					'teeny'         => true,
					'quicktags'     => false,
				)
			);
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_checkbox_auth_access_should_email_approved_users( $args = '' ) {
			// Get plugin option.
			$option               = 'access_should_email_approved_users';
			$auth_settings_option = $this->get_plugin_option( $option );

			// Print option elements.
			?>
			<input type="checkbox" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="1"<?php checked( 1 === intval( $auth_settings_option ) ); ?> /><label for="auth_settings_<?php echo esc_attr( $option ); ?>"><?php esc_html_e( 'Send a welcome email when approving a new user', 'authorizer' ); ?></label>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_text_auth_access_email_approved_users_subject( $args = '' ) {
			// Get plugin option.
			$option               = 'access_email_approved_users_subject';
			$auth_settings_option = $this->get_plugin_option( $option );

			// Print option elements.
			?>
			<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="Welcome to [site_name]!" style="width:320px;" /><br /><small><?php echo wp_kses( __( 'You can use the <b>[site_name]</b> shortcode.', 'authorizer' ), $this->allowed_html ); ?></small>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_wysiwyg_auth_access_email_approved_users_body( $args = '' ) {
			// Get plugin option.
			$option               = 'access_email_approved_users_body';
			$auth_settings_option = $this->get_plugin_option( $option );

			// Print option elements.
			wp_editor(
				wpautop( $auth_settings_option ),
				"auth_settings_$option",
				array(
					'media_buttons' => false,
					'textarea_name' => "auth_settings[$option]",
					'textarea_rows' => 9,
					'tinymce'       => true,
					'teeny'         => true,
					'quicktags'     => false,
				)
			);
			?>
			<small>
				<?php
				printf(
					/* TRANSLATORS: 1: Shortcode for site name 2: Shortcode for site URL 3: Shortcode for user email */
					wp_kses( __( 'You can use %1$s, %2$s, and %3$s shortcodes.', 'authorizer' ), $this->allowed_html ),
					'<b>[site_name]</b>',
					'<b>[site_url]</b>',
					'<b>[user_email]</b>'
				);
				?>
			</small>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_section_info_access_public( $args = '' ) {
			?>
			<div id="section_info_access_public" class="section_info">
				<p><?php esc_html_e( 'Choose your public access options here.', 'authorizer' ); ?></p>
			</div>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_radio_auth_access_who_can_view( $args = '' ) {
			// Get plugin option.
			$option               = 'access_who_can_view';
			$admin_mode           = $this->get_admin_mode( $args );
			$auth_settings_option = $this->get_plugin_option( $option, $admin_mode, 'allow override', 'print overlay' );

			// If this site is configured independently of any multisite overrides, make sure we are not grabbing the multisite value; otherwise, grab the multisite value to show behind the disabled overlay.
			if ( is_multisite() && 1 === intval( $this->get_plugin_option( 'advanced_override_multisite' ) ) ) {
				$auth_settings_option = $this->get_plugin_option( $option );
			} elseif ( is_multisite() && WP_Plugin_Authorizer::SINGLE_CONTEXT === $admin_mode && '1' === $this->get_plugin_option( 'multisite_override', WP_Plugin_Authorizer::NETWORK_CONTEXT ) ) {
				// Workaround: javascript code hides/shows other settings based
				// on the selection in this option. If this option is overridden
				// by a multisite option, it should show that value in order to
				// correctly display the other appropriate options.
				// Side effect: this site option will be overwritten by the
				// multisite option on save. Since this is a 2-item radio, we
				// determined this was acceptable.
				$auth_settings_option = $this->get_plugin_option( $option, WP_Plugin_Authorizer::NETWORK_CONTEXT );
			}

			// Print option elements.
			?>
			<input type="radio" id="radio_auth_settings_<?php echo esc_attr( $option ); ?>_everyone" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="everyone"<?php checked( 'everyone' === $auth_settings_option ); ?> /><label for="radio_auth_settings_<?php echo esc_attr( $option ); ?>_everyone"><?php esc_html_e( 'Everyone can see the site', 'authorizer' ); ?></label><br />
			<input type="radio" id="radio_auth_settings_<?php echo esc_attr( $option ); ?>_logged_in_users" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="logged_in_users"<?php checked( 'logged_in_users' === $auth_settings_option ); ?> /><label for="radio_auth_settings_<?php echo esc_attr( $option ); ?>_logged_in_users"><?php esc_html_e( 'Only logged in users can see the site', 'authorizer' ); ?></label><br />
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_radio_auth_access_redirect( $args = '' ) {
			// Get plugin option.
			$option               = 'access_redirect';
			$auth_settings_option = $this->get_plugin_option( $option );

			// Print option elements.
			?>
			<input type="radio" id="radio_auth_settings_<?php echo esc_attr( $option ); ?>_to_login" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="login"<?php checked( 'login' === $auth_settings_option ); ?> /><label for="radio_auth_settings_<?php echo esc_attr( $option ); ?>_to_login"><?php esc_html_e( 'Send them to the login screen', 'authorizer' ); ?></label><br />
			<input type="radio" id="radio_auth_settings_<?php echo esc_attr( $option ); ?>_to_message" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="message"<?php checked( 'message' === $auth_settings_option ); ?> /><label for="radio_auth_settings_<?php echo esc_attr( $option ); ?>_to_message"><?php esc_html_e( 'Show them the anonymous access message (below)', 'authorizer' ); ?></label>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_radio_auth_access_public_warning( $args = '' ) {
			// Get plugin option.
			$option               = 'access_public_warning';
			$auth_settings_option = $this->get_plugin_option( $option );

			// Print option elements.
			?>
			<input type="radio" id="radio_auth_settings_<?php echo esc_attr( $option ); ?>_no" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="no_warning"<?php checked( 'no_warning' === $auth_settings_option ); ?> /><label for="radio_auth_settings_<?php echo esc_attr( $option ); ?>_no"><?php echo wp_kses( __( 'Show them the page <strong>without</strong> the anonymous access message', 'authorizer' ), $this->allowed_html ); ?></label><br />
			<input type="radio" id="radio_auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="warning"<?php checked( 'warning' === $auth_settings_option ); ?> /><label for="radio_auth_settings_<?php echo esc_attr( $option ); ?>"><?php echo wp_kses( __( 'Show them the page <strong>with</strong> the anonymous access message (marked up as a <a href="http://getbootstrap.com/components/#alerts-dismissible" target="_blank">Bootstrap Dismissible Alert</a>)', 'authorizer' ), $this->allowed_html ); ?></label>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_wysiwyg_auth_access_redirect_to_message( $args = '' ) {
			// Get plugin option.
			$option               = 'access_redirect_to_message';
			$auth_settings_option = $this->get_plugin_option( $option );

			// Print option elements.
			wp_editor(
				wpautop( $auth_settings_option ),
				"auth_settings_$option",
				array(
					'media_buttons' => false,
					'textarea_name' => "auth_settings[$option]",
					'textarea_rows' => 5,
					'tinymce'       => true,
					'teeny'         => true,
					'quicktags'     => false,
				)
			);
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_multiselect_auth_access_public_pages( $args = '' ) {
			// Get plugin option.
			$option               = 'access_public_pages';
			$auth_settings_option = $this->get_plugin_option( $option );
			$auth_settings_option = is_array( $auth_settings_option ) ? $auth_settings_option : array();

			$post_types = array_merge( array( 'page', 'post' ), get_post_types( array( '_builtin' => false ), 'names' ) );
			$post_types = is_array( $post_types ) ? $post_types : array();

			// Print option elements.
			?>
			<select id="auth_settings_<?php echo esc_attr( $option ); ?>" multiple="multiple" name="auth_settings[<?php echo esc_attr( $option ); ?>][]">
				<optgroup label="<?php esc_attr_e( 'Home', 'authorizer' ); ?>">
					<option value="home" <?php selected( in_array( 'home', $auth_settings_option, true ) ); ?>><?php esc_html_e( 'Home Page', 'authorizer' ); ?></option>
					<option value="auth_public_404" <?php selected( in_array( 'auth_public_404', $auth_settings_option, true ) ); ?>><?php esc_html_e( 'Nonexistent (404) Pages', 'authorizer' ); ?></option>
				</optgroup>
				<?php foreach ( $post_types as $post_type ) : ?>
					<optgroup label="<?php echo esc_attr( ucfirst( $post_type ) ); ?>">
					<?php
					$pages = get_posts(
						array(
							'post_type'      => $post_type,
							'posts_per_page' => 1000, // phpcs:ignore WordPress.VIP.PostsPerPage.posts_per_page_posts_per_page
						)
					);
					$pages = is_array( $pages ) ? $pages : array();
					foreach ( $pages as $page ) :
						?>
						<option value="<?php echo esc_attr( $page->ID ); ?>" <?php selected( in_array( strval( $page->ID ), $auth_settings_option, true ) ); ?>><?php echo esc_html( $page->post_title ); ?></option>
					<?php endforeach; ?>
					</optgroup>
				<?php endforeach; ?>
				<optgroup label="<?php esc_attr_e( 'Categories', 'authorizer' ); ?>">
					<?php
					// If sitepress-multilingual-cms plugin is enabled, temporarily disable
					// its terms_clauses filter since it conflicts with the category handling.
					if ( array_key_exists( 'sitepress', $GLOBALS ) && is_object( $GLOBALS['sitepress'] ) ) {
						remove_filter( 'terms_clauses', array( $GLOBALS['sitepress'], 'terms_clauses' ) );
						$categories = get_categories( array( 'hide_empty' => false ) );
						add_filter( 'terms_clauses', array( $GLOBALS['sitepress'], 'terms_clauses' ) );
					} else {
						$categories = get_categories( array( 'hide_empty' => false ) );
					}
					foreach ( $categories as $category ) :
						?>
						<option value="<?php echo esc_attr( 'cat_' . $category->slug ); ?>" <?php selected( in_array( 'cat_' . $category->slug, $auth_settings_option, true ) ); ?>><?php echo esc_html( $category->name ); ?></option>
					<?php endforeach; ?>
				</optgroup>
			</select>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_section_info_external( $args = '' ) {
			?>
			<div id="section_info_external" class="section_info">
				<p><?php esc_html_e( 'Enter your external server settings below.', 'authorizer' ); ?></p>
			</div>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_select_auth_access_default_role( $args = '' ) {
			// Get plugin option.
			$option               = 'access_default_role';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<select id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]">
				<?php wp_dropdown_roles( $auth_settings_option ); ?>
				<option value=""<?php selected( '' === $auth_settings_option ); ?>><?php esc_html_e( '-- None --', 'authorizer' ); ?></option>
			</select>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_checkbox_auth_external_google( $args = '' ) {
			// Get plugin option.
			$option               = 'google';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<input type="checkbox" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="1"<?php checked( 1 === intval( $auth_settings_option ) ); ?> /><label for="auth_settings_<?php echo esc_attr( $option ); ?>"><?php esc_html_e( 'Enable Google Logins', 'authorizer' ); ?></label>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_text_google_clientid( $args = '' ) {
			// Get plugin option.
			$option               = 'google_clientid';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			$site_url_parts = wp_parse_url( get_site_url() );
			$site_url_host  = $site_url_parts['scheme'] . '://' . $site_url_parts['host'] . '/';

			esc_html_e( "If you don't have a Google Client ID and Secret, generate them by following these instructions:", 'authorizer' );
			?>
			<ol>
				<li><?php echo wp_kses( __( 'Click <strong>Create a Project</strong> on the <a href="https://cloud.google.com/console" target="_blank">Google Developers Console</a>. You can name it whatever you want.', 'authorizer' ), $this->allowed_html ); ?></li>
				<li><?php echo wp_kses( __( 'Within the project, navigate to <em>APIs and Auth</em> &gt; <em>Credentials</em>, then click <strong>Create New Client ID</strong> under OAuth. Use these settings:', 'authorizer' ), $this->allowed_html ); ?>
					<ul>
						<li><?php echo wp_kses( __( 'Application Type: <strong>Web application</strong>', 'authorizer' ), $this->allowed_html ); ?></li>
						<li><?php esc_html_e( 'Authorized Javascript Origins:', 'authorizer' ); ?> <strong><?php echo esc_html( rtrim( $site_url_host, '/' ) ); ?></strong></li>
						<li><?php echo wp_kses( __( 'Authorized Redirect URI: <em>none</em>', 'authorizer' ), $this->allowed_html ); ?></li>
					</ul>
				</li>
				<li><?php esc_html_e( 'Copy/paste your new Client ID/Secret pair into the fields below.', 'authorizer' ); ?></li>
				<li><?php echo wp_kses( __( '<strong>Note</strong>: Navigate to <em>APIs and Auth</em> &gt; <em>Consent screen</em> to change the way the Google consent screen appears after a user has successfully entered their password, but before they are redirected back to WordPress.', 'authorizer' ), $this->allowed_html ); ?></li>
				<li><?php echo wp_kses( __( 'Note: Google may have a more recent version of these instructions in their <a href="https://developers.google.com/identity/sign-in/web/devconsole-project" target="_blank">developer documentation</a>.', 'authorizer' ), $this->allowed_html ); ?></li>
			</ol>
			<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" style="width:560px;" />
			<br /><label for="auth_settings_<?php echo esc_attr( $option ); ?>" class="helper"><?php esc_html_e( 'Example:  1234567890123-kdjr85yt6vjr6d8g7dhr8g7d6durjf7g.apps.googleusercontent.com', 'authorizer' ); ?></label>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_text_google_clientsecret( $args = '' ) {
			// Get plugin option.
			$option               = 'google_clientsecret';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" style="width:220px;" />
			<br /><label for="auth_settings_<?php echo esc_attr( $option ); ?>" class="helper"><?php esc_html_e( 'Example:  sDNgX5_pr_5bly-frKmvp8jT', 'authorizer' ); ?></label>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_text_google_hosteddomain( $args = '' ) {
			// Get plugin option.
			$option               = 'google_hosteddomain';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<textarea id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" placeholder="" style="width:220px;"><?php echo esc_html( $auth_settings_option ); ?></textarea>
			<br /><small><?php esc_html_e( 'Restrict Google logins to a specific Google Apps hosted domain (for example, mycollege.edu). Leave blank to allow all Google sign-ins.', 'authorizer' ); ?><br /><?php esc_html_e( 'If restricting to multiple domains, add one domain per line.', 'authorizer' ); ?></small>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_checkbox_auth_external_cas( $args = '' ) {
			// Get plugin option.
			$option               = 'cas';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Make sure php5-curl extension is installed on server.
			$curl_installed_message = ! function_exists( 'curl_init' ) ? __( '<a href="http://www.php.net//manual/en/curl.installation.php" target="_blank" style="color: red;">PHP CURL extension</a> is not installed', 'authorizer' ) : '';

			// Make sure php_openssl extension is installed on server.
			$openssl_installed_message = ! extension_loaded( 'openssl' ) ? __( '<a href="http://stackoverflow.com/questions/23424459/enable-php-openssl-not-working" target="_blank" style="color: red;">PHP openssl extension</a> is not installed', 'authorizer' ) : '';

			// Build error message string.
			$error_message = '';
			if ( strlen( $curl_installed_message ) > 0 || strlen( $openssl_installed_message ) > 0 ) {
				$error_message = '<span style="color: red;">(' .
					__( 'Warning', 'authorizer' ) . ': ' .
					$curl_installed_message .
					( strlen( $curl_installed_message ) > 0 && strlen( $openssl_installed_message ) > 0 ? '; ' : '' ) .
					$openssl_installed_message .
					')</span>';
			}

			// Print option elements.
			?>
			<input type="checkbox" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="1"<?php checked( 1 === intval( $auth_settings_option ) ); ?> /><label for="auth_settings_<?php echo esc_attr( $option ); ?>"><?php esc_html_e( 'Enable CAS Logins', 'authorizer' ); ?></label> <?php echo wp_kses( $error_message, $this->allowed_html ); ?>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_text_cas_custom_label( $args = '' ) {
			// Get plugin option.
			$option               = 'cas_custom_label';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			esc_html_e( 'The button on the login page will read:', 'authorizer' );
			?>
			<p><a class="button-primary button-large" style="padding: 3px 16px; height: 36px;"><span class="dashicons dashicons-lock" style="margin: 4px 4px 0 0;"></span> <strong><?php esc_html_e( 'Sign in with', 'authorizer' ); ?> </strong><input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="CAS" style="width: 100px;" /></a></p>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_text_cas_host( $args = '' ) {
			// Get plugin option.
			$option               = 'cas_host';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" />
			<br /><label for="auth_settings_<?php echo esc_attr( $option ); ?>" class="helper"><?php esc_html_e( 'Example:  authn.example.edu', 'authorizer' ); ?></label>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_text_cas_port( $args = '' ) {
			// Get plugin option.
			$option               = 'cas_port';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" style="width:50px;" />
			<br /><label for="auth_settings_<?php echo esc_attr( $option ); ?>" class="helper"><?php esc_html_e( 'Example:  443', 'authorizer' ); ?></label>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_text_cas_path( $args = '' ) {
			// Get plugin option.
			$option               = 'cas_path';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" />
			<br /><label for="auth_settings_<?php echo esc_attr( $option ); ?>" class="helper"><?php esc_html_e( 'Example:  /cas', 'authorizer' ); ?></label>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_select_cas_version( $args = '' ) {
			// Get plugin option.
			$option               = 'cas_version';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<select id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]">
				<option value="SAML_VERSION_1_1" <?php selected( $auth_settings_option, 'SAML_VERSION_1_1' ); ?>>SAML_VERSION_1_1</option>
				<option value="CAS_VERSION_3_0" <?php selected( $auth_settings_option, 'CAS_VERSION_3_0' ); ?>>CAS_VERSION_3_0</option>
				<option value="CAS_VERSION_2_0" <?php selected( $auth_settings_option, 'CAS_VERSION_2_0' ); ?>>CAS_VERSION_2_0</option>
				<option value="CAS_VERSION_1_0" <?php selected( $auth_settings_option, 'CAS_VERSION_1_0' ); ?>>CAS_VERSION_1_0</option>
			</select>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_text_cas_attr_email( $args = '' ) {
			// Get plugin option.
			$option               = 'cas_attr_email';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" />
			<br /><label for="auth_settings_<?php echo esc_attr( $option ); ?>" class="helper"><?php esc_html_e( 'Example:  mail', 'authorizer' ); ?></label>
			<br /><small><?php echo wp_kses( __( "Note: If your CAS server doesn't return an attribute containing an email, you can specify the @domain portion of the email address here, and the email address will be constructed from it and the username. For example, if user 'bob' logs in and his email address should be bob@example.edu, then enter <strong>@example.edu</strong> in this field.", 'authorizer' ), $this->allowed_html ); ?></small>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_text_cas_attr_first_name( $args = '' ) {
			// Get plugin option.
			$option               = 'cas_attr_first_name';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" />
			<br /><label for="auth_settings_<?php echo esc_attr( $option ); ?>" class="helper"><?php esc_html_e( 'Example:  givenName', 'authorizer' ); ?></label>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_text_cas_attr_last_name( $args = '' ) {
			// Get plugin option.
			$option               = 'cas_attr_last_name';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" />
			<br /><label for="auth_settings_<?php echo esc_attr( $option ); ?>" class="helper"><?php esc_html_e( 'Example:  sn', 'authorizer' ); ?></label>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_checkbox_cas_attr_update_on_login( $args = '' ) {
			// Get plugin option.
			$option               = 'cas_attr_update_on_login';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<input type="checkbox" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="1"<?php checked( 1 === intval( $auth_settings_option ) ); ?> /><label for="auth_settings_<?php echo esc_attr( $option ); ?>"><?php esc_html_e( 'Update first and last name fields on login (will overwrite any name the user has supplied in their profile)', 'authorizer' ); ?></label>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_checkbox_cas_auto_login( $args = '' ) {
			// Get plugin option.
			$option               = 'cas_auto_login';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<input type="checkbox" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="1"<?php checked( 1 === intval( $auth_settings_option ) ); ?> /><label for="auth_settings_<?php echo esc_attr( $option ); ?>"><?php esc_html_e( "Immediately redirect to CAS login form if it's the only enabled external service and WordPress logins are hidden", 'authorizer' ); ?></label>
			<p><small><?php esc_html_e( 'Note: This feature will only work if you have checked "Hide WordPress Logins" in Advanced settings, and if CAS is the only enabled service (i.e., no Google or LDAP). If you have enabled CAS Single Sign-On (SSO), and a user has already logged into CAS elsewhere, enabling this feature will allow automatic logins without any user interaction.', 'authorizer' ); ?></small></p>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_checkbox_auth_external_ldap( $args = '' ) {
			// Get plugin option.
			$option               = 'ldap';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Make sure php5-ldap extension is installed on server.
			$ldap_installed_message = ! function_exists( 'ldap_connect' ) ? '<span style="color: red;">(' . __( 'Warning: <a href="http://www.php.net/manual/en/ldap.installation.php" target="_blank" style="color: red;">PHP LDAP extension</a> is <strong>not</strong> installed', 'authorizer' ) . ')</span>' : '';

			// Print option elements.
			?>
			<input type="checkbox" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="1"<?php checked( 1 === intval( $auth_settings_option ) ); ?> /><label for="auth_settings_<?php echo esc_attr( $option ); ?>"><?php esc_html_e( 'Enable LDAP Logins', 'authorizer' ); ?></label> <?php echo wp_kses( $ldap_installed_message, $this->allowed_html ); ?>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_text_ldap_host( $args = '' ) {
			// Get plugin option.
			$option               = 'ldap_host';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" style="width:330px;" />
			<br /><small><?php esc_html_e( 'Specify either a hostname (for example, ldap.example.edu) or a full LDAP URI (for example, ldaps://ldap.example.edu:636).', 'authorizer' ); ?></small>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_text_ldap_port( $args = '' ) {
			// Get plugin option.
			$option               = 'ldap_port';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" style="width:50px;" />
			<br /><label for="auth_settings_<?php echo esc_attr( $option ); ?>" class="helper"><?php esc_html_e( 'Example:  389', 'authorizer' ); ?></label>
			<br /><small><?php esc_html_e( 'If a full LDAP URI (ldaps://hostname:port) is specified above, this field is ignored.', 'authorizer' ); ?></small>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_checkbox_ldap_tls( $args = '' ) {
			// Get plugin option.
			$option               = 'ldap_tls';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<input type="checkbox" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="1"<?php checked( 1 === intval( $auth_settings_option ) ); ?> /><label for="auth_settings_<?php echo esc_attr( $option ); ?>"><?php esc_html_e( 'Use TLS', 'authorizer' ); ?></label>
			<br /><small><?php esc_html_e( 'If ldaps is used, this should be unchecked', 'authorizer' ); ?></small>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_text_ldap_search_base( $args = '' ) {
			// Get plugin option.
			$option               = 'ldap_search_base';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<textarea id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" placeholder="" style="width:330px;"><?php echo esc_attr( $auth_settings_option ); ?></textarea>
			<br /><label for="auth_settings_<?php echo esc_attr( $option ); ?>" class="helper"><?php esc_html_e( 'Example:  ou=people,dc=example,dc=edu', 'authorizer' ); ?></label>
			<br /><small><?php esc_html_e( 'If you have multiple search bases, separate them by newlines (one per line).', 'authorizer' ); ?></small>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_text_ldap_uid( $args = '' ) {
			// Get plugin option.
			$option               = 'ldap_uid';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" style="width:80px;" />
			<br /><label for="auth_settings_<?php echo esc_attr( $option ); ?>" class="helper"><?php esc_html_e( 'Example:  uid', 'authorizer' ); ?></label>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_text_ldap_attr_email( $args = '' ) {
			// Get plugin option.
			$option               = 'ldap_attr_email';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" />
			<br /><label for="auth_settings_<?php echo esc_attr( $option ); ?>" class="helper"><?php esc_html_e( 'Example:  mail', 'authorizer' ); ?></label>
			<br /><small><?php echo wp_kses( __( "Note: If your LDAP server doesn't return an attribute containing an email, you can specify the @domain portion of the email address here, and the email address will be constructed from it and the username. For example, if user 'bob' logs in and his email address should be bob@example.edu, then enter <strong>@example.edu</strong> in this field.", 'authorizer' ), $this->allowed_html ); ?></small>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_text_ldap_user( $args = '' ) {
			// Get plugin option.
			$option               = 'ldap_user';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" style="width:330px;" />
			<br /><label for="auth_settings_<?php echo esc_attr( $option ); ?>" class="helper"><?php esc_html_e( 'Example:  cn=directory-user,ou=specials,dc=example,dc=edu', 'authorizer' ); ?></label>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_password_ldap_password( $args = '' ) {
			// Get plugin option.
			$option               = 'ldap_password';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<input type="password" id="garbage_to_stop_autofill" name="garbage" value="" autocomplete="off" style="display:none;" />
			<input type="password" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $this->decrypt( $auth_settings_option ) ); ?>" autocomplete="off" />
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_text_ldap_lostpassword_url( $args = '' ) {
			// Get plugin option.
			$option               = 'ldap_lostpassword_url';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" style="width: 400px;" />
			<br /><label for="auth_settings_<?php echo esc_attr( $option ); ?>" class="helper"><?php esc_html_e( 'Example:  https://myschool.example.edu:8888/am-forgot-password', 'authorizer' ); ?></label>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_text_ldap_attr_first_name( $args = '' ) {
			// Get plugin option.
			$option               = 'ldap_attr_first_name';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" />
			<br /><label for="auth_settings_<?php echo esc_attr( $option ); ?>" class="helper"><?php esc_html_e( 'Example:  givenname', 'authorizer' ); ?></label>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_text_ldap_attr_last_name( $args = '' ) {
			// Get plugin option.
			$option               = 'ldap_attr_last_name';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" />
			<br /><label for="auth_settings_<?php echo esc_attr( $option ); ?>" class="helper"><?php esc_html_e( 'Example:  sn', 'authorizer' ); ?></label>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_checkbox_ldap_attr_update_on_login( $args = '' ) {
			// Get plugin option.
			$option               = 'ldap_attr_update_on_login';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<input type="checkbox" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="1"<?php checked( 1 === intval( $auth_settings_option ) ); ?> /><label for="auth_settings_<?php echo esc_attr( $option ); ?>"><?php esc_html_e( 'Update first and last name fields on login (will overwrite any name the user has supplied in their profile)', 'authorizer' ); ?></label>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_section_info_advanced( $args = '' ) {
			?>
			<div id="section_info_advanced" class="section_info">
				<p><?php esc_html_e( 'You may optionally specify some advanced settings below.', 'authorizer' ); ?></p>
			</div>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_text_auth_advanced_lockouts( $args = '' ) {
			// Get plugin option.
			$option               = 'advanced_lockouts';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			esc_html_e( 'After', 'authorizer' );
			?>
			<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>_attempts_1" name="auth_settings[<?php echo esc_attr( $option ); ?>][attempts_1]" value="<?php echo esc_attr( $auth_settings_option['attempts_1'] ); ?>" placeholder="10" style="width:30px;" />
			<?php esc_html_e( 'invalid password attempts, delay further attempts on that user for', 'authorizer' ); ?>
			<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>_duration_1" name="auth_settings[<?php echo esc_attr( $option ); ?>][duration_1]" value="<?php echo esc_attr( $auth_settings_option['duration_1'] ); ?>" placeholder="1" style="width:30px;" />
			<?php esc_html_e( 'minute(s).', 'authorizer' ); ?>
			<br />
			<?php esc_html_e( 'After', 'authorizer' ); ?>
			<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>_attempts_2" name="auth_settings[<?php echo esc_attr( $option ); ?>][attempts_2]" value="<?php echo esc_attr( $auth_settings_option['attempts_2'] ); ?>" placeholder="10" style="width:30px;" />
			<?php esc_html_e( 'more invalid attempts, increase the delay to', 'authorizer' ); ?>
			<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>_duration_2" name="auth_settings[<?php echo esc_attr( $option ); ?>][duration_2]" value="<?php echo esc_attr( $auth_settings_option['duration_2'] ); ?>" placeholder="10" style="width:30px;" />
			<?php esc_html_e( 'minutes.', 'authorizer' ); ?>
			<br />
			<?php esc_html_e( 'Reset the delays after', 'authorizer' ); ?>
			<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>_reset_duration" name="auth_settings[<?php echo esc_attr( $option ); ?>][reset_duration]" value="<?php echo esc_attr( $auth_settings_option['reset_duration'] ); ?>" placeholder="240" style="width:40px;" />
			<?php esc_html_e( 'minutes with no invalid attempts.', 'authorizer' ); ?>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_checkbox_auth_advanced_hide_wp_login( $args = '' ) {
			// Get plugin option.
			$option               = 'advanced_hide_wp_login';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<input type="checkbox" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="1"<?php checked( 1 === intval( $auth_settings_option ) ); ?> /><label for="auth_settings_<?php echo esc_attr( $option ); ?>"><?php esc_html_e( 'Hide WordPress Logins', 'authorizer' ); ?></label>
			<p><small><?php esc_html_e( 'Note: You can always access the WordPress logins by adding external=wordpress to the wp-login URL, like so:', 'authorizer' ); ?><br /><a href="<?php echo esc_attr( wp_login_url() ); ?>?external=wordpress" target="_blank"><?php echo esc_html( wp_login_url() ); ?>?external=wordpress</a>.</p>
				<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_radio_auth_advanced_branding( $args = '' ) {
			// Get plugin option.
			$option               = 'advanced_branding';
			$auth_settings_option = $this->get_plugin_option( $option );

			// Print option elements.
			?>
			<input type="radio" id="radio_auth_settings_<?php echo esc_attr( $option ); ?>_default" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="default"<?php checked( 'default' === $auth_settings_option ); ?> /><label for="radio_auth_settings_<?php echo esc_attr( $option ); ?>_default"><?php esc_html_e( 'Default WordPress login screen', 'authorizer' ); ?></label><br />
			<?php

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
				if ( ! ( is_array( $branding_option ) && array_key_exists( 'value', $branding_option ) && array_key_exists( 'description', $branding_option ) ) ) {
					continue;
				}
				?>
				<input type="radio" id="radio_auth_settings_<?php echo esc_attr( $option ); ?>_<?php echo esc_attr( sanitize_title( $branding_option['value'] ) ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $branding_option['value'] ); ?>"<?php checked( $branding_option['value'] === $auth_settings_option ); ?> /><label for="radio_auth_settings_<?php echo esc_attr( $option ); ?>_<?php echo esc_attr( sanitize_title( $branding_option['value'] ) ); ?>"><?php echo esc_html( $branding_option['description'] ); ?></label><br />
				<?php
			}

			// Print message about adding custom brands if there are none.
			if ( count( $branding_options ) === 0 ) {
				?>
				<p><em><?php echo wp_kses( __( '<strong>Note for theme developers</strong>: Add more options here by using the `authorizer_add_branding_option` filter in your theme. You can see an example theme that implements this filter in the plugin directory under sample-theme-add-branding.', 'authorizer' ), $this->allowed_html ); ?></em></p>
				<?php
			}
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_radio_auth_advanced_admin_menu( $args = '' ) {
			// Get plugin option.
			$option               = 'advanced_admin_menu';
			$auth_settings_option = $this->get_plugin_option( $option );

			// Print option elements.
			?>
			<input type="radio" id="radio_auth_settings_<?php echo esc_attr( $option ); ?>_settings" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="settings"<?php checked( 'settings' === $auth_settings_option ); ?> /><label for="radio_auth_settings_<?php echo esc_attr( $option ); ?>_settings"><?php esc_html_e( 'Show in Settings menu', 'authorizer' ); ?></label><br />
			<input type="radio" id="radio_auth_settings_<?php echo esc_attr( $option ); ?>_top" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="top"<?php checked( 'top' === $auth_settings_option ); ?> /><label for="radio_auth_settings_<?php echo esc_attr( $option ); ?>_top"><?php esc_html_e( 'Show in sidebar (top level)', 'authorizer' ); ?></label><br />
			<?php

		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_select_auth_advanced_usermeta( $args = '' ) {
			// Get plugin option.
			$option               = 'advanced_usermeta';
			$auth_settings_option = $this->get_plugin_option( $option );

			// Print option elements.
			?>
			<select id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]">
				<option value=""><?php esc_html_e( '-- None --', 'authorizer' ); ?></option>
				<?php
				if ( class_exists( 'acf' ) ) :
					// Get ACF 5 fields. Note: it would be much easier to use `get_field_objects()`
					// or `get_field_objects( 'user_' . get_current_user_id() )`, but neither will
					// list fields that have never been given values for users (i.e., new ACF
					// fields). Therefore we fall back on finding any ACF fields applied to users
					// (user_role or user_form location rules in the field group definition).
					$fields              = array();
					$acf_field_group_ids = array();
					$acf_field_groups    = new WP_Query(
						array(
							'post_type' => 'acf-field-group',
						)
					);
					while ( $acf_field_groups->have_posts() ) : $acf_field_groups->the_post();
						if ( strpos( get_the_content(), 's:5:"param";s:9:"user_role"' ) !== false || strpos( get_the_content(), 's:5:"param";s:9:"user_form"' ) !== false ) :
							array_push( $acf_field_group_ids, get_the_ID() );
						endif;
					endwhile;
					wp_reset_postdata();
					foreach ( $acf_field_group_ids as $acf_field_group_id ) :
						$acf_fields = new WP_Query(
							array(
								'post_type'   => 'acf-field',
								'post_parent' => $acf_field_group_id,
							)
						);
						while ( $acf_fields->have_posts() ) : $acf_fields->the_post();
							global $post;
							$fields[ $post->post_name ] = get_field_object( $post->post_name );
						endwhile;
						wp_reset_postdata();
					endforeach;
					// Get ACF 4 fields.
					$acf4_field_groups = new WP_Query(
						array(
							'post_type' => 'acf',
						)
					);
					while ( $acf4_field_groups->have_posts() ) : $acf4_field_groups->the_post();
						$field_group_rules = get_post_meta( get_the_ID(), 'rule', true );
						if ( is_array( $field_group_rules ) && array_key_exists( 'param', $field_group_rules ) && 'ef_user' === $field_group_rules['param'] ) :
							$acf4_fields = get_post_custom( get_the_ID() );
							foreach ( $acf4_fields as $meta_key => $meta_value ) :
								if ( strpos( $meta_key, 'field_' ) === 0 ) :
									$meta_value          = unserialize( $meta_value[0] );
									$fields[ $meta_key ] = $meta_value;
								endif;
							endforeach;
						endif;
					endwhile;
					wp_reset_postdata();
					?>
					<optgroup label="ACF User Fields:">
						<?php foreach ( (array) $fields as $field => $field_object ) : ?>
							<option value="acf___<?php echo esc_attr( $field_object['key'] ); ?>"<?php selected( "acf___{$field_object['key']}" === $auth_settings_option ); ?>><?php echo esc_html( $field_object['label'] ); ?></option>
						<?php endforeach; ?>
					</optgroup>
				<?php endif; ?>
				<optgroup label="<?php esc_attr_e( 'All Usermeta:', 'authorizer' ); ?>">
					<?php
					foreach ( $this->get_all_usermeta_keys() as $meta_key ) :
						if ( substr( $meta_key, 0, 3 ) === 'wp_' ) :
							continue;
						endif;
						?>
						<option value="<?php echo esc_attr( $meta_key ); ?>"<?php selected( $auth_settings_option === $meta_key ); ?>><?php echo esc_html( $meta_key ); ?></option>
					<?php endforeach; ?>
				</optgroup>
			</select>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_text_auth_advanced_users_per_page( $args = '' ) {
			// Get plugin option.
			$option               = 'advanced_users_per_page';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" size="4" />
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_select_auth_advanced_users_sort_by( $args = '' ) {
			// Get plugin option.
			$option               = 'advanced_users_sort_by';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<select id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]">
				<option value="created" <?php selected( $auth_settings_option, 'created' ); ?>><?php esc_html_e( 'Date approved', 'authorizer' ); ?></option>
				<option value="email" <?php selected( $auth_settings_option, 'email' ); ?>><?php esc_html_e( 'Email', 'authorizer' ); ?></option>
				<option value="role" <?php selected( $auth_settings_option, 'role' ); ?>><?php esc_html_e( 'Role', 'authorizer' ); ?></option>
				<option value="date_added" <?php selected( $auth_settings_option, 'date_added' ); ?>><?php esc_html_e( 'Date registered', 'authorizer' ); ?></option>
			</select>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_select_auth_advanced_users_sort_order( $args = '' ) {
			// Get plugin option.
			$option               = 'advanced_users_sort_order';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<select id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]">
				<option value="asc" <?php selected( $auth_settings_option, 'asc' ); ?>><?php esc_html_e( 'Ascending', 'authorizer' ); ?></option>
				<option value="desc" <?php selected( $auth_settings_option, 'desc' ); ?>><?php esc_html_e( 'Descending', 'authorizer' ); ?></option>
			</select>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_checkbox_auth_advanced_widget_enabled( $args = '' ) {
			// Get plugin option.
			$option               = 'advanced_widget_enabled';
			$auth_settings_option = $this->get_plugin_option( $option, $this->get_admin_mode( $args ), 'allow override', 'print overlay' );

			// Print option elements.
			?>
			<input type="checkbox" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="1"<?php checked( 1 === intval( $auth_settings_option ) ); ?> /><label for="auth_settings_<?php echo esc_attr( $option ); ?>"><?php esc_html_e( 'Show Dashboard Widget', 'authorizer' ); ?></label>
			<p><small><?php esc_html_e( 'Note: Only users with the create_users capability will be able to see the dashboard widget.', 'authorizer' ); ?></small></p>
			<?php
		}


		/**
		 * Settings print callback.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return void
		 */
		public function print_checkbox_auth_advanced_override_multisite( $args = '' ) {
			// Get plugin option.
			$option               = 'advanced_override_multisite';
			$auth_settings_option = $this->get_plugin_option( $option );

			// Print option elements.
			?>
			<input type="checkbox" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="1"<?php checked( 1 === intval( $auth_settings_option ) ); ?> /><label for="auth_settings_<?php echo esc_attr( $option ); ?>"><?php esc_html_e( "Configure this site independently (don't inherit any multisite settings)", 'authorizer' ); ?></label>
			<?php
		}



		/**
		 * Determines whether we are in single site or multisite admin context.
		 *
		 * @param  string $args Args (e.g., multisite admin mode).
		 * @return int          Current mode.
		 */
		private function get_admin_mode( $args ) {
			if ( is_array( $args ) && array_key_exists( WP_Plugin_Authorizer::NETWORK_CONTEXT, $args ) && true === $args[ WP_Plugin_Authorizer::NETWORK_CONTEXT ] ) {
				return WP_Plugin_Authorizer::NETWORK_CONTEXT;
			} else {
				return WP_Plugin_Authorizer::SINGLE_CONTEXT;
			}
		}


		/**
		 * Add help documentation to the options page.
		 *
		 * Action: load-settings_page_authorizer > admin_head
		 */
		public function admin_head() {
			$screen = get_current_screen();

			// Add help tab for Access Lists Settings.
			$help_auth_settings_access_lists_content = '
				<p>' . __( "<strong>Pending Users</strong>: Pending users are users who have successfully logged in to the site, but who haven't yet been approved (or blocked) by you.", 'authorizer' ) . '</p>
				<p>' . __( '<strong>Approved Users</strong>: Approved users have access to the site once they successfully log in.', 'authorizer' ) . '</p>
				<p>' . __( '<strong>Blocked Users</strong>: Blocked users will receive an error message when they try to visit the site after authenticating.', 'authorizer' ) . '</p>
				<p>' . __( 'Users in the <strong>Pending</strong> list appear automatically after a new user tries to log in from the configured external authentication service. You can add users to the <strong>Approved</strong> or <strong>Blocked</strong> lists by typing them in manually, or by clicking the <em>Approve</em> or <em>Block</em> buttons next to a user in the <strong>Pending</strong> list.', 'authorizer' ) . '</p>
			';
			$screen->add_help_tab(
				array(
					'id'      => 'help_auth_settings_access_lists_content',
					'title'   => __( 'Access Lists', 'authorizer' ),
					'content' => $help_auth_settings_access_lists_content,
				)
			);

			// Add help tab for Login Access Settings.
			$help_auth_settings_access_login_content = '
				<p>' . __( "<strong>Who can log in to the site?</strong>: Choose the level of access restriction you'd like to use on your site here. You can leave the site open to anyone with a WordPress account or an account on an external service like Google, CAS, or LDAP, or restrict it to WordPress users and only the external users that you specify via the <em>Access Lists</em>.", 'authorizer' ) . '</p>
				<p>' . __( "<strong>Which role should receive email notifications about pending users?</strong>: If you've restricted access to <strong>approved users</strong>, you can determine which WordPress users will receive a notification email everytime a new external user successfully logs in and is added to the pending list. All users of the specified role will receive an email, and the external user will get a message (specified below) telling them their access is pending approval.", 'authorizer' ) . '</p>
				<p>' . __( '<strong>What message should pending users see after attempting to log in?</strong>: Here you can specify the exact message a new external user will see once they try to log in to the site for the first time.', 'authorizer' ) . '</p>
			';
			$screen->add_help_tab(
				array(
					'id'      => 'help_auth_settings_access_login_content',
					'title'   => __( 'Login Access', 'authorizer' ),
					'content' => $help_auth_settings_access_login_content,
				)
			);

			// Add help tab for Public Access Settings.
			$help_auth_settings_access_public_content = '
				<p>' . __( "<strong>Who can view the site?</strong>: You can restrict the site's visibility by only allowing logged in users to see pages. If you do so, you can customize the specifics about the site's privacy using the settings below.", 'authorizer' ) . '</p>
				<p>' . __( "<strong>What pages (if any) should be available to everyone?</strong>: If you'd like to declare certain pages on your site as always public (such as the course syllabus, introduction, or calendar), specify those pages here. These pages will always be available no matter what access restrictions exist.", 'authorizer' ) . '</p>
				<p>' . __( '<strong>What happens to people without access when they visit a <em>private</em> page?</strong>: Choose the response anonymous users receive when visiting the site. You can choose between immediately taking them to the <strong>login screen</strong>, or simply showing them a <strong>message</strong>.', 'authorizer' ) . '</p>
				<p>' . __( '<strong>What happens to people without access when they visit a <em>public</em> page?</strong>: Choose the response anonymous users receive when visiting a page on the site marked as public. You can choose between showing them the page without any message, or showing them a the page with a message above the content.', 'authorizer' ) . '</p>
				<p>' . __( '<strong>What message should people without access see?</strong>: If you chose to show new users a <strong>message</strong> above, type that message here.', 'authorizer' ) . '</p>
			';
			$screen->add_help_tab(
				array(
					'id'      => 'help_auth_settings_access_public_content',
					'title'   => __( 'Public Access', 'authorizer' ),
					'content' => $help_auth_settings_access_public_content,
				)
			);

			// Add help tab for External Service (CAS, LDAP) Settings.
			$help_auth_settings_external_content = '
				<p>' . __( "<strong>Type of external service to authenticate against</strong>: Choose which authentication service type you will be using. You'll have to fill out different fields below depending on which service you choose.", 'authorizer' ) . '</p>
				<p>' . __( '<strong>Enable Google Logins</strong>: Choose if you want to allow users to log in with their Google Account credentials. You will need to enter your API Client ID and Secret to enable Google Logins.', 'authorizer' ) . '</p>
				<p>' . __( '<strong>Enable CAS Logins</strong>: Choose if you want to allow users to log in with via CAS (Central Authentication Service). You will need to enter details about your CAS server (host, port, and path) to enable CAS Logins.', 'authorizer' ) . '</p>
				<p>' . __( '<strong>Enable LDAP Logins</strong>: Choose if you want to allow users to log in with their LDAP (Lightweight Directory Access Protocol) credentials. You will need to enter details about your LDAP server (host, port, search base, uid attribute, directory user, directory user password, and whether to use TLS) to enable Google Logins.', 'authorizer' ) . '</p>
				<p>' . __( '<strong>Default role for new CAS users</strong>: Specify which role new external users will get by default. Be sure to choose a role with limited permissions!', 'authorizer' ) . '</p>
				<p><strong><em>' . __( 'If you enable Google logins:', 'authorizer' ) . '</em></strong></p>
				<ul>
					<li>' . __( "<strong>Google Client ID</strong>: You can generate this ID by creating a new Project in the <a href='https://cloud.google.com/console'>Google Developers Console</a>. A Client ID typically looks something like this: 1234567890123-kdjr85yt6vjr6d8g7dhr8g7d6durjf7g.apps.googleusercontent.com", 'authorizer' ) . '</li>
					<li>' . __( "<strong>Google Client Secret</strong>: You can generate this secret by creating a new Project in the <a href='https://cloud.google.com/console'>Google Developers Console</a>. A Client Secret typically looks something like this: sDNgX5_pr_5bly-frKmvp8jT", 'authorizer' ) . '</li>
				</ul>
				<p><strong><em>' . __( 'If you enable CAS logins:', 'authorizer' ) . '</em></strong></p>
				<ul>
					<li>' . __( '<strong>CAS server hostname</strong>: Enter the hostname of the CAS server you authenticate against (e.g., authn.example.edu).', 'authorizer' ) . '</li>
					<li>' . __( '<strong>CAS server port</strong>: Enter the port on the CAS server to connect to (e.g., 443).', 'authorizer' ) . '</li>
					<li>' . __( '<strong>CAS server path/context</strong>: Enter the path to the login endpoint on the CAS server (e.g., /cas).', 'authorizer' ) . '</li>
					<li>' . __( "<strong>CAS attribute containing first name</strong>: Enter the CAS attribute that has the user's first name. When this user first logs in, their WordPress account will have their first name retrieved from CAS and added to their WordPress profile.", 'authorizer' ) . '</li>
					<li>' . __( "<strong>CAS attribute containing last name</strong>: Enter the CAS attribute that has the user's last name. When this user first logs in, their WordPress account will have their last name retrieved from CAS and added to their WordPress profile.", 'authorizer' ) . '</li>
					<li>' . __( '<strong>CAS attribute update</strong>: Select whether the first and last names retrieved from CAS should overwrite any value the user has entered in the first and last name fields in their WordPress profile. If this is not set, this only happens the first time they log in.', 'authorizer' ) . '</li>
				</ul>
				<p><strong><em>' . __( 'If you enable LDAP logins:', 'authorizer' ) . '</em></strong></p>
				<ul>
					<li>' . __( '<strong>LDAP Host</strong>: Enter the URL of the LDAP server you authenticate against.', 'authorizer' ) . '</li>
					<li>' . __( '<strong>LDAP Port</strong>: Enter the port number that the LDAP server listens on.', 'authorizer' ) . '</li>
					<li>' . __( '<strong>LDAP Search Base</strong>: Enter the LDAP string that represents the search base, e.g., ou=people,dc=example,dc=edu', 'authorizer' ) . '</li>
					<li>' . __( '<strong>LDAP attribute containing username</strong>: Enter the name of the LDAP attribute that contains the usernames used by those attempting to log in. The plugin will search on this attribute to find the cn to bind against for login attempts.', 'authorizer' ) . '</li>
					<li>' . __( '<strong>LDAP Directory User</strong>: Enter the name of the LDAP user that has permissions to browse the directory.', 'authorizer' ) . '</li>
					<li>' . __( '<strong>LDAP Directory User Password</strong>: Enter the password for the LDAP user that has permission to browse the directory.', 'authorizer' ) . '</li>
					<li>' . __( '<strong>Use TLS</strong>: Select whether all communication with the LDAP server should be performed over a TLS-secured connection.', 'authorizer' ) . '</li>
					<li>' . __( "<strong>Custom lost password URL</strong>: The WordPress login page contains a link to recover a lost password. If you have external users who shouldn't change the password on their WordPress account, point them to the appropriate location to change the password on their external authentication service here.", 'authorizer' ) . '</li>
					<li>' . __( "<strong>LDAP attribute containing first name</strong>: Enter the LDAP attribute that has the user's first name. When this user first logs in, their WordPress account will have their first name retrieved from LDAP and added to their WordPress profile.", 'authorizer' ) . '</li>
					<li>' . __( "<strong>LDAP attribute containing last name</strong>: Enter the LDAP attribute that has the user's last name. When this user first logs in, their WordPress account will have their last name retrieved from LDAP and added to their WordPress profile.", 'authorizer' ) . '</li>
					<li>' . __( '<strong>LDAP attribute update</strong>: Select whether the first and last names retrieved from LDAP should overwrite any value the user has entered in the first and last name fields in their WordPress profile. If this is not set, this only happens the first time they log in.', 'authorizer' ) . '</li>
				</ul>
			';
			$screen->add_help_tab(
				array(
					'id'      => 'help_auth_settings_external_content',
					'title'   => __( 'External Service', 'authorizer' ),
					'content' => $help_auth_settings_external_content,
				)
			);

			// Add help tab for Advanced Settings.
			$help_auth_settings_advanced_content = '
				<p>' . __( '<strong>Limit invalid login attempts</strong>: Choose how soon (and for how long) to restrict access to individuals (or bots) making repeated invalid login attempts. You may set a shorter delay first, and then a longer delay after repeated invalid attempts; you may also set how much time must pass before the delays will be reset to normal.', 'authorizer' ) . '</p>
				<p>' . __( '<strong>Hide WordPress Logins</strong>: If you want to hide the WordPress username and password fields and the Log In button on the wp-login screen, enable this option. Note: You can always access the WordPress logins by adding external=wordpress to the wp-login URL, like so:', 'authorizer' ) . ' <a href="' . wp_login_url() . '?external=wordpress" target="_blank">' . wp_login_url() . '?external=wordpress</a>.</p>
				<p>' . __( "<strong>Custom WordPress login branding</strong>: If you'd like to use custom branding on the WordPress login page, select that here. You will need to use the `authorizer_add_branding_option` filter in your theme to add it. You can see an example theme that implements this filter in the plugin directory under sample-theme-add-branding.", 'authorizer' ) . '</p>
			';
			$screen->add_help_tab(
				array(
					'id'      => 'help_auth_settings_advanced_content',
					'title'   => __( 'Advanced', 'authorizer' ),
					'content' => $help_auth_settings_advanced_content,
				)
			);
		}



		/**
		 * ***************************
		 * Multisite: Network Admin Options page
		 * ***************************
		 */


		/**
		 * Network Admin menu item
		 *
		 * Action: network_admin_menu
		 *
		 * @return void
		 */
		public function network_admin_menu() {
			// @see http://codex.wordpress.org/Function_Reference/add_menu_page
			add_menu_page(
				'Authorizer',
				'Authorizer',
				'manage_network_options',
				'authorizer',
				array( $this, 'create_network_admin_page' ),
				'dashicons-groups',
				89 // Position.
			);
		}


		/**
		 * Output the HTML for the options page.
		 */
		public function create_network_admin_page() {
			if ( ! current_user_can( 'manage_network_options' ) ) {
				wp_die( wp_kses( __( 'You do not have sufficient permissions to access this page.', 'authorizer' ), $this->allowed_html ) );
			}
			$auth_settings = get_blog_option( $this->current_site_blog_id, 'auth_multisite_settings', array() );
			?>
			<div class="wrap">
				<form method="post" action="" autocomplete="off">
					<h2><?php esc_html_e( 'Authorizer Settings', 'authorizer' ); ?></h2>
					<p><?php echo wp_kses( __( 'Most <strong>Authorizer</strong> settings are set in the individual sites, but you can specify a few options here that apply to <strong>all sites in the network</strong>. These settings will override settings in the individual sites.', 'authorizer' ), $this->allowed_html ); ?></p>

					<input type="checkbox" id="auth_settings_multisite_override" name="auth_settings[multisite_override]" value="1"<?php checked( 1 === intval( $auth_settings['multisite_override'] ) ); ?> /><label for="auth_settings_multisite_override"><?php esc_html_e( 'Override individual site settings with the settings below', 'authorizer' ); ?></label>

					<div id="auth_multisite_settings_disabled_overlay" style="display: none;"></div>

					<div class="wrap" id="auth_multisite_settings">
						<?php $this->print_section_info_tabs( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?>

						<?php wp_nonce_field( 'save_auth_settings', 'nonce_save_auth_settings' ); ?>

						<?php // Custom access lists (for network, we only really want approved list, not pending or blocked). ?>
						<div id="section_info_access_lists" class="section_info">
							<p><?php esc_html_e( 'Manage who has access to all sites in the network.', 'authorizer' ); ?></p>
						</div>
						<table class="form-table"><tbody>
							<tr>
								<th scope="row"><?php esc_html_e( 'Who can log in to sites in this network?', 'authorizer' ); ?></th>
								<td><?php $this->print_radio_auth_access_who_can_login( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'Who can view sites in this network?', 'authorizer' ); ?></th>
								<td><?php $this->print_radio_auth_access_who_can_view( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'Approved Users (All Sites)', 'authorizer' ); ?><br /><small><em><?php echo wp_kses( __( 'Note: these users will <strong>not</strong> receive welcome emails when approved. Only users approved from individual sites can receive these messages.', 'authorizer' ), $this->allowed_html ); ?></em></small></th>
								<td><?php $this->print_combo_auth_access_users_approved( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
						</tbody></table>

						<?php $this->print_section_info_external(); ?>
						<table class="form-table"><tbody>
							<tr>
								<th scope="row"><?php esc_html_e( 'Default role for new users', 'authorizer' ); ?></th>
								<td><?php $this->print_select_auth_access_default_role( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'Google Logins', 'authorizer' ); ?></th>
								<td><?php $this->print_checkbox_auth_external_google( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'Google Client ID', 'authorizer' ); ?></th>
								<td><?php $this->print_text_google_clientid( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'Google Client Secret', 'authorizer' ); ?></th>
								<td><?php $this->print_text_google_clientsecret( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'Google Hosted Domain', 'authorizer' ); ?></th>
								<td><?php $this->print_text_google_hosteddomain( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'CAS Logins', 'authorizer' ); ?></th>
								<td><?php $this->print_checkbox_auth_external_cas( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'CAS Custom Label', 'authorizer' ); ?></th>
								<td><?php $this->print_text_cas_custom_label( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'CAS server hostname', 'authorizer' ); ?></th>
								<td><?php $this->print_text_cas_host( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'CAS server port', 'authorizer' ); ?></th>
								<td><?php $this->print_text_cas_port( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'CAS server path/context', 'authorizer' ); ?></th>
								<td><?php $this->print_text_cas_path( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'CAS server version', 'authorizer' ); ?></th>
								<td><?php $this->print_select_cas_version( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'CAS attribute containing email', 'authorizer' ); ?></th>
								<td><?php $this->print_text_cas_attr_email( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'CAS attribute containing first name', 'authorizer' ); ?></th>
								<td><?php $this->print_text_cas_attr_first_name( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'CAS attribute containing last name', 'authorizer' ); ?></th>
								<td><?php $this->print_text_cas_attr_last_name( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'CAS attribute update', 'authorizer' ); ?></th>
								<td><?php $this->print_checkbox_cas_attr_update_on_login( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'CAS automatic login', 'authorizer' ); ?></th>
								<td><?php $this->print_checkbox_cas_auto_login( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'LDAP Logins', 'authorizer' ); ?></th>
								<td><?php $this->print_checkbox_auth_external_ldap( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'LDAP Host', 'authorizer' ); ?></th>
								<td><?php $this->print_text_ldap_host( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'LDAP Port', 'authorizer' ); ?></th>
								<td><?php $this->print_text_ldap_port( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'Use TLS', 'authorizer' ); ?></th>
								<td><?php $this->print_checkbox_ldap_tls( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'LDAP Search Base', 'authorizer' ); ?></th>
								<td><?php $this->print_text_ldap_search_base( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'LDAP attribute containing username', 'authorizer' ); ?></th>
								<td><?php $this->print_text_ldap_uid( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'LDAP attribute containing email', 'authorizer' ); ?></th>
								<td><?php $this->print_text_ldap_attr_email( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'LDAP Directory User', 'authorizer' ); ?></th>
								<td><?php $this->print_text_ldap_user( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'LDAP Directory User Password', 'authorizer' ); ?></th>
								<td><?php $this->print_password_ldap_password( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'Custom lost password URL', 'authorizer' ); ?></th>
								<td><?php $this->print_text_ldap_lostpassword_url( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'LDAP attribute containing first name', 'authorizer' ); ?></th>
								<td><?php $this->print_text_ldap_attr_first_name( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'LDAP attribute containing last name', 'authorizer' ); ?></th>
								<td><?php $this->print_text_ldap_attr_last_name( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'LDAP attribute update', 'authorizer' ); ?></th>
								<td><?php $this->print_checkbox_ldap_attr_update_on_login( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
						</tbody></table>

						<?php $this->print_section_info_advanced(); ?>
						<table class="form-table"><tbody>
							<tr>
								<th scope="row"><?php esc_html_e( 'Limit invalid login attempts', 'authorizer' ); ?></th>
								<td><?php $this->print_text_auth_advanced_lockouts( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'Hide WordPress Logins', 'authorizer' ); ?></th>
								<td><?php $this->print_checkbox_auth_advanced_hide_wp_login( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'Number of users per page', 'authorizer' ); ?></th>
								<td><?php $this->print_text_auth_advanced_users_per_page( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'Approved users sort method', 'authorizer' ); ?></th>
								<td><?php $this->print_select_auth_advanced_users_sort_by( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'Approved users sort order', 'authorizer' ); ?></th>
								<td><?php $this->print_select_auth_advanced_users_sort_order( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'Show Dashboard Widget', 'authorizer' ); ?></th>
								<td><?php $this->print_checkbox_auth_advanced_widget_enabled( array( WP_Plugin_Authorizer::NETWORK_CONTEXT => true ) ); ?></td>
							</tr>
						</tbody></table>

						<br class="clear" />
					</div>
					<input type="button" name="submit" id="submit" class="button button-primary" value="<?php esc_attr_e( 'Save Changes', 'authorizer' ); ?>" onclick="saveAuthMultisiteSettings(this);" />
				</form>
			</div>
			<?php
		}


		/**
		 * Save multisite settings (ajax call).
		 *
		 * Action: wp_ajax_save_auth_multisite_settings
		 */
		public function ajax_save_auth_multisite_settings() {
			// Fail silently if current user doesn't have permissions.
			if ( ! current_user_can( 'manage_network_options' ) ) {
				die( '' );
			}

			// Make sure nonce exists.
			if ( empty( $_POST['nonce'] ) ) {
				die( '' );
			}

			// Nonce check.
			if ( ! wp_verify_nonce( sanitize_key( $_POST['nonce'] ), 'save_auth_settings' ) ) {
				die( '' );
			}

			// Assert multisite.
			if ( ! is_multisite() ) {
				die( '' );
			}

			// Get multisite settings.
			$auth_multisite_settings = get_blog_option( $this->current_site_blog_id, 'auth_multisite_settings', array() );

			// Sanitize settings.
			$auth_multisite_settings = $this->sanitize_options( $_POST );

			// Filter options to only the allowed values (multisite options are a subset of all options).
			$allowed                 = array(
				'multisite_override',
				'access_who_can_login',
				'access_who_can_view',
				'access_default_role',
				'google',
				'google_clientid',
				'google_clientsecret',
				'google_hosteddomain',
				'cas',
				'cas_custom_label',
				'cas_host',
				'cas_port',
				'cas_path',
				'cas_version',
				'cas_attr_email',
				'cas_attr_first_name',
				'cas_attr_last_name',
				'cas_attr_update_on_login',
				'cas_auto_login',
				'ldap',
				'ldap_host',
				'ldap_port',
				'ldap_tls',
				'ldap_search_base',
				'ldap_uid',
				'ldap_attr_email',
				'ldap_user',
				'ldap_password',
				'ldap_lostpassword_url',
				'ldap_attr_first_name',
				'ldap_attr_last_name',
				'ldap_attr_update_on_login',
				'advanced_lockouts',
				'advanced_hide_wp_login',
				'advanced_users_per_page',
				'advanced_users_sort_by',
				'advanced_users_sort_order',
				'advanced_widget_enabled',
			);
			$auth_multisite_settings = array_intersect_key( $auth_multisite_settings, array_flip( $allowed ) );

			// Update multisite settings in database.
			update_blog_option( $this->current_site_blog_id, 'auth_multisite_settings', $auth_multisite_settings );

			// Return 'success' value to AJAX call.
			die( 'success' );
		}



		/**
		 * ***************************
		 * Dashboard widget
		 * ***************************
		 */



		/**
		 * Load Authorizer dashboard widget if it's enabled.
		 *
		 * Action: wp_dashboard_setup
		 */
		public function add_dashboard_widgets() {
			$widget_enabled = $this->get_plugin_option( 'advanced_widget_enabled', WP_Plugin_Authorizer::SINGLE_CONTEXT, 'allow override' ) === '1';

			// Load authorizer dashboard widget if it's enabled and user has permission.
			if ( current_user_can( 'create_users' ) && $widget_enabled ) {
				// Add dashboard widget for adding/editing users with access.
				wp_add_dashboard_widget( 'auth_dashboard_widget', __( 'Authorizer Settings', 'authorizer' ), array( $this, 'add_auth_dashboard_widget' ) );
			}
		}


		/**
		 * Render Authorizer dashboard widget (callback).
		 */
		public function add_auth_dashboard_widget() {
			?>
			<form method="post" id="auth_settings_access_form" action="">
				<?php $this->print_section_info_access_login(); ?>
				<div>
					<h2><?php esc_html_e( 'Pending Users', 'authorizer' ); ?></h2>
					<?php $this->print_combo_auth_access_users_pending(); ?>
				</div>
				<div>
					<h2><?php esc_html_e( 'Approved Users', 'authorizer' ); ?></h2>
					<?php $this->print_combo_auth_access_users_approved(); ?>
				</div>
				<div>
					<h2><?php esc_html_e( 'Blocked Users', 'authorizer' ); ?></h2>
					<?php $this->print_combo_auth_access_users_blocked(); ?>
				</div>
				<br class="clear" />
			</form>
			<?php
		}



		/**
		 * ***************************
		 * AJAX Actions
		 * ***************************
		 */



		/**
		 * Re-render the Approved User list (usually triggered if pager params have
		 * changed, e.g., current page, search term, sort order).
		 *
		 * Action: wp_ajax_refresh_approved_user_list
		 *
		 * @return void
		 */
		public function ajax_refresh_approved_user_list() {
			// Fail silently if current user doesn't have permissions.
			if ( ! current_user_can( 'create_users' ) ) {
				die( '' );
			}

			// Nonce check.
			if ( empty( $_POST['nonce'] ) || ! wp_verify_nonce( sanitize_key( $_POST['nonce'] ), 'save_auth_settings' ) ) {
				die( '' );
			}

			// Fail if required post data doesn't exist.
			if ( ! array_key_exists( 'paged', $_REQUEST ) ) {
				die( '' );
			}

			// Get defaults.
			$success          = true;
			$message          = '';
			$is_network_admin = isset( $_REQUEST['is_network_admin'] ) && '1' === $_REQUEST['is_network_admin'];

			// Get user list.
			$option               = 'access_users_approved';
			$admin_mode           = is_multisite() && $is_network_admin ? WP_Plugin_Authorizer::NETWORK_CONTEXT : WP_Plugin_Authorizer::SINGLE_CONTEXT;
			$auth_settings_option = $this->get_plugin_option( $option, $admin_mode, 'no override' );
			$auth_settings_option = is_array( $auth_settings_option ) ? $auth_settings_option : array();

			// Get multisite approved users (will be added to top of list, greyed out).
			$auth_override_multisite        = $this->get_plugin_option( 'advanced_override_multisite' );
			$auth_multisite_settings        = $this->get_plugin_options( WP_Plugin_Authorizer::NETWORK_CONTEXT );
			$auth_settings_option_multisite = array();
			if (
				is_multisite() &&
				! $is_network_admin &&
				1 !== intval( $auth_override_multisite ) &&
				array_key_exists( 'multisite_override', $auth_multisite_settings ) &&
				'1' === $auth_multisite_settings['multisite_override']
			) {
				$auth_settings_option_multisite = $this->get_plugin_option( $option, WP_Plugin_Authorizer::NETWORK_CONTEXT, 'allow override' );
				$auth_settings_option_multisite = is_array( $auth_settings_option_multisite ) ? $auth_settings_option_multisite : array();
				// Add multisite users to the beginning of the main user array.
				foreach ( array_reverse( $auth_settings_option_multisite ) as $approved_user ) {
					$approved_user['multisite_user'] = true;
					array_unshift( $auth_settings_option, $approved_user );
				}
			}

			// Get custom usermeta field to show.
			$advanced_usermeta = $this->get_plugin_option( 'advanced_usermeta' );

			// Filter user list to search terms.
			if ( ! empty( $_REQUEST['search'] ) ) {
				$search_term          = sanitize_text_field( wp_unslash( $_REQUEST['search'] ) );
				$auth_settings_option = array_filter(
					$auth_settings_option, function ( $user ) use ( $search_term ) {
						return stripos( $user['email'], $search_term ) !== false ||
						stripos( $user['role'], $search_term ) !== false ||
						stripos( $user['date_added'], $search_term ) !== false;
					}
				);
			}

			// Sort user list.
			$sort_by        = $this->get_plugin_option( 'advanced_users_sort_by', WP_Plugin_Authorizer::SINGLE_CONTEXT, 'allow override' ); // email, role, date_added (registered), created (date approved).
			$sort_order     = $this->get_plugin_option( 'advanced_users_sort_order', WP_Plugin_Authorizer::SINGLE_CONTEXT, 'allow override' ); // asc or desc.
			$sort_dimension = array();
			if ( in_array( $sort_by, array( 'email', 'role', 'date_added' ), true ) ) {
				foreach ( $auth_settings_option as $key => $user ) {
					if ( 'date_added' === $sort_by ) {
						$sort_dimension[ $key ] = date( 'Ymd', strtotime( $user[ $sort_by ] ) );
					} else {
						$sort_dimension[ $key ] = strtolower( $user[ $sort_by ] );
					}
				}
				$sort_order = 'asc' === $sort_order ? SORT_ASC : SORT_DESC;
				array_multisort( $sort_dimension, $sort_order, $auth_settings_option );
			} elseif ( 'created' === $sort_by && 'asc' !== $sort_order ) {
				// If default sort method and reverse order, just reverse the array.
				$auth_settings_option = array_reverse( $auth_settings_option );
			}

			// Ensure array keys run from 0..max (keys in database will be the original,
			// index, and removing users will not reorder the array keys of other users).
			$auth_settings_option = array_values( $auth_settings_option );

			// Get pager params.
			$total_users    = count( $auth_settings_option );
			$users_per_page = intval( $this->get_plugin_option( 'advanced_users_per_page', WP_Plugin_Authorizer::SINGLE_CONTEXT, 'allow override' ) );
			$current_page   = isset( $_REQUEST['paged'] ) ? intval( $_REQUEST['paged'] ) : 1;
			$total_pages    = ceil( $total_users / $users_per_page );
			if ( $total_pages < 1 ) {
				$total_pages = 1;
			}

			// Make sure current_page is between 1 and max pages.
			if ( $current_page < 1 ) {
				$current_page = 1;
			} elseif ( $current_page > $total_pages ) {
				$current_page = $total_pages;
			}

			// Render user list.
			ob_start();
			$offset = ( $current_page - 1 ) * $users_per_page;
			$max    = min( $offset + $users_per_page, count( $auth_settings_option ) );
			for ( $key = $offset; $key < $max; $key++ ) :
				$approved_user = $auth_settings_option[ $key ];
				if ( empty( $approved_user ) || count( $approved_user ) < 1 ) :
					continue;
				endif;
				$this->render_user_element( $approved_user, $key, $option, $admin_mode, $advanced_usermeta );
			endfor;

			// Send response to client.
			$response = array(
				'success'          => $success,
				'message'          => $message,
				'html'             => ob_get_clean(),
				/* TRANSLATORS: %s: number of users */
				'total_users_html' => sprintf( _n( '%s user', '%s users', $total_users, 'authorizer' ), number_format_i18n( $total_users ) ),
				'total_pages_html' => number_format_i18n( $total_pages ),
				'total_pages'      => $total_pages,
			);
			header( 'content-type: application/json' );
			echo wp_json_encode( $response );
			exit;
		}


		/**
		 * Fired on a change event from the optional usermeta field in the approved
		 * user list. Updates the selected usermeta value, or saves it in the user's
		 * approved list entry if the user hasn't logged in yet and created a
		 * WordPress account.
		 *
		 * Action: wp_ajax_update_auth_usermeta
		 *
		 * @return void
		 */
		public function ajax_update_auth_usermeta() {
			// Fail silently if current user doesn't have permissions.
			if ( ! current_user_can( 'create_users' ) ) {
				die( '' );
			}

			// Nonce check.
			if ( empty( $_POST['nonce'] ) || ! wp_verify_nonce( sanitize_key( $_POST['nonce'] ), 'save_auth_settings' ) ) {
				die( '' );
			}

			// Fail if required post data doesn't exist.
			if ( ! isset( $_REQUEST['email'], $_REQUEST['usermeta'] ) ) {
				die( '' );
			}

			// Get values to update from post data.
			$email      = sanitize_email( wp_unslash( $_REQUEST['email'] ) );
			$meta_value = sanitize_meta( 'authorizer-usermeta', wp_unslash( $_REQUEST['usermeta'] ), 'user' );
			$meta_key   = $this->get_plugin_option( 'advanced_usermeta' );

			// If user doesn't exist, save usermeta selection to authorizer
			// list. This value will get saved to usermeta when the user first
			// logs in (i.e., when their WordPress account is created).
			$wp_user = get_user_by( 'email', $email );
			if ( ! $wp_user ) {
				// Look through multisite approved users and add a usermeta
				// reference for the current blog if the user is found.
				$auth_multisite_settings_access_users_approved               = is_multisite() ? get_blog_option( $this->current_site_blog_id, 'auth_multisite_settings_access_users_approved', array() ) : array();
				$should_update_auth_multisite_settings_access_users_approved = false;
				foreach ( $auth_multisite_settings_access_users_approved as $index => $approved_user ) {
					if ( 0 === strcasecmp( $email, $approved_user['email'] ) ) {
						if ( ! is_array( $auth_multisite_settings_access_users_approved[ $index ]['usermeta'] ) ) {
							// Initialize the array of usermeta for each blog this user belongs to.
							$auth_multisite_settings_access_users_approved[ $index ]['usermeta'] = array();
						} else {
							// There is already usermeta associated with this
							// preapproved user; iterate through it and make
							// sure it's not for old meta_keys (delete it if
							// so). This can happen if someone changes the
							// usermeta key in authorizer options, and we don't
							// want to hang on to old data.
							foreach ( $auth_multisite_settings_access_users_approved[ $index ]['usermeta'] as $blog_id => $usermeta ) {
								if ( array_key_exists( 'meta_key', $usermeta ) && $usermeta['meta_key'] === $meta_key ) {
									continue;
								} else {
									unset( $auth_multisite_settings_access_users_approved[ $index ]['usermeta'][ $blog_id ] );
								}
							}
						}
						$auth_multisite_settings_access_users_approved[ $index ]['usermeta'][ get_current_blog_id() ] = array(
							'meta_key'   => $meta_key,
							'meta_value' => $meta_value,
						);
						$should_update_auth_multisite_settings_access_users_approved                                  = true;
					}
				}
				if ( $should_update_auth_multisite_settings_access_users_approved ) {
					update_blog_option( $this->current_site_blog_id, 'auth_multisite_settings_access_users_approved', $auth_multisite_settings_access_users_approved );
				}

				// Look through the approved users (of the current blog in a
				// multisite install, or just of the single site) and add a
				// usermeta reference if the user is found.
				$auth_settings_access_users_approved               = $this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::SINGLE_CONTEXT );
				$should_update_auth_settings_access_users_approved = false;
				foreach ( $auth_settings_access_users_approved as $index => $approved_user ) {
					if ( 0 === strcasecmp( $email, $approved_user['email'] ) ) {
						$auth_settings_access_users_approved[ $index ]['usermeta'] = array(
							'meta_key'   => $meta_key,
							'meta_value' => $meta_value,
						);
						$should_update_auth_settings_access_users_approved         = true;
					}
				}
				if ( $should_update_auth_settings_access_users_approved ) {
					update_option( 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
				}
			} else {
				// Update user's usermeta value for usermeta key stored in authorizer options.
				if ( strpos( $meta_key, 'acf___' ) === 0 && class_exists( 'acf' ) ) {
					// We have an ACF field value, so use the ACF function to update it.
					update_field( str_replace( 'acf___', '', $meta_key ), $meta_value, 'user_' . $wp_user->ID );
				} else {
					// We have a normal usermeta value, so just update it via the WordPress function.
					update_user_meta( $wp_user->ID, $meta_key, $meta_value );
				}
			}

			// Return 'success' value to AJAX call.
			die( 'success' );
		}


		/**
		 * Fired on a change event from the user fields in the user lists. Updates
		 * the selected user value.
		 *
		 * Action: wp_ajax_update_auth_user
		 *
		 * @return void
		 */
		public function ajax_update_auth_user() {
			// Fail silently if current user doesn't have permissions.
			if ( ! current_user_can( 'create_users' ) ) {
				die( '' );
			}

			// Nonce check.
			if ( empty( $_POST['nonce'] ) || ! wp_verify_nonce( sanitize_key( $_POST['nonce'] ), 'save_auth_settings' ) ) {
				die( '' );
			}

			// Fail if requesting a change to an invalid setting.
			if ( ! isset( $_POST['setting'] ) || ! in_array( wp_unslash( $_POST['setting'] ), array( 'access_users_pending', 'access_users_approved', 'access_users_blocked' ), true ) ) {
				die( '' );
			}

			// Track any emails that couldn't be added (used when adding users).
			$invalid_emails = array();

			// Editing a pending list entry.
			if ( 'access_users_pending' === $_POST['setting'] ) {
				// Sanitize posted data.
				$access_users_pending = array();
				if ( isset( $_POST['access_users_pending'] ) && is_array( $_POST['access_users_pending'] ) ) {
					$access_users_pending = $this->sanitize_update_auth_users( wp_unslash( $_POST['access_users_pending'] ) );
				}

				// Deal with each modified user (add or remove).
				foreach ( $access_users_pending as $pending_user ) {

					if ( 'add' === $pending_user['edit_action'] ) {

						// Add new user to pending list and save (skip if it's
						// already there--someone else might have just done it).
						if ( ! $this->is_email_in_list( $pending_user['email'], 'pending' ) ) {
							$auth_settings_access_users_pending = $this->sanitize_user_list(
								$this->get_plugin_option( 'access_users_pending', WP_Plugin_Authorizer::SINGLE_CONTEXT )
							);
							array_push( $auth_settings_access_users_pending, $pending_user );
							update_option( 'auth_settings_access_users_pending', $auth_settings_access_users_pending );
						}
					} elseif ( 'remove' === $pending_user['edit_action'] ) {

						// Remove user from pending list and save.
						$auth_settings_access_users_pending = $this->get_plugin_option( 'access_users_pending', WP_Plugin_Authorizer::SINGLE_CONTEXT );
						foreach ( $auth_settings_access_users_pending as $key => $existing_user ) {
							if ( 0 === strcasecmp( $pending_user['email'], $existing_user['email'] ) ) {
								unset( $auth_settings_access_users_pending[ $key ] );
								update_option( 'auth_settings_access_users_pending', $auth_settings_access_users_pending );
								break;
							}
						}
					}
				}
			}

			// Editing an approved list entry.
			if ( 'access_users_approved' === $_POST['setting'] ) {
				// Sanitize posted data.
				$access_users_approved = array();
				if ( isset( $_POST['access_users_approved'] ) && is_array( $_POST['access_users_approved'] ) ) {
					$access_users_approved = $this->sanitize_update_auth_users( wp_unslash( $_POST['access_users_approved'] ) );
				}

				// Deal with each modified user (add, remove, or change_role).
				foreach ( $access_users_approved as $approved_user ) {
					// Skip blank entries.
					if ( strlen( $approved_user['email'] ) < 1 ) {
						continue;
					}

					// New user (create user, or add existing user to current site in multisite).
					if ( 'add' === $approved_user['edit_action'] ) {
						$new_user = get_user_by( 'email', $approved_user['email'] );
						if ( false !== $new_user ) {
							// If we're adding an existing multisite user, make sure their
							// newly-assigned role is updated on all sites they are already in.
							if ( is_multisite() && 'false' !== $approved_user['multisite_user'] ) {
								foreach ( get_blogs_of_user( $new_user->ID ) as $blog ) {
									add_user_to_blog( $blog->userblog_id, $new_user->ID, $approved_user['role'] );
								}
							}
							// If this user already has an account on another site in the network, add them to this site.
							if ( is_multisite() ) {
								add_user_to_blog( get_current_blog_id(), $new_user->ID, $approved_user['role'] );
							}
						} elseif ( $approved_user['local_user'] && 'false' !== $approved_user['local_user'] ) {
							// Create a WP account for this new *local* user and email the password.
							$plaintext_password = wp_generate_password(); // random password
							// If there's already a user with this username (e.g.,
							// johndoe/johndoe@gmail.com exists, and we're trying to add
							// johndoe/johndoe@example.com), use the full email address
							// as the username.
							$username = explode( '@', $approved_user['email'] );
							$username = $username[0];
							if ( get_user_by( 'login', $username ) !== false ) {
								$username = $this->lowercase( $approved_user['email'] );
							}
							if ( 'false' !== $approved_user['multisite_user'] ) {
								$result = wpmu_create_user(
									strtolower( $username ),
									$plaintext_password,
									$this->lowercase( $approved_user['email'] )
								);
							} else {
								$result = wp_insert_user(
									array(
										'user_login'      => strtolower( $username ),
										'user_pass'       => $plaintext_password,
										'first_name'      => '',
										'last_name'       => '',
										'user_email'      => $this->lowercase( $approved_user['email'] ),
										'user_registered' => date( 'Y-m-d H:i:s' ),
										'role'            => $approved_user['role'],
									)
								);
							}
							if ( ! is_wp_error( $result ) ) {
								// Email login credentials to new user.
								wp_new_user_notification( $result, null, 'both' );
							}
						}

						// Email new user welcome message if plugin option is set.
						$this->maybe_email_welcome_message( $approved_user['email'] );

						// Add new user to approved list and save (skip if it's
						// already there--someone else might have just done it).
						if ( 'false' !== $approved_user['multisite_user'] ) {
							if ( ! $this->is_email_in_list( $approved_user['email'], 'approved', 'multisite' ) ) {
								$auth_multisite_settings_access_users_approved = $this->sanitize_user_list(
									$this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::NETWORK_CONTEXT )
								);
								$approved_user['date_added']                   = date( 'M Y' );
								array_push( $auth_multisite_settings_access_users_approved, $approved_user );
								update_blog_option( $this->current_site_blog_id, 'auth_multisite_settings_access_users_approved', $auth_multisite_settings_access_users_approved );
							} else {
								$invalid_emails[] = $approved_user['email'];
							}
						} else {
							if ( ! $this->is_email_in_list( $approved_user['email'], 'approved' ) ) {
								$auth_settings_access_users_approved = $this->sanitize_user_list(
									$this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::SINGLE_CONTEXT )
								);
								$approved_user['date_added']         = date( 'M Y' );
								array_push( $auth_settings_access_users_approved, $approved_user );
								update_option( 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
							} else {
								$invalid_emails[] = $approved_user['email'];
							}
						}

						// If we've added a new multisite user, go through all pending/approved/blocked lists
						// on individual sites and remove this user from them (to prevent duplicate entries).
						if ( 'false' !== $approved_user['multisite_user'] && is_multisite() ) {
							$list_names = array( 'access_users_pending', 'access_users_approved', 'access_users_blocked' );
							// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
							$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
							foreach ( $sites as $site ) {
								$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
								foreach ( $list_names as $list_name ) {
									$user_list    = get_blog_option( $blog_id, 'auth_settings_' . $list_name, array() );
									$list_changed = false;
									foreach ( $user_list as $key => $user ) {
										if ( 0 === strcasecmp( $user['email'], $approved_user['email'] ) ) {
											unset( $user_list[ $key ] );
											$list_changed = true;
										}
									}
									if ( $list_changed ) {
										update_blog_option( $blog_id, 'auth_settings_' . $list_name, $user_list );
									}
								}
							}
						}
					} elseif ( 'remove' === $approved_user['edit_action'] ) { // Remove user from approved list and save (also remove their role if they have a WordPress account).
						if ( 'false' !== $approved_user['multisite_user'] ) {
							$auth_multisite_settings_access_users_approved = $this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::NETWORK_CONTEXT );
							foreach ( $auth_multisite_settings_access_users_approved as $key => $existing_user ) {
								if ( 0 === strcasecmp( $approved_user['email'], $existing_user['email'] ) ) {
									// Remove role of the associated WordPress user from all blogs (but don't delete the user).
									$user = get_user_by( 'email', $approved_user['email'] );
									if ( false !== $user ) {
										// Loop through all of the blogs this user is a member of and remove their capabilities.
										foreach ( get_blogs_of_user( $user->ID ) as $blog ) {
											remove_user_from_blog( $user->ID, $blog->userblog_id, '' );
										}
									}
									// Remove entry from Approved Users list.
									unset( $auth_multisite_settings_access_users_approved[ $key ] );
									update_blog_option( $this->current_site_blog_id, 'auth_multisite_settings_access_users_approved', $auth_multisite_settings_access_users_approved );
									break;
								}
							}
						} else {
							$auth_settings_access_users_approved = $this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::SINGLE_CONTEXT );
							foreach ( $auth_settings_access_users_approved as $key => $existing_user ) {
								if ( 0 === strcasecmp( $approved_user['email'], $existing_user['email'] ) ) {
									// Remove role of the associated WordPress user (but don't delete the user).
									$user = get_user_by( 'email', $approved_user['email'] );
									if ( false !== $user ) {
										$user->set_role( '' );
									}
									// Remove entry from Approved Users list.
									unset( $auth_settings_access_users_approved[ $key ] );
									update_option( 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
									break;
								}
							}
						}
					} elseif ( 'change_role' === $approved_user['edit_action'] ) { // Update user's role in WordPress.
						$changed_user = get_user_by( 'email', $approved_user['email'] );
						if ( $changed_user ) {
							if ( is_multisite() && 'false' !== $approved_user['multisite_user'] ) {
								foreach ( get_blogs_of_user( $changed_user->ID ) as $blog ) {
									add_user_to_blog( $blog->userblog_id, $changed_user->ID, $approved_user['role'] );
								}
							} else {
								$changed_user->set_role( $approved_user['role'] );
							}
						}

						if ( 'false' !== $approved_user['multisite_user'] ) {
							if ( $this->is_email_in_list( $approved_user['email'], 'approved', 'multisite' ) ) {
								$auth_multisite_settings_access_users_approved = $this->sanitize_user_list(
									$this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::NETWORK_CONTEXT )
								);
								foreach ( $auth_multisite_settings_access_users_approved as $key => $existing_user ) {
									if ( 0 === strcasecmp( $approved_user['email'], $existing_user['email'] ) ) {
										$auth_multisite_settings_access_users_approved[ $key ]['role'] = $approved_user['role'];
										break;
									}
								}
								update_blog_option( $this->current_site_blog_id, 'auth_multisite_settings_access_users_approved', $auth_multisite_settings_access_users_approved );
							}
						} else {
							// Update user's role in approved list and save.
							if ( $this->is_email_in_list( $approved_user['email'], 'approved' ) ) {
								$auth_settings_access_users_approved = $this->sanitize_user_list(
									$this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::SINGLE_CONTEXT )
								);
								foreach ( $auth_settings_access_users_approved as $key => $existing_user ) {
									if ( 0 === strcasecmp( $approved_user['email'], $existing_user['email'] ) ) {
										$auth_settings_access_users_approved[ $key ]['role'] = $approved_user['role'];
										break;
									}
								}
								update_option( 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
							}
						}
					}
				}
			}

			// Editing a blocked list entry.
			if ( 'access_users_blocked' === $_POST['setting'] ) {
				// Sanitize post data.
				$access_users_blocked = array();
				if ( isset( $_POST['access_users_blocked'] ) && is_array( $_POST['access_users_blocked'] ) ) {
					$access_users_blocked = $this->sanitize_update_auth_users(
						wp_unslash( $_POST['access_users_blocked'] ),
						array(
							'allow_wildcard_email' => true,
						)
					);
				}

				// Deal with each modified user (add or remove).
				foreach ( $access_users_blocked as $blocked_user ) {

					if ( 'add' === $blocked_user['edit_action'] ) {

						// Add auth_blocked usermeta for the user.
						$blocked_wp_user = get_user_by( 'email', $blocked_user['email'] );
						if ( false !== $blocked_wp_user ) {
							update_user_meta( $blocked_wp_user->ID, 'auth_blocked', 'yes' );
						}

						// Add new user to blocked list and save (skip if it's
						// already there--someone else might have just done it).
						if ( ! $this->is_email_in_list( $blocked_user['email'], 'blocked' ) ) {
							$auth_settings_access_users_blocked = $this->sanitize_user_list(
								$this->get_plugin_option( 'access_users_blocked', WP_Plugin_Authorizer::SINGLE_CONTEXT )
							);
							$blocked_user['date_added']         = date( 'M Y' );
							array_push( $auth_settings_access_users_blocked, $blocked_user );
							update_option( 'auth_settings_access_users_blocked', $auth_settings_access_users_blocked );
						} else {
							$invalid_emails[] = $blocked_user['email'];
						}
					} elseif ( 'remove' === $blocked_user['edit_action'] ) {

						// Remove auth_blocked usermeta for the user.
						$unblocked_user = get_user_by( 'email', $blocked_user['email'] );
						if ( false !== $unblocked_user ) {
							delete_user_meta( $unblocked_user->ID, 'auth_blocked', 'yes' );
						}

						// Remove user from blocked list and save.
						$auth_settings_access_users_blocked = $this->get_plugin_option( 'access_users_blocked', WP_Plugin_Authorizer::SINGLE_CONTEXT );
						foreach ( $auth_settings_access_users_blocked as $key => $existing_user ) {
							if ( 0 === strcasecmp( $blocked_user['email'], $existing_user['email'] ) ) {
								unset( $auth_settings_access_users_blocked[ $key ] );
								update_option( 'auth_settings_access_users_blocked', $auth_settings_access_users_blocked );
								break;
							}
						}
					}
				}
			}

			// Send response to client.
			$response = array(
				'success'        => true,
				'invalid_emails' => $invalid_emails,
			);
			header( 'content-type: application/json' );
			echo wp_json_encode( $response );
			exit;
		}


		/**
		 * Sanitizes an array of user update commands coming from the AJAX handler in Authorizer Settings.
		 *
		 * Example $users array:
		 * array(
		 *   array(
		 *     edit_action: 'add' or 'remove' or 'change_role',
		 *     email: 'johndoe@example.com',
		 *     role: 'subscriber',
		 *     date_added: 'Jun 2014',
		 *     local_user: 'true' or 'false',
		 *     multisite_user: 'true' or 'false',
		 *   ),
		 *   ...
		 * )
		 *
		 * @param  array $users Users to edit.
		 * @param  array $args  Options (e.g., 'allow_wildcard_email' => true).
		 * @return array        Sanitized users to edit.
		 */
		private function sanitize_update_auth_users( $users = array(), $args = array() ) {
			if ( ! is_array( $users ) ) {
				$users = array();
			}
			if ( isset( $args['allow_wildcard_email'] ) && $args['allow_wildcard_email'] ) {
				$users = array_map( array( $this, 'sanitize_update_auth_user_allow_wildcard_email' ), $users );
			} else {
				$users = array_map( array( $this, 'sanitize_update_auth_user' ), $users );
			}

			// Remove any entries that failed email address validation.
			$users = array_filter( $users, array( $this, 'remove_invalid_auth_users' ) );

			return $users;
		}


		/**
		 * This array filter will remove any users who failed email address validation
		 * (which would set their email to a blank string).
		 * @param  array $user User data to check for a valid email.
		 * @return bool  Whether to filter out the user.
		 */
		private function remove_invalid_auth_users( $user ) {
			return isset( $user['email'] ) && strlen( $user['email'] ) > 0;
		}

		/**
		 * Callback for array_map in sanitize_update_auth_users().
		 *
		 * @param  array $user User data to sanitize.
		 * @return array       Sanitized user data.
		 */
		private function sanitize_update_auth_user( $user ) {
			if ( array_key_exists( 'edit_action', $user ) ) {
				$user['edit_action'] = sanitize_text_field( $user['edit_action'] );
			}
			if ( isset( $user['email'] ) ) {
				$user['email'] = sanitize_email( $user['email'] );
			}
			if ( isset( $user['role'] ) ) {
				$user['role'] = sanitize_text_field( $user['role'] );
			}
			if ( isset( $user['date_added'] ) ) {
				$user['date_added'] = sanitize_text_field( $user['date_added'] );
			}
			if ( isset( $user['local_user'] ) ) {
				$user['local_user'] = 'true' === $user['local_user'] ? 'true' : 'false';
			}
			if ( isset( $user['multisite_user'] ) ) {
				$user['multisite_user'] = 'true' === $user['multisite_user'] ? 'true' : 'false';
			}

			return $user;
		}



		/**
		 * Callback for array_map in sanitize_update_auth_users().
		 *
		 * @param  array $user User data to sanitize.
		 * @return array       Sanitized user data.
		 */
		private function sanitize_update_auth_user_allow_wildcard_email( $user ) {
			if ( array_key_exists( 'edit_action', $user ) ) {
				$user['edit_action'] = sanitize_text_field( $user['edit_action'] );
			}
			if ( isset( $user['email'] ) ) {
				if ( strpos( $user['email'], '@' ) === 0 ) {
					$user['email'] = sanitize_text_field( $user['email'] );
				} else {
					$user['email'] = sanitize_email( $user['email'] );
				}
			}
			if ( isset( $user['role'] ) ) {
				$user['role'] = sanitize_text_field( $user['role'] );
			}
			if ( isset( $user['date_added'] ) ) {
				$user['date_added'] = sanitize_text_field( $user['date_added'] );
			}
			if ( isset( $user['local_user'] ) ) {
				$user['local_user'] = 'true' === $user['local_user'] ? 'true' : 'false';
			}
			if ( isset( $user['multisite_user'] ) ) {
				$user['multisite_user'] = 'true' === $user['multisite_user'] ? 'true' : 'false';
			}

			return $user;
		}



		/**
		 * ***************************
		 * Helper functions
		 * ***************************
		 */


		/**
		 * Retrieves a specific plugin option from db. Multisite enabled.
		 *
		 * @param  string $option        Option name.
		 * @param  string $admin_mode    WP_Plugin_Authorizer::NETWORK_CONTEXT will retrieve the multisite value.
		 * @param  string $override_mode 'allow override' will retrieve the multisite value if it exists.
		 * @param  string $print_mode    'print overlay' will output overlay that hides this option on the settings page.
		 * @return mixed                 Option value, or null on failure.
		 */
		private function get_plugin_option( $option, $admin_mode = WP_Plugin_Authorizer::SINGLE_CONTEXT, $override_mode = 'no override', $print_mode = 'no overlay' ) {
			// Special case for user lists (they are saved seperately to prevent concurrency issues).
			if ( in_array( $option, array( 'access_users_pending', 'access_users_approved', 'access_users_blocked' ), true ) ) {
				$list = WP_Plugin_Authorizer::NETWORK_CONTEXT === $admin_mode ? array() : get_option( 'auth_settings_' . $option );
				if ( is_multisite() && WP_Plugin_Authorizer::NETWORK_CONTEXT === $admin_mode ) {
					$list = get_blog_option( $this->current_site_blog_id, 'auth_multisite_settings_' . $option, array() );
				}
				return $list;
			}

			// Get all plugin options.
			$auth_settings = $this->get_plugin_options( $admin_mode, $override_mode );

			// Set option to null if it wasn't found.
			if ( ! array_key_exists( $option, $auth_settings ) ) {
				return null;
			}

			// If requested and appropriate, print the overlay hiding the
			// single site option that is overridden by a multisite option.
			if (
				WP_Plugin_Authorizer::NETWORK_CONTEXT !== $admin_mode &&
				'allow override' === $override_mode &&
				'print overlay' === $print_mode &&
				array_key_exists( 'multisite_override', $auth_settings ) &&
				'1' === $auth_settings['multisite_override'] &&
				( ! array_key_exists( 'advanced_override_multisite', $auth_settings ) || 1 !== intval( $auth_settings['advanced_override_multisite'] ) )
			) {
				// Get original plugin options (not overridden value). We'll
				// show this old value behind the disabled overlay.
				// $auth_settings = $this->get_plugin_options( $admin_mode, 'no override' );
				// (This feature is disabled).
				//
				$name = "auth_settings[$option]";
				$id   = "auth_settings_$option";
				?>
				<div id="overlay-hide-auth_settings_<?php echo esc_attr( $option ); ?>" class="auth_multisite_override_overlay">
					<span class="overlay-note">
						<?php esc_html_e( 'This setting is overridden by a', 'authorizer' ); ?> <a href="<?php echo esc_attr( network_admin_url( 'admin.php?page=authorizer' ) ); ?>"><?php esc_html_e( 'multisite option', 'authorizer' ); ?></a>.
					</span>
				</div>
				<?php
			}

			// If we're getting an option in a site that has overridden the multisite override, make
			// sure we are returning the option value from that site (not the multisite value).
			if ( array_key_exists( 'advanced_override_multisite', $auth_settings ) && 1 === intval( $auth_settings['advanced_override_multisite'] ) ) {
				$auth_settings = $this->get_plugin_options( $admin_mode, 'no override' );
			}

			// Set option to null if it wasn't found.
			if ( ! array_key_exists( $option, $auth_settings ) ) {
				return null;
			}

			return $auth_settings[ $option ];
		}

		/**
		 * Retrieves all plugin options from db. Multisite enabled.
		 *
		 * @param  string $admin_mode    WP_Plugin_Authorizer::NETWORK_CONTEXT will retrieve the multisite value.
		 * @param  string $override_mode 'allow override' will retrieve the multisite value if it exists.
		 * @return mixed                 Option value, or null on failure.
		 */
		private function get_plugin_options( $admin_mode = WP_Plugin_Authorizer::SINGLE_CONTEXT, $override_mode = 'no override' ) {
			// Grab plugin settings (skip if in WP_Plugin_Authorizer::NETWORK_CONTEXT mode).
			$auth_settings = WP_Plugin_Authorizer::NETWORK_CONTEXT === $admin_mode ? array() : get_option( 'auth_settings' );

			// Initialize to default values if the plugin option doesn't exist.
			if ( false === $auth_settings ) {
				$auth_settings = $this->set_default_options();
			}

			// Merge multisite options if we're in a network and the current site hasn't overridden multisite settings.
			if ( is_multisite() && ( ! array_key_exists( 'advanced_override_multisite', $auth_settings ) || 1 !== intval( $auth_settings['advanced_override_multisite'] ) ) ) {
				// Get multisite options.
				$auth_multisite_settings = get_blog_option( $this->current_site_blog_id, 'auth_multisite_settings', array() );

				// Return the multisite options if we're viewing the network admin options page.
				// Otherwise override options with their multisite equivalents.
				if ( WP_Plugin_Authorizer::NETWORK_CONTEXT === $admin_mode ) {
					$auth_settings = $auth_multisite_settings;
				} elseif (
					'allow override' === $override_mode &&
					array_key_exists( 'multisite_override', $auth_multisite_settings ) &&
					'1' === $auth_multisite_settings['multisite_override']
				) {
					// Keep track of the multisite override selection.
					$auth_settings['multisite_override'] = $auth_multisite_settings['multisite_override'];

					/**
					 * Note: the options below should be the complete list of overridden
					 * options. It is *not* the complete list of all options (some options
					 * don't have a multisite equivalent).
					 */

					/**
					 * Note: access_users_approved, access_users_pending, and
					 * access_users_blocked do not get overridden. However, since
					 * access_users_approved has a multisite equivalent, you must retrieve
					 * them both seperately. This is done because the two lists should be
					 * treated differently.
					 *
					 * $approved_users    = $this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::SINGLE_CONTEXT );
					 * $ms_approved_users = $this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::NETWORK_CONTEXT );
					 */

					// Override external services (google, cas, or ldap) and associated options.
					$auth_settings['google']                    = $auth_multisite_settings['google'];
					$auth_settings['google_clientid']           = $auth_multisite_settings['google_clientid'];
					$auth_settings['google_clientsecret']       = $auth_multisite_settings['google_clientsecret'];
					$auth_settings['google_hosteddomain']       = $auth_multisite_settings['google_hosteddomain'];
					$auth_settings['cas']                       = $auth_multisite_settings['cas'];
					$auth_settings['cas_custom_label']          = $auth_multisite_settings['cas_custom_label'];
					$auth_settings['cas_host']                  = $auth_multisite_settings['cas_host'];
					$auth_settings['cas_port']                  = $auth_multisite_settings['cas_port'];
					$auth_settings['cas_path']                  = $auth_multisite_settings['cas_path'];
					$auth_settings['cas_version']               = $auth_multisite_settings['cas_version'];
					$auth_settings['cas_attr_email']            = $auth_multisite_settings['cas_attr_email'];
					$auth_settings['cas_attr_first_name']       = $auth_multisite_settings['cas_attr_first_name'];
					$auth_settings['cas_attr_last_name']        = $auth_multisite_settings['cas_attr_last_name'];
					$auth_settings['cas_attr_update_on_login']  = $auth_multisite_settings['cas_attr_update_on_login'];
					$auth_settings['cas_auto_login']            = $auth_multisite_settings['cas_auto_login'];
					$auth_settings['ldap']                      = $auth_multisite_settings['ldap'];
					$auth_settings['ldap_host']                 = $auth_multisite_settings['ldap_host'];
					$auth_settings['ldap_port']                 = $auth_multisite_settings['ldap_port'];
					$auth_settings['ldap_tls']                  = $auth_multisite_settings['ldap_tls'];
					$auth_settings['ldap_search_base']          = $auth_multisite_settings['ldap_search_base'];
					$auth_settings['ldap_uid']                  = $auth_multisite_settings['ldap_uid'];
					$auth_settings['ldap_attr_email']           = $auth_multisite_settings['ldap_attr_email'];
					$auth_settings['ldap_user']                 = $auth_multisite_settings['ldap_user'];
					$auth_settings['ldap_password']             = $auth_multisite_settings['ldap_password'];
					$auth_settings['ldap_lostpassword_url']     = $auth_multisite_settings['ldap_lostpassword_url'];
					$auth_settings['ldap_attr_first_name']      = $auth_multisite_settings['ldap_attr_first_name'];
					$auth_settings['ldap_attr_last_name']       = $auth_multisite_settings['ldap_attr_last_name'];
					$auth_settings['ldap_attr_update_on_login'] = $auth_multisite_settings['ldap_attr_update_on_login'];

					// Override access_who_can_login and access_who_can_view.
					$auth_settings['access_who_can_login'] = $auth_multisite_settings['access_who_can_login'];
					$auth_settings['access_who_can_view']  = $auth_multisite_settings['access_who_can_view'];

					// Override access_default_role.
					$auth_settings['access_default_role'] = $auth_multisite_settings['access_default_role'];

					// Override lockouts.
					$auth_settings['advanced_lockouts'] = $auth_multisite_settings['advanced_lockouts'];

					// Override Hide WordPress login.
					$auth_settings['advanced_hide_wp_login'] = $auth_multisite_settings['advanced_hide_wp_login'];

					// Override Users per page.
					$auth_settings['advanced_users_per_page'] = $auth_multisite_settings['advanced_users_per_page'];

					// Override Sort users by.
					$auth_settings['advanced_users_sort_by'] = $auth_multisite_settings['advanced_users_sort_by'];

					// Override Sort users order.
					$auth_settings['advanced_users_sort_order'] = $auth_multisite_settings['advanced_users_sort_order'];

					// Override Show Dashboard Widget.
					$auth_settings['advanced_widget_enabled'] = $auth_multisite_settings['advanced_widget_enabled'];
				}
			}
			return $auth_settings;
		}


		/**
		 * Remove user from authorizer lists when that user is deleted in WordPress.
		 *
		 * Action: delete_user
		 *
		 * @param  int $user_id User ID to remove.
		 * @return void
		 */
		public function remove_user_from_authorizer_when_deleted( $user_id ) {
			$user          = get_user_by( 'id', $user_id );
			$deleted_email = $user->user_email;

			// Remove user from pending/approved lists and save.
			$list_names = array( 'access_users_pending', 'access_users_approved' );
			foreach ( $list_names as $list_name ) {
				$user_list    = $this->sanitize_user_list( $this->get_plugin_option( $list_name, WP_Plugin_Authorizer::SINGLE_CONTEXT ) );
				$list_changed = false;
				foreach ( $user_list as $key => $existing_user ) {
					if ( 0 === strcasecmp( $deleted_email, $existing_user['email'] ) ) {
						$list_changed = true;
						unset( $user_list[ $key ] );
					}
				}
				if ( $list_changed ) {
					update_option( 'auth_settings_' . $list_name, $user_list );
				}
			}
		}


		/**
		 * Remove multisite user from authorizer lists when that user is deleted from Network Users.
		 *
		 * Action: wpmu_delete_user
		 *
		 * @param  int $user_id User ID to remove.
		 * @return void
		 */
		public function remove_network_user_from_authorizer_when_deleted( $user_id ) {
			$user          = get_user_by( 'id', $user_id );
			$deleted_email = $user->user_email;

			// Go through multisite approved user list and remove this user.
			$auth_multisite_settings_access_users_approved = $this->sanitize_user_list(
				$this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::NETWORK_CONTEXT )
			);
			$list_changed                                  = false;
			foreach ( $auth_multisite_settings_access_users_approved as $key => $existing_user ) {
				if ( 0 === strcasecmp( $deleted_email, $existing_user['email'] ) ) {
					$list_changed = true;
					unset( $auth_multisite_settings_access_users_approved[ $key ] );
				}
			}
			if ( $list_changed ) {
				update_blog_option( $this->current_site_blog_id, 'auth_multisite_settings_access_users_approved', $auth_multisite_settings_access_users_approved );
			}

			// Go through all pending/approved lists on individual sites and remove this user from them.
			// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
			$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
			foreach ( $sites as $site ) {
				$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
				$this->remove_network_user_from_site_when_removed( $user_id, $blog_id );
			}

		}


		/**
		 * Remove multisite user from a specific site's lists when that user is removed from the site.
		 *
		 * Action: remove_user_from_blog
		 *
		 * @param  int $user_id User ID to remove.
		 * @param  int $blog_id Blog ID to remove from.
		 * @return void
		 */
		public function remove_network_user_from_site_when_removed( $user_id, $blog_id ) {
			$user          = get_user_by( 'id', $user_id );
			$deleted_email = $user->user_email;

			$list_names = array( 'access_users_pending', 'access_users_approved' );
			foreach ( $list_names as $list_name ) {
				$user_list    = get_blog_option( $blog_id, 'auth_settings_' . $list_name, array() );
				$list_changed = false;
				foreach ( $user_list as $key => $existing_user ) {
					if ( 0 === strcasecmp( $deleted_email, $existing_user['email'] ) ) {
						$list_changed = true;
						unset( $user_list[ $key ] );
					}
				}
				if ( $list_changed ) {
					update_blog_option( $blog_id, 'auth_settings_' . $list_name, $user_list );
				}
			}
		}


		/**
		 * Helper: Add multisite user to a specific site's approved list.
		 *
		 * @param  int $user_id User ID to add.
		 * @param  int $blog_id Blog ID to add to.
		 * @return void
		 */
		private function add_network_user_to_site( $user_id, $blog_id ) {
			// Switch to blog.
			switch_to_blog( $blog_id );

			// Get user details and role.
			$access_default_role = $this->get_plugin_option( 'access_default_role', WP_Plugin_Authorizer::SINGLE_CONTEXT, 'allow override' );
			$user                = get_user_by( 'id', $user_id );
			$user_email          = $user->user_email;
			$user_role           = $user && is_array( $user->roles ) && count( $user->roles ) > 0 ? $user->roles[0] : $access_default_role;

			// Add user to approved list if not already there and not in blocked list.
			$auth_settings_access_users_approved = $this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::SINGLE_CONTEXT );
			$auth_settings_access_users_blocked  = $this->get_plugin_option( 'access_users_blocked', WP_Plugin_Authorizer::SINGLE_CONTEXT );
			if ( ! $this->in_multi_array( $user_email, $auth_settings_access_users_approved ) && ! $this->in_multi_array( $user_email, $auth_settings_access_users_blocked ) ) {
				$approved_user = array(
					'email'      => $this->lowercase( $user_email ),
					'role'       => $user_role,
					'date_added' => date( 'M Y', strtotime( $user->user_registered ) ),
					'local_user' => true,
				);
				array_push( $auth_settings_access_users_approved, $approved_user );
				update_option( 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
			}

			// Restore original blog.
			restore_current_blog();
		}


		/**
		 * Multisite:
		 * When an existing user is invited to the current site (or a new user is created),
		 * add them to the authorizer approved list. This action fires when the admin
		 * doesn't select the "Skip Confirmation Email" option.
		 *
		 * Action: invite_user
		 *
		 * @param int    $user_id     The invited user's ID.
		 * @param array  $role        The role of the invited user (or none if a new user creation).
		 * @param string $newuser_key The key of the invitation.
		 */
		public function add_existing_user_to_authorizer_when_created( $user_id, $role = array(), $newuser_key = '' ) {
			$user = get_user_by( 'id', $user_id );
			$this->add_user_to_authorizer_when_created( $user->user_email, $user->user_registered, $user->roles, $role );
		}


		/**
		 * Multisite:
		 * When an existing user is invited to the current site (or a new user is created),
		 * add them to the authorizer approved list. This action fires when the admin
		 * selects the "Skip Confirmation Email" option.
		 *
		 * Action: added_existing_user
		 *
		 * @param int   $user_id The invited user's ID.
		 * @param mixed $result  True on success or a WP_Error object if the user doesn't exist.
		 */
		public function add_existing_user_to_authorizer_when_created_noconfirmation( $user_id, $result ) {
			$user = get_user_by( 'id', $user_id );
			$this->add_user_to_authorizer_when_created( $user->user_email, $user->user_registered, $user->roles );
		}


		/**
		 * Multisite:
		 * When a new user is invited to the current site (or a new user is created),
		 * add them to the authorizer approved list.
		 *
		 * Action: after_signup_user
		 *
		 * @param string $user       User's requested login name.
		 * @param string $user_email User's email address.
		 * @param string $key        User's activation key.
		 * @param array  $meta       Additional signup meta, including initially set roles.
		 */
		public function add_new_user_to_authorizer_when_created( $user, $user_email, $key, $meta ) {
			$user_roles = isset( $meta['new_role'] ) ? array( $meta['new_role'] ) : array();
			$this->add_user_to_authorizer_when_created( $user_email, time(), $user_roles );
		}


		/**
		 * Single site:
		 * When a new user is added in single site mode, add them to the authorizer
		 * approved list.
		 *
		 * Action: edit_user_created_user
		 *
		 * @param int    $user_id ID of the newly created user.
		 * @param string $notify  Type of notification that should happen. See
		 *                        wp_send_new_user_notifications() for more
		 *                        information on possible values.
		 */
		public function add_new_user_to_authorizer_when_created_single_site( $user_id, $notify ) {
			$user = get_user_by( 'id', $user_id );
			$this->add_user_to_authorizer_when_created( $user->user_email, $user->user_registered, $user->roles );
		}


		/**
		 * Helper: When a new user is added/invited to the current site (or a new
		 * user is created), add them to the authorizer approved list.
		 *
		 * @param string $user_email      Email address of user to add.
		 * @param string $date_registered Date user registered.
		 * @param array  $user_roles      Role to add for user.
		 * @param array  $default_role    Default role, if no role specified.
		 */
		private function add_user_to_authorizer_when_created( $user_email, $date_registered, $user_roles = array(), $default_role = array() ) {
			$auth_multisite_settings_access_users_approved = is_multisite() ? get_blog_option( $this->current_site_blog_id, 'auth_multisite_settings_access_users_approved', array() ) : array();
			$auth_settings_access_users_pending            = $this->get_plugin_option( 'access_users_pending', WP_Plugin_Authorizer::SINGLE_CONTEXT );
			$auth_settings_access_users_approved           = $this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::SINGLE_CONTEXT );
			$auth_settings_access_users_blocked            = $this->get_plugin_option( 'access_users_blocked', WP_Plugin_Authorizer::SINGLE_CONTEXT );

			// Get default role if one isn't specified.
			if ( count( $default_role ) < 1 ) {
				$default_role = '';
			} else {
				// If default role was provided, it came from the invite_user hook, and
				// only contains the role's display name. Here we look up the actual role
				// name to save (and default to no role if the display name isn't found).
				global $wp_roles;
				$default_role_display_name = $default_role['name'];
				$default_role = '';
				foreach ( $wp_roles->role_names as $role_name => $display_name ) {
					if ( $default_role_display_name === $display_name ) {
						$default_role = $role_name;
						break;
					}
				}
			}

			$updated = false;

			// Skip if user is in blocked list.
			if ( $this->in_multi_array( $user_email, $auth_settings_access_users_blocked ) ) {
				return;
			}
			// Remove from pending list if there.
			foreach ( $auth_settings_access_users_pending as $key => $pending_user ) {
				if ( 0 === strcasecmp( $pending_user['email'], $user_email ) ) {
					unset( $auth_settings_access_users_pending[ $key ] );
					$updated = true;
				}
			}
			// Skip if user is in multisite approved list.
			if ( $this->in_multi_array( $user_email, $auth_multisite_settings_access_users_approved ) ) {
				return;
			}
			// Add to approved list if not there.
			if ( ! $this->in_multi_array( $user_email, $auth_settings_access_users_approved ) ) {
				$approved_user = array(
					'email'      => $this->lowercase( $user_email ),
					'role'       => is_array( $user_roles ) && count( $user_roles ) > 0 ? $user_roles[0] : $default_role,
					'date_added' => date( 'M Y', strtotime( $date_registered ) ),
					'local_user' => true,
				);
				array_push( $auth_settings_access_users_approved, $approved_user );
				$updated = true;
			}

			if ( $updated ) {
				update_option( 'auth_settings_access_users_pending', $auth_settings_access_users_pending );
				update_option( 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
			}
		}


		/**
		 * Multisite:
		 * When a user is granted super admin status (checkbox on network user edit
		 * screen), add them to the authorizer network approved list. Also remove
		 * them from pending/approved list on any individual sites.
		 *
		 * Action: grant_super_admin
		 *
		 * @param int $user_id The user's ID.
		 */
		public function grant_super_admin__add_to_network_approved( $user_id ) {
			$user       = get_user_by( 'id', $user_id );
			$user_email = $user->user_email;

			// Add user to multisite approved user list (if not already there).
			$auth_multisite_settings_access_users_approved = $this->sanitize_user_list(
				$this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::NETWORK_CONTEXT )
			);
			if ( ! $this->in_multi_array( $user_email, $auth_multisite_settings_access_users_approved ) ) {
				$multisite_approved_user = array(
					'email'      => $this->lowercase( $user_email ),
					'role'       => count( $user->roles ) > 0 ? $user->roles[0] : 'administrator',
					'date_added' => date( 'M Y', strtotime( $user->user_registered ) ),
					'local_user' => true,
				);
				array_push( $auth_multisite_settings_access_users_approved, $multisite_approved_user );
				update_blog_option( $this->current_site_blog_id, 'auth_multisite_settings_access_users_approved', $auth_multisite_settings_access_users_approved );
			}

			// Go through all pending/approved lists on individual sites and remove this user from them.
			// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
			$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
			foreach ( $sites as $site ) {
				$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
				$this->remove_network_user_from_site_when_removed( $user_id, $blog_id );
			}

		}

		/**
		 * Multisite:
		 * When a user's super admin status is revoked (checkbox on network user edit
		 * screen), remove them from the authorizer network approved list. Also add
		 * them to approved list on any individual sites they are already a part of.
		 *
		 * Action: revoke_super_admin
		 *
		 * @param int $user_id The user's ID.
		 */
		public function revoke_super_admin__remove_from_network_approved( $user_id ) {
			$user          = get_user_by( 'id', $user_id );
			$revoked_email = $user->user_email;

			// Go through multisite approved user list and remove this user.
			$auth_multisite_settings_access_users_approved = $this->sanitize_user_list(
				$this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::NETWORK_CONTEXT )
			);
			$list_changed                                  = false;
			foreach ( $auth_multisite_settings_access_users_approved as $key => $existing_user ) {
				if ( 0 === strcasecmp( $revoked_email, $existing_user['email'] ) ) {
					$list_changed = true;
					unset( $auth_multisite_settings_access_users_approved[ $key ] );
				}
			}
			if ( $list_changed ) {
				update_blog_option( $this->current_site_blog_id, 'auth_multisite_settings_access_users_approved', $auth_multisite_settings_access_users_approved );
			}

			// Go through this user's current sites and add them to the approved list
			// (since they are no longer on the network approved list).
			$sites_of_user = get_blogs_of_user( $user_id );
			foreach ( $sites_of_user as $site ) {
				$blog_id = $site->userblog_id;
				$this->add_network_user_to_site( $user_id, $blog_id );
			}

		}

		/**
		 * Send a welcome email message to a newly approved user (if the "Should
		 * email approved users" setting is enabled).
		 *
		 * @param  string $email Email address to send welcome email to.
		 * @return bool          Whether the email was sent.
		 */
		private function maybe_email_welcome_message( $email ) {
			// Get option for whether to email welcome messages.
			$should_email_new_approved_users = $this->get_plugin_option( 'access_should_email_approved_users' );

			// Do not send welcome email if option not enabled.
			if ( '1' !== $should_email_new_approved_users ) {
				return false;
			}

			// Make sure we didn't just email this user (can happen with
			// multiple admins saving at the same time, or by clicking
			// Approve button too rapidly).
			$recently_sent_emails = get_option( 'auth_settings_recently_sent_emails' );
			if ( false === $recently_sent_emails ) {
				$recently_sent_emails = array();
			}
			foreach ( $recently_sent_emails as $key => $recently_sent_email ) {
				if ( $recently_sent_email['time'] < strtotime( 'now -1 minutes' ) ) {
					// Remove emails sent more than 1 minute ago.
					unset( $recently_sent_emails[ $key ] );
				} elseif ( $recently_sent_email['email'] === $email ) {
					// Sent an email to this user within the last 1 minute, so
					// quit without sending.
					return false;
				}
			}
			// Add the email we're about to send to the list.
			$recently_sent_emails[] = array(
				'email' => $email,
				'time'  => time(),
			);
			update_option( 'auth_settings_recently_sent_emails', $recently_sent_emails );

			// Get welcome email subject and body text.
			$subject = $this->get_plugin_option( 'access_email_approved_users_subject' );
			$body    = apply_filters( 'the_content', $this->get_plugin_option( 'access_email_approved_users_body' ) );

			// Fail if the subject/body options don't exist or are empty.
			if ( is_null( $subject ) || is_null( $body ) || strlen( $subject ) === 0 || strlen( $body ) === 0 ) {
				return false;
			}

			// Replace approved shortcode patterns in subject and body.
			$site_name = get_bloginfo( 'name' );
			$site_url  = get_site_url();
			$subject   = str_replace( '[site_name]', $site_name, $subject );
			$body      = str_replace( '[site_name]', $site_name, $body );
			$body      = str_replace( '[site_url]', $site_url, $body );
			$body      = str_replace( '[user_email]', $email, $body );
			$headers   = 'Content-type: text/html' . "\r\n";

			// Send email.
			wp_mail( $email, $subject, $body, $headers );

			// Indicate mail was sent.
			return true;
		}


		/**
		 * Generate a unique cookie to add to nonces to prevent CSRF.
		 *
		 * @var string
		 */
		private $cookie_value = null;

		/**
		 * Retrieve the unique login cookie.
		 *
		 * @return string Login cookie value.
		 */
		private function get_cookie_value() {
			if ( ! $this->cookie_value ) {
				if ( isset( $_COOKIE['login_unique'] ) ) {
					$this->cookie_value = sanitize_key( wp_unslash( $_COOKIE['login_unique'] ) );
				} else {
					$this->cookie_value = md5( rand() );
				}
			}
			return $this->cookie_value;
		}


		/**
		 * Encryption key (not secret!).
		 *
		 * @var string
		 */
		private static $key = "8QxnrvjdtweisvCBKEY!+0\0\0";

		/**
		 * Encryption salt (not secret!).
		 *
		 * @var string
		 */
		private static $iv = 'R_O2D]jPn]1[fhJl!-P1.oe';

		/**
		 * Basic encryption using a public (not secret!) key. Used for general
		 * database obfuscation of passwords.
		 *
		 * @param  string $text    String to encrypt.
		 * @param  string $library Encryption library to use (openssl).
		 * @return string          Encrypted string.
		 */
		private function encrypt( $text, $library = 'openssl' ) {
			$result = '';

			// Use openssl library (better) if it is enabled.
			if ( function_exists( 'openssl_encrypt' ) && 'openssl' === $library ) {
				$result = base64_encode(
					openssl_encrypt(
						$text,
						'AES-256-CBC',
						hash( 'sha256', self::$key ),
						0,
						substr( hash( 'sha256', self::$iv ), 0, 16 )
					)
				);
			} elseif ( function_exists( 'mcrypt_encrypt' ) ) { // Use mcrypt library (deprecated in PHP 7.1) if php5-mcrypt extension is enabled.
				$result = base64_encode( mcrypt_encrypt( MCRYPT_RIJNDAEL_256, self::$key, $text, MCRYPT_MODE_ECB, 'abcdefghijklmnopqrstuvwxyz012345' ) );
			} else { // Fall back to basic obfuscation.
				$length = strlen( $text );
				for ( $i = 0; $i < $length; $i++ ) {
					$char    = substr( $text, $i, 1 );
					$keychar = substr( self::$key, ( $i % strlen( self::$key ) ) - 1, 1 );
					$char    = chr( ord( $char ) + ord( $keychar ) );
					$result .= $char;
				}
				$result = base64_encode( $result );
			}

			return $result;
		}


		/**
		 * Basic decryption using a public (not secret!) key. Used for general
		 * database obfuscation of passwords.
		 *
		 * @param  string $secret  String to encrypt.
		 * @param  string $library Encryption lib to use (openssl).
		 * @return string          Decrypted string
		 */
		private function decrypt( $secret, $library = 'openssl' ) {
			$result = '';

			// Use openssl library (better) if it is enabled.
			if ( function_exists( 'openssl_decrypt' ) && 'openssl' === $library ) {
				$result = openssl_decrypt(
					base64_decode( $secret ),
					'AES-256-CBC',
					hash( 'sha256', self::$key ),
					0,
					substr( hash( 'sha256', self::$iv ), 0, 16 )
				);
			} elseif ( function_exists( 'mcrypt_decrypt' ) ) { // Use mcrypt library (deprecated in PHP 7.1) if php5-mcrypt extension is enabled.
				$secret = base64_decode( $secret );
				$result = rtrim( mcrypt_decrypt( MCRYPT_RIJNDAEL_256, self::$key, $secret, MCRYPT_MODE_ECB, 'abcdefghijklmnopqrstuvwxyz012345' ), "\0$result" );
			} else { // Fall back to basic obfuscation.
				$secret = base64_decode( $secret );
				$length = strlen( $secret );
				for ( $i = 0; $i < $length; $i++ ) {
					$char    = substr( $secret, $i, 1 );
					$keychar = substr( self::$key, ( $i % strlen( self::$key ) ) - 1, 1 );
					$char    = chr( ord( $char ) - ord( $keychar ) );
					$result .= $char;
				}
			}

			return $result;
		}


		/**
		 * In a multisite environment, returns true if the current user is logged
		 * in and a user of the current blog. In single site mode, simply returns
		 * true if the current user is logged in.
		 *
		 * @return bool Whether current user is logged in and a user of the current blog.
		 */
		protected function is_user_logged_in_and_blog_user() {
			$is_user_logged_in_and_blog_user = false;
			if ( is_multisite() ) {
				$is_user_logged_in_and_blog_user = is_user_logged_in() && is_user_member_of_blog( get_current_user_id() );
			} else {
				$is_user_logged_in_and_blog_user = is_user_logged_in();
			}
			return $is_user_logged_in_and_blog_user;
		}


		/**
		 * Helper function to determine whether a given email is in one of
		 * the lists (pending, approved, blocked). Defaults to the list of
		 * approved users.
		 *
		 * @param  string $email          Email to check existent of.
		 * @param  string $list           List to look for email in.
		 * @param  string $multisite_mode Admin context.
		 * @return boolean                Whether email was found.
		 */
		protected function is_email_in_list( $email = '', $list = 'approved', $multisite_mode = 'single' ) {
			if ( empty( $email ) ) {
				return false;
			}

			switch ( $list ) {
				case 'pending':
					$auth_settings_access_users_pending = $this->get_plugin_option( 'access_users_pending', WP_Plugin_Authorizer::SINGLE_CONTEXT );
					return $this->in_multi_array( $email, $auth_settings_access_users_pending );
				case 'blocked':
					$auth_settings_access_users_blocked = $this->get_plugin_option( 'access_users_blocked', WP_Plugin_Authorizer::SINGLE_CONTEXT );
					// Blocked list can have wildcard matches, e.g., @baddomain.com, which
					// should match any email address at that domain. Check if any wildcards
					// exist, and if the email address has that domain.
					$email_in_blocked_domain = false;
					$blocked_domains = preg_grep( '/^@.*/', array_map(
						function ( $blocked_item ) { return $blocked_item['email']; },
						$auth_settings_access_users_blocked
					) );
					foreach ( $blocked_domains as $blocked_domain ) {
						$email_domain = substr( $email, strrpos( $email, '@' ) );
						if ( $email_domain === $blocked_domain ) {
							$email_in_blocked_domain = true;
							break;
						}
					}
					return $email_in_blocked_domain || $this->in_multi_array( $email, $auth_settings_access_users_blocked );
				case 'approved':
				default:
					if ( 'single' !== $multisite_mode ) {
						// Get multisite users only.
						$auth_settings_access_users_approved = $this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::NETWORK_CONTEXT );
					} elseif ( is_multisite() && 1 === intval( $this->get_plugin_option( 'advanced_override_multisite' ) ) ) {
						// This site has overridden any multisite settings, so only get its users.
						$auth_settings_access_users_approved = $this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::SINGLE_CONTEXT );
					} else {
						// Get all site users and all multisite users.
						$auth_settings_access_users_approved = array_merge(
							$this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::SINGLE_CONTEXT ),
							$this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::NETWORK_CONTEXT )
						);
					}
					return $this->in_multi_array( $email, $auth_settings_access_users_approved );
			}
		}


		/**
		 * Helper function to get number of users (including multisite users)
		 * in a given list (pending, approved, or blocked).
		 *
		 * @param  string $list       List to get count of.
		 * @param  string $admin_mode WP_Plugin_Authorizer::SINGLE_CONTEXT or WP_Plugin_Authorizer::NETWORK_CONTEXT determines whether to include multisite users.
		 * @return int                Number of users in list.
		 */
		protected function get_user_count_from_list( $list, $admin_mode = WP_Plugin_Authorizer::SINGLE_CONTEXT ) {
			$auth_settings_access_users = array();

			switch ( $list ) {
				case 'pending':
					$auth_settings_access_users = $this->get_plugin_option( 'access_users_pending', WP_Plugin_Authorizer::SINGLE_CONTEXT );
					break;
				case 'blocked':
					$auth_settings_access_users = $this->get_plugin_option( 'access_users_blocked', WP_Plugin_Authorizer::SINGLE_CONTEXT );
					break;
				case 'approved':
					if ( WP_Plugin_Authorizer::SINGLE_CONTEXT !== $admin_mode ) {
						// Get multisite users only.
						$auth_settings_access_users = $this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::NETWORK_CONTEXT );
					} elseif ( is_multisite() && 1 === intval( $this->get_plugin_option( 'advanced_override_multisite' ) ) ) {
						// This site has overridden any multisite settings, so only get its users.
						$auth_settings_access_users = $this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::SINGLE_CONTEXT );
					} else {
						// Get all site users and all multisite users.
						$auth_settings_access_users = array_merge(
							$this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::SINGLE_CONTEXT ),
							$this->get_plugin_option( 'access_users_approved', WP_Plugin_Authorizer::NETWORK_CONTEXT )
						);
					}
			}

			return count( $auth_settings_access_users );
		}


		/**
		 * Helper function to search a multidimensional array for a value.
		 *
		 * @param  string $needle           Value to search for.
		 * @param  array  $haystack         Multidimensional array to search.
		 * @param  string $strict_mode      'strict' if strict comparisons should be used.
		 * @param  string $case_sensitivity 'case sensitive' if comparisons should respect case.
		 * @return bool                     Whether needle was found.
		 */
		protected function in_multi_array( $needle = '', $haystack = array(), $strict_mode = 'not strict', $case_sensitivity = 'case insensitive' ) {
			if ( ! is_array( $haystack ) ) {
				return false;
			}
			if ( 'case insensitive' === $case_sensitivity ) {
				$needle = strtolower( $needle );
			}
			foreach ( $haystack as $item ) {
				if ( 'case insensitive' === $case_sensitivity && ! is_array( $item ) ) {
					$item = strtolower( $item );
				}
				if ( ( 'strict' === $strict_mode ? $item === $needle : $item == $needle ) || ( is_array( $item ) && $this->in_multi_array( $needle, $item, $strict_mode, $case_sensitivity ) ) ) { // phpcs:ignore WordPress.PHP.StrictComparisons.LooseComparison
					return true;
				}
			}
			return false;
		}


		/**
		 * Helper function to determine if an URL is accessible.
		 *
		 * @param  string $url URL that should be publicly reachable.
		 * @return boolean     Whether the URL is publicly reachable.
		 */
		protected function url_is_accessible( $url ) {
			// Use wp_remote_retrieve_response_code() to retrieve the URL.
			$response      = wp_remote_get( $url );
			$response_code = wp_remote_retrieve_response_code( $response );

			// Return true if the document has loaded successfully without any redirection or error.
			return $response_code >= 200 && $response_code < 400;
		}


		/**
		 * Helper function to reconstruct a URL split using parse_url().
		 *
		 * @param  array $parts Array returned from parse_url().
		 * @return string       URL.
		 */
		protected function build_url( $parts = array() ) {
			return (
				( isset( $parts['scheme'] ) ? "{$parts['scheme']}:" : '' ) .
				( ( isset( $parts['user'] ) || isset( $parts['host'] ) ) ? '//' : '' ) .
				( isset( $parts['user'] ) ? "{$parts['user']}" : '' ) .
				( isset( $parts['pass'] ) ? ":{$parts['pass']}" : '' ) .
				( isset( $parts['user'] ) ? '@' : '' ) .
				( isset( $parts['host'] ) ? "{$parts['host']}" : '' ) .
				( isset( $parts['port'] ) ? ":{$parts['port']}" : '' ) .
				( isset( $parts['path'] ) ? "{$parts['path']}" : '' ) .
				( isset( $parts['query'] ) ? "?{$parts['query']}" : '' ) .
				( isset( $parts['fragment'] ) ? "#{$parts['fragment']}" : '' )
			);
		}


		/**
		 * Helper function that prints option tags for a select element for all
		 * roles the current user has permission to assign.
		 *
		 * @param  string $selected_role Which role should be selected in the dropdown.
		 * @param  string $disable_input 'disabled' if select element should be disabled.
		 * @param  int    $admin_mode    WP_Plugin_Authorizer::NETWORK_CONTEXT if we are in that context.
		 * @return void
		 */
		protected function wp_dropdown_permitted_roles( $selected_role = 'subscriber', $disable_input = 'not disabled', $admin_mode = WP_Plugin_Authorizer::SINGLE_CONTEXT ) {
			$roles        = get_editable_roles();
			$current_user = wp_get_current_user();

			// If we're in network admin, also show any roles that might exist only on
			// specific sites in the network (themes can add their own roles).
			if ( WP_Plugin_Authorizer::NETWORK_CONTEXT === $admin_mode ) {
				// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
				$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
				foreach ( $sites as $site ) {
					$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
					switch_to_blog( $blog_id );
					$roles = array_merge( $roles, get_editable_roles() );
					restore_current_blog();
				}
				$unique_role_names = array();
				foreach ( $roles as $role_name => $role_info ) {
					if ( array_key_exists( $role_name, $unique_role_names ) ) {
						unset( $roles[ $role_name ] );
					} else {
						$unique_role_names[ $role_name ] = true;
					}
				}
			}

			// If the currently selected role exists, but is not in the list of roles,
			// the current user is not permitted to assign it. Assume they can't edit
			// that user's role at all. Return only the one role for the dropdown list.
			if ( strlen( $selected_role ) > 0 && ! array_key_exists( $selected_role, $roles ) && ! is_null( get_role( $selected_role ) ) ) {
				return;
			}

			// Print an option element for each permitted role.
			foreach ( $roles as $name => $role ) {
				$is_selected = $selected_role === $name;

				// Don't let a user change their own role (but network admins always can).
				$is_disabled = $selected_role !== $name && 'disabled' === $disable_input && ! ( is_multisite() && current_user_can( 'manage_network' ) );
				?>
				<option value="<?php echo esc_attr( $name ); ?>"<?php selected( $is_selected ); ?><?php disabled( $is_disabled ); ?>><?php echo esc_html( $role['name'] ); ?></option>
				<?php
			}

			// Print default role (no role).
			$is_selected = strlen( $selected_role ) === 0 || ! array_key_exists( $selected_role, $roles );
			$is_disabled = strlen( $selected_role ) > 0 && 'disabled' === $disable_input && ! ( is_multisite() && current_user_can( 'manage_network' ) );
			?>
			<option value=""<?php selected( $is_selected ); ?><?php disabled( $is_disabled ); ?>><?php esc_html_e( '&mdash; No role for this site &mdash;', 'authorizer' ); ?></option>
			<?php

		}


		/**
		 * Helper function to get a single user info array from one of the access
		 * control lists (pending, approved, or blocked).
		 *
		 * @param  string $email Email address to retrieve info for.
		 * @param  string $list  List to get info from.
		 * @return mixed         false if not found, otherwise: array(
		 *                         'email' => '',
		 *                         'role' => '',
		 *                         'date_added' => '',
		 *                         ['usermeta' => [''|array()]]
		 *                       );
		 */
		protected function get_user_info_from_list( $email, $list ) {
			foreach ( $list as $user_info ) {
				if ( 0 === strcasecmp( $user_info['email'], $email ) ) {
					return $user_info;
				}
			}
			return false;
		}

		/**
		 * Helper function to convert a string to lowercase.  Prefers to use mb_strtolower,
		 * but will fall back to strtolower if the former is not available.
		 *
		 * @param  string $string String to convert to lowercase.
		 * @return string         Input in lowercase.
		 */
		protected function lowercase( $string ) {
			return function_exists( 'mb_strtolower' ) ? mb_strtolower( $string ) : strtolower( $string );
		}


		/**
		 * Helper function to convert seconds to human readable text.
		 *
		 * @see: http://csl.name/php-secs-to-human-text/
		 *
		 * @param  int $secs Seconds to display as readable text.
		 * @return string    Readable version of number of seconds.
		 */
		protected function seconds_as_sentence( $secs ) {
			$units = array(
				'week'   => 3600 * 24 * 7,
				'day'    => 3600 * 24,
				'hour'   => 3600,
				'minute' => 60,
				'second' => 1,
			);

			// Specifically handle zero.
			if ( 0 === intval( $secs ) ) {
				return '0 seconds';
			}

			$s = '';

			foreach ( $units as $name => $divisor ) {
				$quot = intval( $secs / $divisor );
				if ( $quot ) {
					$s    .= "$quot $name";
					$s    .= ( abs( $quot ) > 1 ? 's' : '' ) . ', ';
					$secs -= $quot * $divisor;
				}
			}

			return substr( $s, 0, -2 );
		}

		/**
		 * Helper function to get all available usermeta keys as an array.
		 *
		 * @return array All usermeta keys for user.
		 */
		protected function get_all_usermeta_keys() {
			global $wpdb;
			$usermeta_keys = $wpdb->get_col( "SELECT DISTINCT $wpdb->usermeta.meta_key FROM $wpdb->usermeta" );
			return $usermeta_keys;
		}


		/**
		 * Load translated strings from *.mo files in /languages.
		 *
		 * Action: plugins_loaded
		 */
		public function load_textdomain() {
			load_plugin_textdomain(
				'authorizer',
				false,
				plugin_basename( dirname( __FILE__ ) ) . '/languages'
			);
		}


		/**
		 * Generate CAS authentication URL (wp-login.php URL with reauth=1 removed
		 * and external=cas added).
		 */
		private function modify_current_url_for_cas_login() {
			// Construct the URL of the current page (wp-login.php).
			$url = '';
			if ( isset( $_SERVER['HTTP_HOST'], $_SERVER['REQUEST_URI'] ) ) {
				$url = set_url_scheme( esc_url_raw( wp_unslash( $_SERVER['HTTP_HOST'] ) ) . esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) );
			}

			// Parse the URL into its components.
			$parsed_url = wp_parse_url( $url );

			// Fix up the querystring values (remove reauth, make sure external=cas).
			$querystring = array();
			if ( array_key_exists( 'query', $parsed_url ) ) {
				parse_str( $parsed_url['query'], $querystring );
			}
			unset( $querystring['reauth'] );
			$querystring['external'] = 'cas';
			$parsed_url['query']     = http_build_query( $querystring );

			// Return the URL as a string.
			return $this->unparse_url( $parsed_url );
		}


		/**
		 * Reconstruct a URL after it has been deconstructed with parse_url().
		 *
		 * @param  array $parsed_url Keys from parse_url().
		 * @return string            URL constructed from the components in $parsed_url.
		 */
		protected function unparse_url( $parsed_url = array() ) {
			$scheme   = isset( $parsed_url['scheme'] ) ? $parsed_url['scheme'] . '://' : '';
			$host     = isset( $parsed_url['host'] ) ? $parsed_url['host'] : '';
			$port     = isset( $parsed_url['port'] ) ? ':' . $parsed_url['port'] : '';
			$user     = isset( $parsed_url['user'] ) ? $parsed_url['user'] : '';
			$pass     = isset( $parsed_url['pass'] ) ? ':' . $parsed_url['pass'] : '';
			$pass     = $user || $pass ? "$pass@" : '';
			$path     = isset( $parsed_url['path'] ) ? $parsed_url['path'] : '';
			$query    = isset( $parsed_url['query'] ) ? '?' . $parsed_url['query'] : '';
			$fragment = isset( $parsed_url['fragment'] ) ? '#' . $parsed_url['fragment'] : '';
			return "$scheme$user$pass$host$port$path$query$fragment";
		}


		/**
		 * Helper function to generate an HTML class name for an option (used in
		 * Authorizer Settings in the Approved User list).
		 *
		 * @param  string  $suffix            Unique part of class name.
		 * @param  boolean $is_multisite_user Whether the class name should indicate it's a multisite user.
		 * @return string                     Class name, e.g., "auth-email auth-multisite-email".
		 */
		private function create_class_name( $suffix = '', $is_multisite_user = false ) {
			return $is_multisite_user ? "auth-$suffix auth-multisite-$suffix" : "auth-$suffix";
		}


		/**
		 * Plugin Update Routines.
		 *
		 * Action: plugins_loaded
		 */
		public function auth_update_check() {
			// Get current version.
			$needs_updating = false;
			if ( is_multisite() ) {
				$auth_version = get_blog_option( $this->current_site_blog_id, 'auth_version' );
			} else {
				$auth_version = get_option( 'auth_version' );
			}

			// Update: migrate user lists to own options (addresses concurrency
			// when saving plugin options, since user lists are changed often
			// and we don't want to overwrite changes to the lists when an
			// admin saves all of the plugin options.)
			// Note: Pending user list is changed whenever a new user tries to
			// log in; approved and blocked lists are changed whenever an admin
			// changes them from the multisite panel, the dashboard widget, or
			// the plugin options page.
			$update_if_older_than = 20140709;
			if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
				// Copy single site user lists to new options (if they exist).
				$auth_settings = get_option( 'auth_settings' );
				if ( is_array( $auth_settings ) && array_key_exists( 'access_users_pending', $auth_settings ) ) {
					update_option( 'auth_settings_access_users_pending', $auth_settings['access_users_pending'] );
					unset( $auth_settings['access_users_pending'] );
					update_option( 'auth_settings', $auth_settings );
				}
				if ( is_array( $auth_settings ) && array_key_exists( 'access_users_approved', $auth_settings ) ) {
					update_option( 'auth_settings_access_users_approved', $auth_settings['access_users_approved'] );
					unset( $auth_settings['access_users_approved'] );
					update_option( 'auth_settings', $auth_settings );
				}
				if ( is_array( $auth_settings ) && array_key_exists( 'access_users_blocked', $auth_settings ) ) {
					update_option( 'auth_settings_access_users_blocked', $auth_settings['access_users_blocked'] );
					unset( $auth_settings['access_users_blocked'] );
					update_option( 'auth_settings', $auth_settings );
				}
				// Copy multisite user lists to new options (if they exist).
				if ( is_multisite() ) {
					$auth_multisite_settings = get_blog_option( $this->current_site_blog_id, 'auth_multisite_settings', array() );
					if ( is_array( $auth_multisite_settings ) && array_key_exists( 'access_users_pending', $auth_multisite_settings ) ) {
						update_blog_option( $this->current_site_blog_id, 'auth_multisite_settings_access_users_pending', $auth_multisite_settings['access_users_pending'] );
						unset( $auth_multisite_settings['access_users_pending'] );
						update_blog_option( $this->current_site_blog_id, 'auth_multisite_settings', $auth_multisite_settings );
					}
					if ( is_array( $auth_multisite_settings ) && array_key_exists( 'access_users_approved', $auth_multisite_settings ) ) {
						update_blog_option( $this->current_site_blog_id, 'auth_multisite_settings_access_users_approved', $auth_multisite_settings['access_users_approved'] );
						unset( $auth_multisite_settings['access_users_approved'] );
						update_blog_option( $this->current_site_blog_id, 'auth_multisite_settings', $auth_multisite_settings );
					}
					if ( is_array( $auth_multisite_settings ) && array_key_exists( 'access_users_blocked', $auth_multisite_settings ) ) {
						update_blog_option( $this->current_site_blog_id, 'auth_multisite_settings_access_users_blocked', $auth_multisite_settings['access_users_blocked'] );
						unset( $auth_multisite_settings['access_users_blocked'] );
						update_blog_option( $this->current_site_blog_id, 'auth_multisite_settings', $auth_multisite_settings );
					}
				}
				// Update version to reflect this change has been made.
				$auth_version   = $update_if_older_than;
				$needs_updating = true;
			}

			// Update: Set default values for newly added options (forgot to do
			// this, so some users are getting debug log notices about undefined
			// indexes in $auth_settings).
			$update_if_older_than = 20160831;
			if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
				// Provide default values for any $auth_settings options that don't exist.
				if ( is_multisite() ) {
					// Get all blog ids.
					// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
					$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
					foreach ( $sites as $site ) {
						$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
						switch_to_blog( $blog_id );
						// Set meaningful defaults for other sites in the network.
						$this->set_default_options();
						// Switch back to original blog.
						restore_current_blog();
					}
				} else {
					// Set meaningful defaults for this site.
					$this->set_default_options();
				}
				// Update version to reflect this change has been made.
				$auth_version   = $update_if_older_than;
				$needs_updating = true;
			}

			// Update: Migrate LDAP passwords encrypted with mcrypt since mcrypt is
			// deprecated as of PHP 7.1. Use openssl library instead.
			$update_if_older_than = 20170510;
			if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
				if ( is_multisite() ) {
					// Reencrypt LDAP passwords in each site in the network.
					// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
					$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
					foreach ( $sites as $site ) {
						$blog_id       = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
						$auth_settings = get_blog_option( $blog_id, 'auth_settings', array() );
						if ( array_key_exists( 'ldap_password', $auth_settings ) && strlen( $auth_settings['ldap_password'] ) > 0 ) {
							$plaintext_ldap_password        = $this->decrypt( $auth_settings['ldap_password'], 'mcrypt' );
							$auth_settings['ldap_password'] = $this->encrypt( $plaintext_ldap_password );
							update_blog_option( $blog_id, 'auth_settings', $auth_settings );
						}
					}
				} else {
					// Reencrypt LDAP password on this single-site install.
					$auth_settings = get_option( 'auth_settings', array() );
					if ( array_key_exists( 'ldap_password', $auth_settings ) && strlen( $auth_settings['ldap_password'] ) > 0 ) {
						$plaintext_ldap_password        = $this->decrypt( $auth_settings['ldap_password'], 'mcrypt' );
						$auth_settings['ldap_password'] = $this->encrypt( $plaintext_ldap_password );
						update_option( 'auth_settings', $auth_settings );
					}
				}
				// Update version to reflect this change has been made.
				$auth_version   = $update_if_older_than;
				$needs_updating = true;
			}

			// Update: Migrate LDAP passwords encrypted with mcrypt since mcrypt is
			// deprecated as of PHP 7.1. Use openssl library instead.
			// Note: Forgot to update the auth_multisite_settings ldap password! Do it here.
			$update_if_older_than = 20170511;
			if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
				if ( is_multisite() ) {
					// Reencrypt LDAP password in network (multisite) options.
					$auth_multisite_settings = get_blog_option( $this->current_site_blog_id, 'auth_multisite_settings', array() );
					if ( array_key_exists( 'ldap_password', $auth_multisite_settings ) && strlen( $auth_multisite_settings['ldap_password'] ) > 0 ) {
						$plaintext_ldap_password                  = $this->decrypt( $auth_multisite_settings['ldap_password'], 'mcrypt' );
						$auth_multisite_settings['ldap_password'] = $this->encrypt( $plaintext_ldap_password );
						update_blog_option( $this->current_site_blog_id, 'auth_multisite_settings', $auth_multisite_settings );
					}
				}
				// Update version to reflect this change has been made.
				$auth_version   = $update_if_older_than;
				$needs_updating = true;
			}

			// Update: Remove duplicates from approved list caused by authorizer_automatically_approve_login
			// filter not respecting users who are already in the approved list
			// (causing them to get re-added each time they logged in).
			$update_if_older_than = 20170711;
			if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
				// Remove duplicates from approved user lists.
				if ( is_multisite() ) {
					// Remove duplicates from each site in the multisite.
					// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
					$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
					foreach ( $sites as $site ) {
						$blog_id                             = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
						$auth_settings_access_users_approved = get_blog_option( $blog_id, 'auth_settings_access_users_approved', array() );
						if ( is_array( $auth_settings_access_users_approved ) ) {
							$should_update   = false;
							$distinct_emails = array();
							foreach ( $auth_settings_access_users_approved as $key => $user ) {
								if ( in_array( $user['email'], $distinct_emails, true ) ) {
									$should_update = true;
									unset( $auth_settings_access_users_approved[ $key ] );
								} else {
									$distinct_emails[] = $user['email'];
								}
							}
							if ( $should_update ) {
								update_blog_option( $blog_id, 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
							}
						}
					}
					// Remove duplicates from multisite approved user list.
					$auth_multisite_settings_access_users_approved = get_blog_option( $this->current_site_blog_id, 'auth_multisite_settings_access_users_approved', array() );
					if ( is_array( $auth_multisite_settings_access_users_approved ) ) {
						$should_update   = false;
						$distinct_emails = array();
						foreach ( $auth_multisite_settings_access_users_approved as $key => $user ) {
							if ( in_array( $user['email'], $distinct_emails, true ) ) {
								$should_update = true;
								unset( $auth_multisite_settings_access_users_approved[ $key ] );
							} else {
								$distinct_emails[] = $user['email'];
							}
						}
						if ( $should_update ) {
							update_blog_option( $this->current_site_blog_id, 'auth_multisite_settings_access_users_approved', $auth_multisite_settings_access_users_approved );
						}
					}
				} else {
					// Remove duplicates from single site approved user list.
					$auth_settings_access_users_approved = get_option( 'auth_settings_access_users_approved' );
					if ( is_array( $auth_settings_access_users_approved ) ) {
						$should_update   = false;
						$distinct_emails = array();
						foreach ( $auth_settings_access_users_approved as $key => $user ) {
							if ( in_array( $user['email'], $distinct_emails, true ) ) {
								$should_update = true;
								unset( $auth_settings_access_users_approved[ $key ] );
							} else {
								$distinct_emails[] = $user['email'];
							}
						}
						if ( $should_update ) {
							update_option( 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
						}
					}
				}
				// Update version to reflect this change has been made.
				$auth_version   = $update_if_older_than;
				$needs_updating = true;
			}

			// Update: Set default value for newly added option advanced_widget_enabled.
			$update_if_older_than = 20171023;
			if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
				// Provide default values for any $auth_settings options that don't exist.
				if ( is_multisite() ) {
					// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
					$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
					foreach ( $sites as $site ) {
						$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
						switch_to_blog( $blog_id );
						$this->set_default_options();
						restore_current_blog();
					}
				} else {
					$this->set_default_options();
				}
				// Update version to reflect this change has been made.
				$auth_version   = $update_if_older_than;
				$needs_updating = true;
			}

			// Update: Set default value for newly added option advanced_users_per_page.
			$update_if_older_than = 20171215;
			if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
				// Provide default values for any $auth_settings options that don't exist.
				if ( is_multisite() ) {
					// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
					$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
					foreach ( $sites as $site ) {
						$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
						switch_to_blog( $blog_id );
						$this->set_default_options();
						restore_current_blog();
					}
				} else {
					$this->set_default_options();
				}
				// Update version to reflect this change has been made.
				$auth_version   = $update_if_older_than;
				$needs_updating = true;
			}

			// Update: Set default value for newly added options advanced_users_sort_by and advanced_users_sort_order.
			$update_if_older_than = 20171219;
			if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
				// Provide default values for any $auth_settings options that don't exist.
				if ( is_multisite() ) {
					// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
					$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
					foreach ( $sites as $site ) {
						$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
						switch_to_blog( $blog_id );
						$this->set_default_options();
						restore_current_blog();
					}
				} else {
					$this->set_default_options();
				}
				// Update version to reflect this change has been made.
				$auth_version   = $update_if_older_than;
				$needs_updating = true;
			}

			/*
			// Update: TEMPLATE
			$update_if_older_than = YYYYMMDD;
			if ( $auth_version === false || intval( $auth_version ) < $update_if_older_than ) {
				UPDATE CODE HERE
				// Update version to reflect this change has been made.
				$auth_version = $update_if_older_than;
				$needs_updating = true;
			}
			*/

			// Save new version number if we performed any updates.
			if ( $needs_updating ) {
				if ( is_multisite() ) {
					// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
					$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
					foreach ( $sites as $site ) {
						$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
						update_blog_option( $blog_id, 'auth_version', $auth_version );
					}
				} else {
					update_option( 'auth_version', $auth_version );
				}
			}
		}

	}
}

// Instantiate the plugin class.
$wp_plugin_authorizer = new WP_Plugin_Authorizer();
