<?php
/**
 * Plugin Name: Authorizer
 * Description: Authorizer limits login attempts, restricts access to specified users, and authenticates against external sources (e.g., Google, LDAP, or CAS).
 * Author: Paul Ryan <prar@hawaii.edu>
 * Plugin URI: https://github.com/uhm-coe/authorizer
 * Text Domain: authorizer
 * Domain Path: /languages
 * License: GPL2
 * Version: 2.8.8
 *
 * @package authorizer
 */

namespace Authorizer;

require_once dirname( __FILE__ ) . '/src/authorizer/abstract-class-static-instance.php';

require_once dirname( __FILE__ ) . '/src/authorizer/class-authorization.php';
require_once dirname( __FILE__ ) . '/src/authorizer/class-login-form.php';
require_once dirname( __FILE__ ) . '/src/authorizer/class-dashboard-widget.php';
require_once dirname( __FILE__ ) . '/src/authorizer/class-ajax-endpoints.php';
require_once dirname( __FILE__ ) . '/src/authorizer/class-sync-userdata.php';
require_once dirname( __FILE__ ) . '/src/authorizer/class-admin-page.php';
require_once dirname( __FILE__ ) . '/src/authorizer/class-options.php';
require_once dirname( __FILE__ ) . '/src/authorizer/options/class-access-lists.php';
require_once dirname( __FILE__ ) . '/src/authorizer/options/class-login-access.php';
require_once dirname( __FILE__ ) . '/src/authorizer/options/class-public-access.php';
require_once dirname( __FILE__ ) . '/src/authorizer/options/class-external.php';
require_once dirname( __FILE__ ) . '/src/authorizer/options/external/class-google.php';
require_once dirname( __FILE__ ) . '/src/authorizer/options/external/class-cas.php';
require_once dirname( __FILE__ ) . '/src/authorizer/options/external/class-ldap.php';
require_once dirname( __FILE__ ) . '/src/authorizer/options/class-advanced.php';

use Authorizer\Options;

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
		 * Current site ID (Multisite).
		 *
		 * @var string
		 */
		public $current_site_blog_id = 1;

		/**
		 * Constructor.
		 */
		public function __construct() {
			// Load helper class.
			require_once dirname( __FILE__ ) . '/src/authorizer/class-helper.php';

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
			add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), array( Admin_Page::get_instance(), 'plugin_settings_link' ) );
			add_filter( 'network_admin_plugin_action_links_' . plugin_basename( __FILE__ ), array( Admin_Page::get_instance(), 'network_admin_plugin_settings_link' ) );

			// Modify login page with a custom password url (if option is set).
			add_filter( 'lostpassword_url', array( Login_Form::get_instance(), 'custom_lostpassword_url' ) );

			// If we have a custom login error, add the filter to show it.
			$error = get_option( 'auth_settings_advanced_login_error' );
			if ( $error && strlen( $error ) > 0 ) {
				add_filter( 'login_errors', array( Login_Form::get_instance(), 'show_advanced_login_error' ) );
			}

			/**
			 * Register actions.
			 */

			// Enable localization. Translation files stored in /languages.
			add_action( 'plugins_loaded', array( $this, 'load_textdomain' ) );

			// Perform plugin updates if newer version installed.
			add_action( 'plugins_loaded', array( $this, 'auth_update_check' ) );

			// Update the user meta with this user's failed login attempt.
			add_action( 'wp_login_failed', array( Login_Form::get_instance(), 'update_login_failed_count' ) );

			// Add users who successfully login to the approved list.
			add_action( 'wp_login', array( Sync_Userdata::get_instance(), 'ensure_wordpress_user_in_approved_list_on_login' ), 10, 2 );

			// Create menu item in Settings.
			add_action( 'admin_menu', array( Admin_Page::get_instance(), 'add_plugin_page' ) );

			// Create options page.
			add_action( 'admin_init', array( Admin_Page::get_instance(), 'page_init' ) );

			// Update user role in approved list if it's changed in the WordPress edit user page.
			add_action( 'user_profile_update_errors', array( Sync_Userdata::get_instance(), 'edit_user_profile_update_role' ), 10, 3 );

			// Update user email in approved list if it's changed in the WordPress edit user page.
			add_filter( 'send_email_change_email', array( Sync_Userdata::get_instance(), 'edit_user_profile_update_email' ), 10, 3 );

			// Enqueue javascript and css on the plugin's options page, the
			// dashboard (for the widget), and the network admin.
			add_action( 'load-settings_page_authorizer', array( Admin_Page::get_instance(), 'load_options_page' ) );
			add_action( 'admin_head-index.php', array( Admin_Page::get_instance(), 'load_options_page' ) );
			add_action( 'load-toplevel_page_authorizer', array( Admin_Page::get_instance(), 'load_options_page' ) );

			// Add custom css and js to wp-login.php.
			add_action( 'login_enqueue_scripts', array( Login_Form::get_instance(), 'login_enqueue_scripts_and_styles' ) );
			add_action( 'login_footer', array( Login_Form::get_instance(), 'load_login_footer_js' ) );

			// Create google nonce cookie when loading wp-login.php if Google is enabled.
			add_action( 'login_init', array( Login_Form::get_instance(), 'login_init__maybe_set_google_nonce_cookie' ) );

			// Modify login page with external auth links (if enabled; e.g., google or cas).
			add_action( 'login_form', array( Login_Form::get_instance(), 'login_form_add_external_service_links' ) );

			// Redirect to CAS login when visiting login page (only if option is
			// enabled, CAS is the only service, and WordPress logins are hidden).
			// Note: hook into wp_login_errors filter so this fires after the
			// authenticate hook (where the redirect to CAS happens), but before html
			// output is started (so the redirect header doesn't complain about data
			// already being sent).
			add_filter( 'wp_login_errors', array( Login_Form::get_instance(), 'wp_login_errors__maybe_redirect_to_cas' ), 10, 2 );

			// Verify current user has access to page they are visiting.
			add_action( 'parse_request', array( Authorization::get_instance(), 'restrict_access' ), 9 );
			add_action( 'init', array( Sync_Userdata::get_instance(), 'init__maybe_add_network_approved_user' ) );

			// AJAX: Save options from dashboard widget.
			add_action( 'wp_ajax_update_auth_user', array( Ajax_Endpoints::get_instance(), 'ajax_update_auth_user' ) );

			// AJAX: Save options from multisite options page.
			add_action( 'wp_ajax_save_auth_multisite_settings', array( Ajax_Endpoints::get_instance(), 'ajax_save_auth_multisite_settings' ) );

			// AJAX: Save usermeta from options page.
			add_action( 'wp_ajax_update_auth_usermeta', array( Ajax_Endpoints::get_instance(), 'ajax_update_auth_usermeta' ) );

			// AJAX: Verify google login.
			add_action( 'wp_ajax_process_google_login', array( Ajax_Endpoints::get_instance(), 'ajax_process_google_login' ) );
			add_action( 'wp_ajax_nopriv_process_google_login', array( Ajax_Endpoints::get_instance(), 'ajax_process_google_login' ) );

			// AJAX: Refresh approved user list.
			add_action( 'wp_ajax_refresh_approved_user_list', array( Ajax_Endpoints::get_instance(), 'ajax_refresh_approved_user_list' ) );

			// Add dashboard widget so instructors can add/edit users with access.
			// Hint: For Multisite Network Admin Dashboard use wp_network_dashboard_setup instead of wp_dashboard_setup.
			add_action( 'wp_dashboard_setup', array( Dashboard_Widget::get_instance(), 'add_dashboard_widgets' ) );

			// If we have a custom admin message, add the action to show it.
			$notice = get_option( 'auth_settings_advanced_admin_notice' );
			if ( $notice && strlen( $notice ) > 0 ) {
				add_action( 'admin_notices', array( Admin_Page::get_instance(), 'show_advanced_admin_notice' ) );
				add_action( 'network_admin_notices', array( Admin_Page::get_instance(), 'show_advanced_admin_notice' ) );
			}

			// Load custom javascript for the main site (e.g., for displaying alerts).
			add_action( 'wp_enqueue_scripts', array( Login_Form::get_instance(), 'auth_public_scripts' ), 20 );

			// Multisite-specific actions.
			if ( is_multisite() ) {
				// Add network admin options page (global settings for all sites).
				add_action( 'network_admin_menu', array( Admin_Page::get_instance(), 'network_admin_menu' ) );
			}

			// Remove user from authorizer lists when that user is deleted in WordPress.
			add_action( 'delete_user', array( Sync_Userdata::get_instance(), 'remove_user_from_authorizer_when_deleted' ) );
			if ( is_multisite() ) {
				// Remove multisite user from authorizer lists when that user is deleted from Network Users.
				add_action( 'remove_user_from_blog', array( Sync_Userdata::get_instance(), 'remove_network_user_from_site_when_removed' ), 10, 2 );
				add_action( 'wpmu_delete_user', array( Sync_Userdata::get_instance(), 'remove_network_user_from_authorizer_when_deleted' ) );
			}

			// Add user to authorizer approved list when that user is added to a blog from the Users screen.
			// Multisite: invite_user action fired when adding (inviting) an existing network user to the current site (with email confirmation).
			add_action( 'invite_user', array( Sync_Userdata::get_instance(), 'add_existing_user_to_authorizer_when_created' ), 10, 3 );
			// Multisite: added_existing_user action fired when adding an existing network user to the current site (without email confirmation).
			add_action( 'added_existing_user', array( Sync_Userdata::get_instance(), 'add_existing_user_to_authorizer_when_created_noconfirmation' ), 10, 2 );
			// Multisite: after_signup_user action fired when adding a new user to the site (with or without email confirmation).
			add_action( 'after_signup_user', array( Sync_Userdata::get_instance(), 'add_new_user_to_authorizer_when_created' ), 10, 4 );
			// Single site: edit_user_created_user action fired when adding a new user to the site (with or without email notification).
			add_action( 'edit_user_created_user', array( Sync_Userdata::get_instance(), 'add_new_user_to_authorizer_when_created_single_site' ), 10, 2 );

			// Add user to network approved users (and remove from individual sites)
			// when user is elevated to super admin status.
			add_action( 'grant_super_admin', array( Sync_Userdata::get_instance(), 'grant_super_admin__add_to_network_approved' ) );
			// Remove user from network approved users (and add them to the approved
			// list on sites they are already on) when super admin status is removed.
			add_action( 'revoke_super_admin', array( Sync_Userdata::get_instance(), 'revoke_super_admin__remove_from_network_approved' ) );

		}


		/**
		 * Plugin activation hook.
		 * Will also activate the plugin for all sites/blogs if this is a "Network enable."
		 *
		 * @param bool $network_wide Whether the plugin is being activated for the whole network.
		 * @return void
		 */
		public function activate( $network_wide ) {
			global $wpdb;
			$options = Options::get_instance();
			$sync_userdata = Sync_Userdata::get_instance();

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
					if ( ! Helper::in_multi_array( $user->user_email, $auth_multisite_settings_access_users_approved ) ) {
						$approved_user = array(
							'email'      => Helper::lowercase( $user->user_email ),
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
					$options->set_default_options();
					$sync_userdata->add_wp_users_to_approved_list();
				}
				switch_to_blog( $current_blog_id );

			} else {
				// Set default plugin options and add current users to approved list.
				$options->set_default_options();
				$sync_userdata->add_wp_users_to_approved_list();
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
			$options       = Options::get_instance();
			$auth_settings = $options->get_all( Helper::SINGLE_CONTEXT, 'allow override' );

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
						Helper::seconds_as_sentence( $seconds_remaining_long_lockout ),
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
						Helper::seconds_as_sentence( $seconds_remaining_short_lockout ),
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

			// Look for an existing WordPress account matching the externally
			// authenticated user. Perform the match either by username or email.
			if ( isset( $auth_settings['cas_link_on_username'] ) && 1 === intval( $auth_settings['cas_link_on_username'] ) ) {
				// Get the external user's WordPress account by username. This is less
				// secure, but a user reported having an installation where a previous
				// CAS plugin had created over 9000 WordPress accounts without email
				// addresses. This option was created to support that case, and any
				// other CAS servers where emails are not used as account identifiers.
				$user = get_user_by( 'login', $result['username']);
			} else {
				// Get the external user's WordPress account by email address. This is
				// the normal behavior (and the most secure).
				foreach ( $externally_authenticated_emails as $externally_authenticated_email ) {
					$user = get_user_by( 'email', Helper::lowercase( $externally_authenticated_email ) );
					// Stop trying email addresses once we have found a match.
					if ( false !== $user ) {
						break;
					}
				}
			}

			// Check this external user's access against the access lists
			// (pending, approved, blocked).
			$result = Authorization::get_instance()->check_user_access( $user, $externally_authenticated_emails, $result );

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
			$email        = Helper::lowercase( $attributes['payload']['email'] );
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

			// Use the WordPress certificate bundle at /wp-includes/certificates/ca-bundle.crt.
			phpCAS::setCasServerCACert( ABSPATH . WPINC . '/certificates/ca-bundle.crt' );

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
				$externally_authenticated_email = Helper::lowercase( $username ) . '@' . $domain_guess;
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
					$externally_authenticated_email = Helper::lowercase( $username . $auth_settings['cas_attr_email'] );
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
							$externally_authenticated_email[] = Helper::lowercase( $external_email );
						}
					} else {
						$externally_authenticated_email = Helper::lowercase( $cas_attributes[ $auth_settings['cas_attr_email'] ] );
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
				$ldap_host = Helper::build_url( $parsed_host );
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
				$bind_password = Helper::decrypt( $auth_settings['ldap_password'] );
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
				array_push( $ldap_attributes_to_retrieve, Helper::lowercase( $auth_settings['ldap_attr_email'] ) );
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
				$ldap_attr_first_name = array_key_exists( 'ldap_attr_first_name', $auth_settings ) ? Helper::lowercase( $auth_settings['ldap_attr_first_name'] ) : '';
				if ( strlen( $ldap_attr_first_name ) > 0 && array_key_exists( $ldap_attr_first_name, $ldap_entries[ $i ] ) && $ldap_entries[ $i ][ $ldap_attr_first_name ]['count'] > 0 && strlen( $ldap_entries[ $i ][ $ldap_attr_first_name ][0] ) > 0 ) {
					$first_name = $ldap_entries[ $i ][ $ldap_attr_first_name ][0];
				}
				$ldap_attr_last_name = array_key_exists( 'ldap_attr_last_name', $auth_settings ) ? Helper::lowercase( $auth_settings['ldap_attr_last_name'] ) : '';
				if ( strlen( $ldap_attr_last_name ) > 0 && array_key_exists( $ldap_attr_last_name, $ldap_entries[ $i ] ) && $ldap_entries[ $i ][ $ldap_attr_last_name ]['count'] > 0 && strlen( $ldap_entries[ $i ][ $ldap_attr_last_name ][0] ) > 0 ) {
					$last_name = $ldap_entries[ $i ][ $ldap_attr_last_name ][0];
				}
				// Get user email if it is specified in another field.
				$ldap_attr_email = array_key_exists( 'ldap_attr_email', $auth_settings ) ? Helper::lowercase( $auth_settings['ldap_attr_email'] ) : '';
				if ( strlen( $ldap_attr_email ) > 0 ) {
					// If the email attribute starts with an at symbol (@), assume that the
					// email domain is manually entered there (instead of a reference to an
					// LDAP attribute), and combine that with the username to create the email.
					// Otherwise, look up the LDAP attribute for email.
					if ( substr( $ldap_attr_email, 0, 1 ) === '@' ) {
						$email = Helper::lowercase( $username . $ldap_attr_email );
					} elseif ( array_key_exists( $ldap_attr_email, $ldap_entries[ $i ] ) && $ldap_entries[ $i ][ $ldap_attr_email ]['count'] > 0 && strlen( $ldap_entries[ $i ][ $ldap_attr_email ][0] ) > 0 ) {
						$email = Helper::lowercase( $ldap_entries[ $i ][ $ldap_attr_email ][0] );
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
			$externally_authenticated_email = Helper::lowercase( $username . '@' . $domain );

			// If an LDAP attribute has been specified as containing the email address, use that instead.
			if ( strlen( $email ) > 0 ) {
				$externally_authenticated_email = Helper::lowercase( $email );
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
			$options       = Options::get_instance();
			$auth_settings = $options->get_all( Helper::SINGLE_CONTEXT, 'allow override' );

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
		 * ***************************
		 * Login page (wp-login.php)
		 * ***************************
		 */




		/**
		 * ***************************
		 * Options page
		 * ***************************
		 */





		/**
		 * ***************************
		 * Multisite: Network Admin Options page
		 * ***************************
		 */



		/**
		 * ***************************
		 * Dashboard widget
		 * ***************************
		 */




		/**
		 * ***************************
		 * AJAX Actions
		 * ***************************
		 */



		/**
		 * This array filter will remove any users who failed email address validation
		 * (which would set their email to a blank string).
		 *
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
		 * Plugin Update Routines.
		 *
		 * Action: plugins_loaded
		 */
		public function auth_update_check() {
			$options = Options::get_instance();

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
						$options->set_default_options();
						// Switch back to original blog.
						restore_current_blog();
					}
				} else {
					// Set meaningful defaults for this site.
					$options->set_default_options();
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
							$plaintext_ldap_password        = Helper::decrypt( $auth_settings['ldap_password'], 'mcrypt' );
							$auth_settings['ldap_password'] = Helper::encrypt( $plaintext_ldap_password );
							update_blog_option( $blog_id, 'auth_settings', $auth_settings );
						}
					}
				} else {
					// Reencrypt LDAP password on this single-site install.
					$auth_settings = get_option( 'auth_settings', array() );
					if ( array_key_exists( 'ldap_password', $auth_settings ) && strlen( $auth_settings['ldap_password'] ) > 0 ) {
						$plaintext_ldap_password        = Helper::decrypt( $auth_settings['ldap_password'], 'mcrypt' );
						$auth_settings['ldap_password'] = Helper::encrypt( $plaintext_ldap_password );
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
						$plaintext_ldap_password                  = Helper::decrypt( $auth_multisite_settings['ldap_password'], 'mcrypt' );
						$auth_multisite_settings['ldap_password'] = Helper::encrypt( $plaintext_ldap_password );
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
						$options->set_default_options();
						restore_current_blog();
					}
				} else {
					$options->set_default_options();
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
						$options->set_default_options();
						restore_current_blog();
					}
				} else {
					$options->set_default_options();
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
						$options->set_default_options();
						restore_current_blog();
					}
				} else {
					$options->set_default_options();
				}
				// Update version to reflect this change has been made.
				$auth_version   = $update_if_older_than;
				$needs_updating = true;
			}

			// Update: Set default value for newly added option cas_link_on_username.
			$update_if_older_than = 20190227;
			if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
				// Provide default values for any $auth_settings options that don't exist.
				if ( is_multisite() ) {
					// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
					$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
					foreach ( $sites as $site ) {
						$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
						switch_to_blog( $blog_id );
						$options->set_default_options();
						restore_current_blog();
					}
				} else {
					$options->set_default_options();
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
