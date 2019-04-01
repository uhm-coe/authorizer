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
			add_action( 'init', array( Sync_Userdata::get_instance(), 'init__maybe_add_network_approved_user' ) );

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
				add_action( 'admin_notices', array( Admin_Page::get_instance(), 'show_advanced_admin_notice' ) );
				add_action( 'network_admin_notices', array( Admin_Page::get_instance(), 'show_advanced_admin_notice' ) );
			}

			// Load custom javascript for the main site (e.g., for displaying alerts).
			add_action( 'wp_enqueue_scripts', array( $this, 'auth_public_scripts' ), 20 );

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
		 * @return WP_Error|WP_User
		 *                             WP_Error if there was an error on user creation / adding user to blog.
		 *                             WP_Error / wp_die() if user does not have access.
		 *                             WP_User if user has access.
		 */
		private function check_user_access( $user, $user_emails, $user_data = array() ) {
			// Grab plugin settings.
			$options                                    = Options::get_instance();
			$auth_settings                              = $options->get_all( Helper::SINGLE_CONTEXT, 'allow override' );
			$auth_settings_access_users_pending         = $options->sanitize_user_list(
				$options->get( 'access_users_pending', Helper::SINGLE_CONTEXT )
			);
			$auth_settings_access_users_approved_single = $options->get( 'access_users_approved', Helper::SINGLE_CONTEXT );
			$auth_settings_access_users_approved_multi  = $options->get( 'access_users_approved', Helper::NETWORK_CONTEXT );
			$auth_settings_access_users_approved        = $options->sanitize_user_list(
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
						$auth_settings_access_users_blocked = $options->sanitize_user_list(
							$options->get( 'access_users_blocked', Helper::SINGLE_CONTEXT )
						);
						array_push(
							$auth_settings_access_users_blocked, array(
								'email'      => Helper::lowercase( $user_email ),
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
					wp_die( wp_kses( $error_message, Helper::$allowed_html ), esc_html( $page_title ) );
					return new WP_Error( 'invalid_login', __( 'Invalid login attempted.', 'authorizer' ) );
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
						'email'      => Helper::lowercase( $user_email ),
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
					$user_info = $is_newly_approved_user ? $approved_user : Helper::get_user_info_from_list( $user_email, $auth_settings_access_users_approved );

					// If this user's role was modified above (in the
					// authorizer_custom_role filter), use that value instead of
					// whatever is specified in the approved list.
					if ( $default_role !== $approved_role ) {
						$user_info['role'] = $approved_role;
					}

					// If the approved external user does not have a WordPress account, create it.
					if ( ! $user ) {
						if ( array_key_exists( 'username', $user_data ) ) {
							$username = $user_data['username'];
						} else {
							$username = explode( '@', $user_info['email'] );
							$username = $username[0];
						}
						// If there's already a user with this username (e.g.,
						// johndoe/johndoe@gmail.com exists, and we're trying to add
						// johndoe/johndoe@example.com), use the full email address
						// as the username.
						if ( get_user_by( 'login', $username ) !== false ) {
							$username = $user_info['email'];
						}
						$result = wp_insert_user(
							array(
								'user_login'      => strtolower( $username ),
								'user_pass'       => wp_generate_password(), // random password.
								'first_name'      => array_key_exists( 'first_name', $user_data ) ? $user_data['first_name'] : '',
								'last_name'       => array_key_exists( 'last_name', $user_data ) ? $user_data['last_name'] : '',
								'user_email'      => Helper::lowercase( $user_info['email'] ),
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
								if ( Helper::in_multi_array( $user->user_email, $other_auth_settings_access_users_approved ) ) {
									$other_user_info = Helper::get_user_info_from_list( $user->user_email, $other_auth_settings_access_users_approved );
									// Add user to other site.
									add_user_to_blog( $blog_id, $user->ID, $other_user_info['role'] );
								}
							}
						}

						// Check if this new user has any preassigned usermeta
						// values in their approved list entry, and apply them to
						// their new WordPress account.
						if ( array_key_exists( 'usermeta', $user_info ) && is_array( $user_info['usermeta'] ) ) {
							$meta_key = $options->get( 'advanced_usermeta' );

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
						$pending_user['email']      = Helper::lowercase( $user_email );
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
					wp_die( wp_kses( $error_message, Helper::$allowed_html ), esc_html( $page_title ) );
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
			$options       = Options::get_instance();
			$auth_settings = $options->get_all( Helper::SINGLE_CONTEXT, 'allow override' );

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
			$options       = Options::get_instance();
			$auth_settings = $options->get_all( Helper::SINGLE_CONTEXT, 'allow override' );

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
				( 'logged_in_users' === $auth_settings['access_who_can_view'] && Helper::is_user_logged_in_and_blog_user() && $this->is_email_in_list( $current_user->user_email, 'approved' ) ) ||
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
				wp_die( wp_kses( $error_message, Helper::$allowed_html ), esc_html( $page_title ) );
			} else {
				wp_redirect( wp_login_url( $current_path ), 302 );
				exit;
			}

			// Sanity check: we should never get here.
			wp_die( '<p>Access denied.</p>', 'Site Access Restricted' );
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
			$options      = Options::get_instance();
			$current_path = ! empty( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : home_url();
			wp_enqueue_script( 'auth_public_scripts', plugins_url( '/js/authorizer-public.js', __FILE__ ), array( 'jquery' ), '2.8.0' );
			$auth_localized = array(
				'wpLoginUrl'      => wp_login_url( $current_path ),
				'publicWarning'   => get_option( 'auth_settings_advanced_public_notice' ),
				'anonymousNotice' => $options->get( 'access_redirect_to_message' ),
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
			$options       = Options::get_instance();
			$auth_settings = $options->get_all( Helper::SINGLE_CONTEXT, 'allow override' );

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
			$options       = Options::get_instance();
			$auth_settings = $options->get_all( Helper::SINGLE_CONTEXT, 'allow override' );

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
				wp_redirect( Helper::modify_current_url_for_cas_login() );
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

			// Get options object.
			$options = Options::get_instance();

			// Get multisite settings.
			$auth_multisite_settings = get_blog_option( $this->current_site_blog_id, 'auth_multisite_settings', array() );

			// Sanitize settings.
			$auth_multisite_settings = $options->sanitize_options( $_POST );

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
				'cas_link_on_username',
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
			$options        = Options::get_instance();
			$widget_enabled = $options->get( 'advanced_widget_enabled', Helper::SINGLE_CONTEXT, 'allow override' ) === '1';

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
			$access_lists = Access_Lists::get_instance();
			$login_access = Login_Access::get_instance();
			?>
			<form method="post" id="auth_settings_access_form" action="">
				<?php $login_access->print_section_info_access_login(); ?>
				<div>
					<h2><?php esc_html_e( 'Pending Users', 'authorizer' ); ?></h2>
					<?php $access_lists->print_combo_auth_access_users_pending(); ?>
				</div>
				<div>
					<h2><?php esc_html_e( 'Approved Users', 'authorizer' ); ?></h2>
					<?php $access_lists->print_combo_auth_access_users_approved(); ?>
				</div>
				<div>
					<h2><?php esc_html_e( 'Blocked Users', 'authorizer' ); ?></h2>
					<?php $access_lists->print_combo_auth_access_users_blocked(); ?>
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

			// Get options reference.
			$options      = Options::get_instance();
			$access_lists = Access_Lists::get_instance();

			// Get user list.
			$option               = 'access_users_approved';
			$admin_mode           = is_multisite() && $is_network_admin ? Helper::NETWORK_CONTEXT : Helper::SINGLE_CONTEXT;
			$auth_settings_option = $options->get( $option, $admin_mode, 'no override' );
			$auth_settings_option = is_array( $auth_settings_option ) ? $auth_settings_option : array();

			// Get multisite approved users (will be added to top of list, greyed out).
			$auth_override_multisite        = $options->get( 'advanced_override_multisite' );
			$auth_multisite_settings        = $options->get_all( Helper::NETWORK_CONTEXT );
			$auth_settings_option_multisite = array();
			if (
				is_multisite() &&
				! $is_network_admin &&
				1 !== intval( $auth_override_multisite ) &&
				array_key_exists( 'multisite_override', $auth_multisite_settings ) &&
				'1' === $auth_multisite_settings['multisite_override']
			) {
				$auth_settings_option_multisite = $options->get( $option, Helper::NETWORK_CONTEXT, 'allow override' );
				$auth_settings_option_multisite = is_array( $auth_settings_option_multisite ) ? $auth_settings_option_multisite : array();
				// Add multisite users to the beginning of the main user array.
				foreach ( array_reverse( $auth_settings_option_multisite ) as $approved_user ) {
					$approved_user['multisite_user'] = true;
					array_unshift( $auth_settings_option, $approved_user );
				}
			}

			// Get custom usermeta field to show.
			$advanced_usermeta = $options->get( 'advanced_usermeta' );

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
			$sort_by        = $options->get( 'advanced_users_sort_by', Helper::SINGLE_CONTEXT, 'allow override' ); // email, role, date_added (registered), created (date approved).
			$sort_order     = $options->get( 'advanced_users_sort_order', Helper::SINGLE_CONTEXT, 'allow override' ); // asc or desc.
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
			$users_per_page = intval( $options->get( 'advanced_users_per_page', Helper::SINGLE_CONTEXT, 'allow override' ) );
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
				$access_lists->render_user_element( $approved_user, $key, $option, $admin_mode, $advanced_usermeta );
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
			$options    = Options::get_instance();
			$email      = sanitize_email( wp_unslash( $_REQUEST['email'] ) );
			$meta_value = sanitize_meta( 'authorizer-usermeta', wp_unslash( $_REQUEST['usermeta'] ), 'user' );
			$meta_key   = $options->get( 'advanced_usermeta' );

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
				$auth_settings_access_users_approved               = $options->get( 'access_users_approved', Helper::SINGLE_CONTEXT );
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

			// Get reference to plugin options.
			$options = Options::get_instance();

			// Track any emails that couldn't be added (used when adding users).
			$invalid_emails = array();

			// Editing a pending list entry.
			if ( 'access_users_pending' === $_POST['setting'] ) {
				// Sanitize posted data.
				$access_users_pending = array();
				if ( isset( $_POST['access_users_pending'] ) && is_array( $_POST['access_users_pending'] ) ) {
					$access_users_pending = $options->sanitize_update_auth_users( wp_unslash( $_POST['access_users_pending'] ) );
				}

				// Deal with each modified user (add or remove).
				foreach ( $access_users_pending as $pending_user ) {

					if ( 'add' === $pending_user['edit_action'] ) {

						// Add new user to pending list and save (skip if it's
						// already there--someone else might have just done it).
						if ( ! $this->is_email_in_list( $pending_user['email'], 'pending' ) ) {
							$auth_settings_access_users_pending = $options->sanitize_user_list(
								$options->get( 'access_users_pending', Helper::SINGLE_CONTEXT )
							);
							array_push( $auth_settings_access_users_pending, $pending_user );
							update_option( 'auth_settings_access_users_pending', $auth_settings_access_users_pending );
						}
					} elseif ( 'remove' === $pending_user['edit_action'] ) {

						// Remove user from pending list and save.
						$auth_settings_access_users_pending = $options->get( 'access_users_pending', Helper::SINGLE_CONTEXT );
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
					$access_users_approved = $options->sanitize_update_auth_users( wp_unslash( $_POST['access_users_approved'] ) );
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
								$username = Helper::lowercase( $approved_user['email'] );
							}
							if ( 'false' !== $approved_user['multisite_user'] ) {
								$result = wpmu_create_user(
									strtolower( $username ),
									$plaintext_password,
									Helper::lowercase( $approved_user['email'] )
								);
							} else {
								$result = wp_insert_user(
									array(
										'user_login'      => strtolower( $username ),
										'user_pass'       => $plaintext_password,
										'first_name'      => '',
										'last_name'       => '',
										'user_email'      => Helper::lowercase( $approved_user['email'] ),
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
						Sync_Userdata::get_instance()->maybe_email_welcome_message( $approved_user['email'] );

						// Add new user to approved list and save (skip if it's
						// already there--someone else might have just done it).
						if ( 'false' !== $approved_user['multisite_user'] ) {
							if ( ! $this->is_email_in_list( $approved_user['email'], 'approved', 'multisite' ) ) {
								$auth_multisite_settings_access_users_approved = $options->sanitize_user_list(
									$options->get( 'access_users_approved', Helper::NETWORK_CONTEXT )
								);
								$approved_user['date_added']                   = date( 'M Y' );
								array_push( $auth_multisite_settings_access_users_approved, $approved_user );
								update_blog_option( $this->current_site_blog_id, 'auth_multisite_settings_access_users_approved', $auth_multisite_settings_access_users_approved );
							} else {
								$invalid_emails[] = $approved_user['email'];
							}
						} else {
							if ( ! $this->is_email_in_list( $approved_user['email'], 'approved' ) ) {
								$auth_settings_access_users_approved = $options->sanitize_user_list(
									$options->get( 'access_users_approved', Helper::SINGLE_CONTEXT )
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
							$auth_multisite_settings_access_users_approved = $options->get( 'access_users_approved', Helper::NETWORK_CONTEXT );
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
							$auth_settings_access_users_approved = $options->get( 'access_users_approved', Helper::SINGLE_CONTEXT );
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
								$auth_multisite_settings_access_users_approved = $options->sanitize_user_list(
									$options->get( 'access_users_approved', Helper::NETWORK_CONTEXT )
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
								$auth_settings_access_users_approved = $options->sanitize_user_list(
									$options->get( 'access_users_approved', Helper::SINGLE_CONTEXT )
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
					$access_users_blocked = $options->sanitize_update_auth_users(
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
							$auth_settings_access_users_blocked = $options->sanitize_user_list(
								$options->get( 'access_users_blocked', Helper::SINGLE_CONTEXT )
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
						$auth_settings_access_users_blocked = $options->get( 'access_users_blocked', Helper::SINGLE_CONTEXT );
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

			$options = Options::get_instance();

			switch ( $list ) {
				case 'pending':
					$auth_settings_access_users_pending = $options->get( 'access_users_pending', Helper::SINGLE_CONTEXT );
					return Helper::in_multi_array( $email, $auth_settings_access_users_pending );
				case 'blocked':
					$auth_settings_access_users_blocked = $options->get( 'access_users_blocked', Helper::SINGLE_CONTEXT );
					// Blocked list can have wildcard matches, e.g., @baddomain.com, which
					// should match any email address at that domain. Check if any wildcards
					// exist, and if the email address has that domain.
					$email_in_blocked_domain = false;
					$blocked_domains         = preg_grep(
						'/^@.*/', array_map(
							function ( $blocked_item ) {
								return $blocked_item['email']; },
							$auth_settings_access_users_blocked
						)
					);
					foreach ( $blocked_domains as $blocked_domain ) {
						$email_domain = substr( $email, strrpos( $email, '@' ) );
						if ( $email_domain === $blocked_domain ) {
							$email_in_blocked_domain = true;
							break;
						}
					}
					return $email_in_blocked_domain || Helper::in_multi_array( $email, $auth_settings_access_users_blocked );
				case 'approved':
				default:
					if ( 'single' !== $multisite_mode ) {
						// Get multisite users only.
						$auth_settings_access_users_approved = $options->get( 'access_users_approved', Helper::NETWORK_CONTEXT );
					} elseif ( is_multisite() && 1 === intval( $options->get( 'advanced_override_multisite' ) ) ) {
						// This site has overridden any multisite settings, so only get its users.
						$auth_settings_access_users_approved = $options->get( 'access_users_approved', Helper::SINGLE_CONTEXT );
					} else {
						// Get all site users and all multisite users.
						$auth_settings_access_users_approved = array_merge(
							$options->get( 'access_users_approved', Helper::SINGLE_CONTEXT ),
							$options->get( 'access_users_approved', Helper::NETWORK_CONTEXT )
						);
					}
					return Helper::in_multi_array( $email, $auth_settings_access_users_approved );
			}
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
