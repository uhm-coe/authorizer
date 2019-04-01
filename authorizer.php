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

require_once dirname( __FILE__ ) . '/src/authorizer/class-authentication.php';
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
			add_filter( 'authenticate', array( Authentication::get_instance(), 'custom_authenticate' ), 1, 3 );

			// Custom logout action using external service.
			add_action( 'wp_logout', array( Authentication::get_instance(), 'custom_logout' ) );

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
