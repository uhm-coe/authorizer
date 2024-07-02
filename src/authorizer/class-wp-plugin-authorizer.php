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
use Authorizer\Authentication;
use Authorizer\Authorization;
use Authorizer\Admin_Page;
use Authorizer\Login_Form;
use Authorizer\Updates;
use Authorizer\Sync_Userdata;
use Authorizer\Ajax_Endpoints;
use Authorizer\Dashboard_Widget;

/**
 * Main plugin class. Activates/deactivates the plugin, and registers all hooks.
 */
class WP_Plugin_Authorizer extends Singleton {

	/**
	 * Constructor.
	 */
	public function __construct() {
		// Installation and uninstallation hooks.
		register_activation_hook( 'authorizer/authorizer.php', array( $this, 'activate' ) );
		register_deactivation_hook( 'authorizer/authorizer.php', array( $this, 'deactivate' ) );

		/**
		 * Register hooks.
		 */

		// Custom wp authentication routine using external service.
		add_filter( 'authenticate', array( Authentication::get_instance(), 'custom_authenticate' ), 1, 3 );

		// Custom logout action using external service.
		add_action( 'clear_auth_cookie', array( Authentication::get_instance(), 'pre_logout' ) );
		add_action( 'wp_logout', array( Authentication::get_instance(), 'custom_logout' ) );

		// Create settings link on Plugins page.
		add_filter( 'plugin_action_links_' . plugin_basename( plugin_root() ), array( Admin_Page::get_instance(), 'plugin_settings_link' ) );
		add_filter( 'network_admin_plugin_action_links_' . plugin_basename( plugin_root() ), array( Admin_Page::get_instance(), 'network_admin_plugin_settings_link' ) );

		// Modify login page with a custom password url (if option is set).
		add_filter( 'lostpassword_url', array( Login_Form::get_instance(), 'custom_lostpassword_url' ) );

		// Modify the log in URL (if applicable options are set).
		add_filter( 'login_url', array( Login_Form::get_instance(), 'maybe_add_external_wordpress_to_log_in_links' ) );

		// If we have a custom login error, add the filter to show it.
		$error = get_option( 'auth_settings_advanced_login_error' );
		if ( $error && strlen( $error ) > 0 ) {
			add_filter( 'login_errors', array( Login_Form::get_instance(), 'show_advanced_login_error' ) );
		}

		// Redirect to wp-login.php?redirect_to=? destination after an Azure login.
		add_filter( 'login_redirect', array( Options\External\OAuth2::get_instance(), 'maybe_redirect_after_azure_login' ), 10, 2 );

		// Enable localization. Translation files stored in /languages.
		add_action( 'plugins_loaded', array( $this, 'load_textdomain' ) );

		// Perform plugin updates if newer version installed.
		add_action( 'plugins_loaded', array( Updates::get_instance(), 'auth_update_check' ) );

		// Update the user meta with this user's failed login attempt.
		add_action( 'wp_login_failed', array( Login_Form::get_instance(), 'update_login_failed_count' ) );

		// Add users who successfully login to the approved list.
		add_action( 'wp_login', array( Sync_Userdata::get_instance(), 'ensure_wordpress_user_in_approved_list_on_login' ), 10, 2 );

		// Create menu item in Settings.
		add_action( 'admin_menu', array( Admin_Page::get_instance(), 'add_plugin_page' ) );

		// Create options page.
		add_action( 'admin_init', array( Admin_Page::get_instance(), 'page_init' ) );

		// Update user role in approved list if it's changed via bulk action on the
		// WordPress list users page (and anywhere else WP_User::set_role() is called).
		add_action( 'set_user_role', array( Sync_Userdata::get_instance(), 'set_user_role_sync_role' ), 10, 3 );

		// Update user email in approved list if it's changed in the WordPress edit user page.
		add_filter( 'send_email_change_email', array( Sync_Userdata::get_instance(), 'edit_user_profile_update_email' ), 10, 3 );

		// Enqueue javascript and css on the plugin's options page, the
		// dashboard (for the widget), and the network admin.
		add_action( 'load-settings_page_authorizer', array( Admin_Page::get_instance(), 'load_options_page' ) );
		add_action( 'load-toplevel_page_authorizer', array( Admin_Page::get_instance(), 'load_options_page' ) );
		add_action( 'admin_head-index.php', array( Admin_Page::get_instance(), 'load_options_page' ) );
		add_action( 'admin_head-index.php', array( Dashboard_Widget::get_instance(), 'widget_scripts' ) );

		// Add custom css and js to wp-login.php.
		add_action( 'login_enqueue_scripts', array( Login_Form::get_instance(), 'login_enqueue_scripts_and_styles' ) );
		add_action( 'login_footer', array( Login_Form::get_instance(), 'load_login_footer_js' ) );

		// Modify login page with external auth links (if enabled; e.g., google or cas).
		add_action( 'login_form', array( Login_Form::get_instance(), 'login_form_add_external_service_links' ) );

		// Redirect to CAS login when visiting login page (only if option is
		// enabled, CAS is the only service, and WordPress logins are hidden).
		// Note: hook into wp_login_errors filter so this fires after the
		// authenticate hook (where the redirect to CAS happens), but before html
		// output is started (so the redirect header doesn't complain about data
		// already being sent).
		add_filter( 'wp_login_errors', array( Login_Form::get_instance(), 'wp_login_errors__maybe_redirect_to_cas' ), 10, 2 );

		// Redirect to OAuth2 login when visiting login page (only if option is
		// enabled, OAuth2 is the only service, and WordPress logins are hidden).
		// Note: hook into wp_login_errors filter so this fires after the
		// authenticate hook (where the redirect to OAuth2 happens), but before html
		// output is started (so the redirect header doesn't complain about data
		// already being sent).
		add_filter( 'wp_login_errors', array( Login_Form::get_instance(), 'wp_login_errors__maybe_redirect_to_oauth2' ), 10, 2 );

		// Prevent access to password reset if WordPress logins are disabled.
		add_filter( 'lost_password_html_link', array( Login_Form::get_instance(), 'maybe_hide_lost_password_link' ), PHP_INT_MAX, 1 );
		add_action( 'lost_password', array( Login_Form::get_instance(), 'maybe_hide_lost_password_form' ), PHP_INT_MAX, 1 );
		add_filter( 'lostpassword_errors', array( Login_Form::get_instance(), 'maybe_prevent_password_reset' ), PHP_INT_MAX, 1 );

		// Verify current user has access to page they are visiting.
		add_action( 'parse_request', array( Authorization::get_instance(), 'restrict_access' ), 9 );
		add_action( 'init', array( Sync_Userdata::get_instance(), 'init__maybe_add_network_approved_user' ) );

		// Hide private pages in search and archives for anonymous users if "only
		// logged in users can see the site" is enabled.
		add_action( 'pre_get_posts', array( Authorization::get_instance(), 'remove_private_pages_from_search_and_archives' ), 10, 1 );

		// Prevent REST API access if user isn't authenticated and "only logged in
		// users can see the site" is enabled.
		add_action( 'rest_authentication_errors', array( Authorization::get_instance(), 'restrict_rest_api' ), 10, 1 );

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

		// AJAX: Test LDAP user.
		add_action( 'wp_ajax_auth_settings_ldap_test_user', array( Ajax_Endpoints::get_instance(), 'ajax_auth_settings_ldap_test_user' ) );

		// Add dashboard widget so instructors can add/edit users with access.
		// Hint: For Multisite Network Admin Dashboard use wp_network_dashboard_setup instead of wp_dashboard_setup.
		add_action( 'wp_dashboard_setup', array( Dashboard_Widget::get_instance(), 'add_dashboard_widgets' ) );

		// If we have a custom admin message, add the action to show it.
		$notice = get_option( 'auth_settings_advanced_admin_notice' );
		if ( $notice && strlen( $notice ) > 0 ) {
			add_action( 'admin_notices', array( Admin_Page::get_instance(), 'show_advanced_admin_notice' ) );
			add_action( 'network_admin_notices', array( Admin_Page::get_instance(), 'show_advanced_admin_notice' ) );
		}

		// Add [authorizer_login_form] shortcode to render the login form.
		add_shortcode( 'authorizer_login_form', array( Login_Form::get_instance(), 'shortcode_authorizer_login_form' ) );

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
		$options       = Options::get_instance();
		$sync_userdata = Sync_Userdata::get_instance();

		// If we're in a multisite environment, run the plugin activation for each
		// site when network enabling.
		// Note: wp-cli does not use nonces, so we skip the nonce check here to
		// allow the "wp plugin activate authorizer" command.
		// phpcs:ignore WordPress.CSRF.NonceVerification.NoNonceVerification
		if ( is_multisite() && $network_wide ) {

			// Add super admins to the multisite approved list.
			$auth_multisite_settings_access_users_approved               = get_blog_option( get_main_site_id( get_main_network_id() ), 'auth_multisite_settings_access_users_approved', array() );
			$should_update_auth_multisite_settings_access_users_approved = false;
			foreach ( get_super_admins() as $super_admin ) {
				$user = get_user_by( 'login', $super_admin );
				// Skip if user wasn't found (edge case).
				if ( empty( $user ) ) {
					continue;
				}
				// Add to approved list if not there.
				if ( ! Helper::in_multi_array( $user->user_email, $auth_multisite_settings_access_users_approved ) ) {
					$approved_user = array(
						'email'      => Helper::lowercase( $user->user_email ),
						'role'       => is_array( $user->roles ) && count( $user->roles ) > 0 ? $user->roles[0] : 'administrator',
						'date_added' => wp_date( 'M Y', strtotime( $user->user_registered ) ),
						'local_user' => true,
					);
					array_push( $auth_multisite_settings_access_users_approved, $approved_user );
					$should_update_auth_multisite_settings_access_users_approved = true;
				}
			}
			if ( $should_update_auth_multisite_settings_access_users_approved ) {
				update_blog_option( get_main_site_id( get_main_network_id() ), 'auth_multisite_settings_access_users_approved', $auth_multisite_settings_access_users_approved );
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
		// Do nothing. Use uninstall.php instead.
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
			basename( dirname( plugin_root() ) ) . '/languages'
		);
	}
}
