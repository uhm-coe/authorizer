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
use Authorizer\Options\Access_Lists;
use Authorizer\Options\Login_Access;
use Authorizer\Options\Public_Access;
use Authorizer\Options\External;
use Authorizer\Options\External\OAuth2;
use Authorizer\Options\External\Google;
use Authorizer\Options\External\Cas;
use Authorizer\Options\External\Ldap;
use Authorizer\Options\Advanced;

/**
 * Contains functions for creating the Authorizer Settings page and adding it to
 * the WordPress Dashboard menu.
 */
class Admin_Page extends Singleton {

	/**
	 * Add help documentation to the options page.
	 *
	 * Action: load-settings_page_authorizer > admin_head
	 */
	public function admin_head() {
		$screen = get_current_screen();

		// Don't print any help items if not on the Authorizer Settings page.
		if ( empty( $screen->id ) || ! in_array( $screen->id, array( 'toplevel_page_authorizer-network', 'toplevel_page_authorizer', 'settings_page_authorizer' ), true ) ) {
			return;
		}

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
				'content' => wp_kses_post( $help_auth_settings_access_lists_content ),
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
				'content' => wp_kses_post( $help_auth_settings_access_login_content ),
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
				'content' => wp_kses_post( $help_auth_settings_access_public_content ),
			)
		);

		// Add help tab for External Service (CAS, LDAP) Settings.
		$help_auth_settings_external_content = '
			<p>' . __( "<strong>Type of external service to authenticate against</strong>: Choose which authentication service type you will be using. You'll have to fill out different fields below depending on which service you choose.", 'authorizer' ) . '</p>
			<p>' . __( '<strong>Enable OAuth2 Logins</strong>: Choose if you want to allow users to log in with one of the supported OAuth2 providers. You will need to enter your API Client ID and Secret to enable these logins.', 'authorizer' ) . '</p>
			<p>' . __( '<strong>Enable Google Logins</strong>: Choose if you want to allow users to log in with their Google Account credentials. You will need to enter your API Client ID and Secret to enable Google Logins.', 'authorizer' ) . '</p>
			<p>' . __( '<strong>Enable CAS Logins</strong>: Choose if you want to allow users to log in with via CAS (Central Authentication Service). You will need to enter details about your CAS server (host, port, and path) to enable CAS Logins.', 'authorizer' ) . '</p>
			<p>' . __( '<strong>Enable LDAP Logins</strong>: Choose if you want to allow users to log in with their LDAP (Lightweight Directory Access Protocol) credentials. You will need to enter details about your LDAP server (host, port, search base, uid attribute, directory user, directory user password, and whether to use STARTTLS) to enable LDAP Logins.', 'authorizer' ) . '</p>
			<p>' . __( '<strong>Default role for new CAS users</strong>: Specify which role new external users will get by default. Be sure to choose a role with limited permissions!', 'authorizer' ) . '</p>
			<p><strong><em>' . __( 'If you enable OAuth2 logins:', 'authorizer' ) . '</em></strong></p>
			<ul>
				<li>' . __( '<strong>Client ID</strong>: You can generate this ID following the instructions for your specific provider.', 'authorizer' ) . '<br>' . __( "Note: for increased security, you can leave this field blank and instead define this value either in wp-config.php via <code>define( 'AUTHORIZER_OAUTH2_CLIENT_ID', '...' );</code>, or you may fetch it from an external service like AWS Secrets Manager by hooking into the <code>authorizer_oauth2_client_id</code> filter. This will prevent it from being stored in plaintext in the WordPress database.", 'authorizer' ) . '</li>
				<li>' . __( '<strong>Client Secret</strong>: You can generate this secret by following the instructions for your specific provider.', 'authorizer' ) . '<br>' . __( "Note: for increased security, you can leave this field blank and instead define this value either in wp-config.php via <code>define( 'AUTHORIZER_OAUTH2_CLIENT_SECRET', '...' );</code>, or you may fetch it from an external service like AWS Secrets Manager by hooking into the <code>authorizer_oauth2_client_secret</code> filter. This will prevent it from being stored in plaintext in the WordPress database.", 'authorizer' ) . '</li>
				<li>' . __( '<strong>Authorization URL</strong>: For the generic OAuth2 provider, you will need to specify the 3 endpoints required for the oauth2 authentication flow. This is the first: the endpoint first contacted to initiate the authentication.', 'authorizer' ) . '</li>
				<li>' . __( '<strong>Access Token URL</strong>: For the generic OAuth2 provider, you will need to specify the 3 endpoints required for the oauth2 authentication flow. This is the second: the endpoint that is contacted after initiation to retrieve an access token for the user that just authenticated.', 'authorizer' ) . '</li>
				<li>' . __( '<strong>Resource Owner URL</strong>: For the generic OAuth2 provider, you will need to specify the 3 endpoints required for the oauth2 authentication flow. This is the third: the endpoint that is contacted after successfully receiving an authentication token to retrieve details on the user that just authenticated.', 'authorizer' ) . '</li>
			</ul>
			<p><strong><em>' . __( 'If you enable Google logins:', 'authorizer' ) . '</em></strong></p>
			<ul>
				<li>' . __( "<strong>Google Client ID</strong>: You can generate this ID by creating a new Project in the <a href='https://cloud.google.com/console'>Google Developers Console</a>. A Client ID typically looks something like this: 1234567890123-kdjr85yt6vjr6d8g7dhr8g7d6durjf7g.apps.googleusercontent.com", 'authorizer' ) . '<br>' . __( "Note: for increased security, you can leave this field blank and instead define this value either in wp-config.php via <code>define( 'AUTHORIZER_GOOGLE_CLIENT_ID', '...' );</code>, or you may fetch it from an external service like AWS Secrets Manager by hooking into the <code>authorizer_google_client_id</code> filter. This will prevent it from being stored in plaintext in the WordPress database.", 'authorizer' ) . '</li>
				<li>' . __( "<strong>Google Client Secret</strong>: You can generate this secret by creating a new Project in the <a href='https://cloud.google.com/console'>Google Developers Console</a>. A Client Secret typically looks something like this: sDNgX5_pr_5bly-frKmvp8jT", 'authorizer' ) . '<br>' . __( "Note: for increased security, you can leave this field blank and instead define this value either in wp-config.php via <code>define( 'AUTHORIZER_GOOGLE_CLIENT_SECRET', '...' );</code>, or you may fetch it from an external service like AWS Secrets Manager by hooking into the <code>authorizer_google_client_secret</code> filter. This will prevent it from being stored in plaintext in the WordPress database.", 'authorizer' ) . '</li>
			</ul>
			<p><strong><em>' . __( 'If you enable CAS logins:', 'authorizer' ) . '</em></strong></p>
			<ul>
				<li>' . __( '<strong>CAS server hostname</strong>: Enter the hostname of the CAS server you authenticate against (e.g., authn.example.edu).', 'authorizer' ) . '</li>
				<li>' . __( '<strong>CAS server port</strong>: Enter the port on the CAS server to connect to (e.g., 443).', 'authorizer' ) . '</li>
				<li>' . __( '<strong>CAS server path/context</strong>: Enter the path to the login endpoint on the CAS server (e.g., /cas).', 'authorizer' ) . '</li>
				<li>' . __( '<strong>CAS server method</strong>: Select the method to use when setting the CAS config (e.g.,"client" or "proxy")', 'authorizer' ) . '</li>
				<li>' . __( "<strong>CAS attribute containing first name</strong>: Enter the CAS attribute that has the user's first name. When this user first logs in, their WordPress account will have their first name retrieved from CAS and added to their WordPress profile.", 'authorizer' ) . '</li>
				<li>' . __( "<strong>CAS attribute containing last name</strong>: Enter the CAS attribute that has the user's last name. When this user first logs in, their WordPress account will have their last name retrieved from CAS and added to their WordPress profile.", 'authorizer' ) . '</li>
				<li>' . __( '<strong>CAS attribute update</strong>: Select whether the first and last names retrieved from CAS should overwrite any value the user has entered in the first and last name fields in their WordPress profile. If this is not set, this only happens the first time they log in.', 'authorizer' ) . '</li>
			</ul>
			<p><strong><em>' . __( 'If you enable LDAP logins:', 'authorizer' ) . '</em></strong></p>
			<ul>
				<li>' . __( '<strong>LDAP Host</strong>: Enter the URL of the LDAP server you authenticate against.', 'authorizer' ) . '</li>
				<li>' . __( '<strong>LDAP Port</strong>: Enter the port number that the LDAP server listens on.', 'authorizer' ) . '</li>
				<li>' . __( '<strong>LDAP Search Base</strong>: Enter the LDAP string that represents the search base, e.g., ou=people,dc=example,dc=edu', 'authorizer' ) . '</li>
				<li>' . __( '<strong>LDAP Search Filter</strong>: Enter the optional LDAP string that represents the search filter, e.g., (memberOf=cn=wp_users,ou=people,dc=example,dc=edu)', 'authorizer' ) . '</li>
				<li>' . __( '<strong>LDAP attribute containing username</strong>: Enter the name of the LDAP attribute that contains the usernames used by those attempting to log in. The plugin will search on this attribute to find the cn to bind against for login attempts.', 'authorizer' ) . '</li>
				<li>' . __( '<strong>LDAP Directory User</strong>: Enter the name of the LDAP user that has permissions to browse the directory.', 'authorizer' ) . '<br>' . __( "Note: for increased security, you can leave this field blank and instead define this value either in wp-config.php via <code>define( 'AUTHORIZER_LDAP_USER', '...' );</code>, or you may fetch it from an external service like AWS Secrets Manager by hooking into the <code>authorizer_ldap_user</code> filter. This will prevent it from being stored in plaintext in the WordPress database.", 'authorizer' ) . '</li>
				<li>' . __( '<strong>LDAP Directory User Password</strong>: Enter the password for the LDAP user that has permission to browse the directory.', 'authorizer' ) . '<br>' . __( "Note: for increased security, you can leave this field blank and instead define this value either in wp-config.php via <code>define( 'AUTHORIZER_LDAP_PASSWORD', '...' );</code>, or you may fetch it from an external service like AWS Secrets Manager by hooking into the <code>authorizer_ldap_password</code> filter. This will prevent it from being stored in the WordPress database.", 'authorizer' ) . '</li>
				<li>' . __( '<strong>Use STARTTLS</strong>: Select whether unencrypted communication with the LDAP server should be upgraded to a TLS-secured connection using STARTTLS.', 'authorizer' ) . '</li>
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
				'content' => wp_kses_post( $help_auth_settings_external_content ),
			)
		);

		// Add help tab for Advanced Settings.
		$help_auth_settings_advanced_content = '
			<p>' . __( '<strong>Limit invalid login attempts</strong>: Choose how soon (and for how long) to restrict access to individuals (or bots) making repeated invalid login attempts. You may set a shorter delay first, and then a longer delay after repeated invalid attempts; you may also set how much time must pass before the delays will be reset to normal.', 'authorizer' ) . '</p>
			<p>' . __( '<strong>Hide WordPress Logins</strong>: If you want to hide the WordPress username and password fields and the Log In button on the wp-login screen, enable this option. Note: You can always access the WordPress logins by adding external=wordpress to the wp-login URL, like so:', 'authorizer' ) . ' <a href="' . wp_login_url() . '?external=wordpress" target="_blank">' . wp_login_url() . '?external=wordpress</a>.</p>
			<p>' . __( '<strong>Disable WordPress Logins</strong>: If you want to prevent users from logging in with their WordPress passwords and instead only allow logins from external services, enable this option. Note: enabling this will also hide WordPress logins unless the LDAP external service is enabled.', 'authorizer' ) . '</p>
			<p>' . __( "<strong>Custom WordPress login branding</strong>: If you'd like to use custom branding on the WordPress login page, select that here. You will need to use the `authorizer_add_branding_option` filter in your theme to add it. You can see an example theme that implements this filter in the plugin directory under sample-theme-add-branding.", 'authorizer' ) . '</p>
		';
		$screen->add_help_tab(
			array(
				'id'      => 'help_auth_settings_advanced_content',
				'title'   => __( 'Advanced', 'authorizer' ),
				'content' => wp_kses_post( $help_auth_settings_advanced_content ),
			)
		);
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
		$options       = Options::get_instance();
		$auth_settings = $options->get_all( Helper::SINGLE_CONTEXT, 'allow override' );

		if ( '1' === $auth_settings['cas'] ) :
			// Check if provided CAS URL is accessible.
			$protocol       = in_array( strval( $auth_settings['cas_port'] ), array( '80', '8080' ), true ) ? 'http' : 'https';
			$cas_url        = $protocol . '://' . $auth_settings['cas_host'] . ':' . $auth_settings['cas_port'] . $auth_settings['cas_path'];
			$legacy_cas_url = trailingslashit( $cas_url ) . 'login'; // Check the specific CAS login endpoint (old; some servers don't register a ./login endpoint, use serviceValidate instead).
			$cas_url        = trailingslashit( $cas_url ) . 'serviceValidate'; // Check the specific CAS login endpoint.
			if ( ! Helper::url_is_accessible( $cas_url ) && ! Helper::url_is_accessible( $legacy_cas_url ) ) :
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
				<p><?php echo wp_kses( $notice, Helper::$allowed_html ); ?></p>
			</div>
			<?php
		}
	}


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
		$options      = Options::get_instance();
		$admin_menu   = $options->get( 'advanced_admin_menu' );
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
			array( Options::get_instance(), 'sanitize_options' )
		);

		add_settings_section(
			'auth_settings_tabs',
			'',
			array( Options::get_instance(), 'print_section_info_tabs' ),
			'authorizer'
		);

		// Create Access Lists section.
		add_settings_section(
			'auth_settings_lists',
			'',
			array( Access_Lists::get_instance(), 'print_section_info_access_lists' ),
			'authorizer'
		);

		// Create Login Access section.
		add_settings_section(
			'auth_settings_access_login',
			'',
			array( Login_Access::get_instance(), 'print_section_info_access_login' ),
			'authorizer'
		);
		add_settings_field(
			'auth_settings_access_who_can_login',
			__( 'Who can log into the site?', 'authorizer' ),
			array( Login_Access::get_instance(), 'print_radio_auth_access_who_can_login' ),
			'authorizer',
			'auth_settings_access_login'
		);
		add_settings_field(
			'auth_settings_access_role_receive_pending_emails',
			__( 'Which role should receive email notifications about pending users?', 'authorizer' ),
			array( Login_Access::get_instance(), 'print_select_auth_access_role_receive_pending_emails' ),
			'authorizer',
			'auth_settings_access_login'
		);
		add_settings_field(
			'auth_settings_access_pending_redirect_to_message',
			__( 'What message should pending users see after attempting to log in?', 'authorizer' ),
			array( Login_Access::get_instance(), 'print_wysiwyg_auth_access_pending_redirect_to_message' ),
			'authorizer',
			'auth_settings_access_login'
		);
		add_settings_field(
			'auth_settings_access_blocked_redirect_to_message',
			__( 'What message should blocked users see after attempting to log in?', 'authorizer' ),
			array( Login_Access::get_instance(), 'print_wysiwyg_auth_access_blocked_redirect_to_message' ),
			'authorizer',
			'auth_settings_access_login'
		);
		add_settings_field(
			'auth_settings_access_should_email_approved_users',
			__( 'Send welcome email to new approved users?', 'authorizer' ),
			array( Login_Access::get_instance(), 'print_checkbox_auth_access_should_email_approved_users' ),
			'authorizer',
			'auth_settings_access_login'
		);
		add_settings_field(
			'auth_settings_access_email_approved_users_subject',
			__( 'Welcome email subject', 'authorizer' ),
			array( Login_Access::get_instance(), 'print_text_auth_access_email_approved_users_subject' ),
			'authorizer',
			'auth_settings_access_login'
		);
		add_settings_field(
			'auth_settings_access_email_approved_users_body',
			__( 'Welcome email body', 'authorizer' ),
			array( Login_Access::get_instance(), 'print_wysiwyg_auth_access_email_approved_users_body' ),
			'authorizer',
			'auth_settings_access_login'
		);

		// Create Public Access section.
		add_settings_section(
			'auth_settings_access_public',
			'',
			array( Public_Access::get_instance(), 'print_section_info_access_public' ),
			'authorizer'
		);
		add_settings_field(
			'auth_settings_access_who_can_view',
			__( 'Who can view the site?', 'authorizer' ),
			array( Public_Access::get_instance(), 'print_radio_auth_access_who_can_view' ),
			'authorizer',
			'auth_settings_access_public'
		);
		add_settings_field(
			'auth_settings_access_public_pages',
			__( 'What pages (if any) should be available to everyone?', 'authorizer' ),
			array( Public_Access::get_instance(), 'print_multiselect_auth_access_public_pages' ),
			'authorizer',
			'auth_settings_access_public'
		);
		add_settings_field(
			'auth_settings_access_redirect',
			__( 'What happens to people without access when they visit a private page?', 'authorizer' ),
			array( Public_Access::get_instance(), 'print_radio_auth_access_redirect' ),
			'authorizer',
			'auth_settings_access_public'
		);
		add_settings_field(
			'auth_settings_access_public_warning',
			__( 'What happens to people without access when they visit a public page?', 'authorizer' ),
			array( Public_Access::get_instance(), 'print_radio_auth_access_public_warning' ),
			'authorizer',
			'auth_settings_access_public'
		);
		add_settings_field(
			'auth_settings_access_redirect_to_message',
			__( 'What message should people without access see?', 'authorizer' ),
			array( Public_Access::get_instance(), 'print_wysiwyg_auth_access_redirect_to_message' ),
			'authorizer',
			'auth_settings_access_public'
		);

		// Create External Service Settings section.
		add_settings_section(
			'auth_settings_external',
			'',
			array( External::get_instance(), 'print_section_info_external' ),
			'authorizer'
		);
		add_settings_field(
			'auth_settings_access_default_role',
			__( 'Default role for new users', 'authorizer' ),
			array( External::get_instance(), 'print_select_auth_access_default_role' ),
			'authorizer',
			'auth_settings_external'
		);

		add_settings_field(
			'auth_settings_external_oauth2',
			__( 'OAuth2 Logins', 'authorizer' ),
			array( OAuth2::get_instance(), 'print_checkbox_auth_external_oauth2' ),
			'authorizer',
			'auth_settings_external',
			array(
				'class' => 'border-top',
			)
		);
		add_settings_field(
			'auth_settings_oauth2_provider',
			__( 'Provider', 'authorizer' ),
			array( OAuth2::get_instance(), 'print_select_oauth2_provider' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_oauth2_custom_label',
			__( 'Custom label', 'authorizer' ),
			array( OAuth2::get_instance(), 'print_text_oauth2_custom_label' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_oauth2_clientid',
			__( 'Client ID', 'authorizer' ),
			array( OAuth2::get_instance(), 'print_text_oauth2_clientid' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_oauth2_clientsecret',
			__( 'Client Secret', 'authorizer' ),
			array( OAuth2::get_instance(), 'print_text_oauth2_clientsecret' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_oauth2_hosteddomain',
			__( 'OAuth2 Hosted Domain', 'authorizer' ),
			array( OAuth2::get_instance(), 'print_text_oauth2_hosteddomain' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_oauth2_tenant_id',
			__( 'Tenant ID', 'authorizer' ),
			array( OAuth2::get_instance(), 'print_text_oauth2_tenant_id' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_oauth2_url_authorize',
			__( 'Authorization URL', 'authorizer' ),
			array( OAuth2::get_instance(), 'print_text_oauth2_url_authorize' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_oauth2_url_token',
			__( 'Access Token URL', 'authorizer' ),
			array( OAuth2::get_instance(), 'print_text_oauth2_url_token' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_oauth2_url_resource',
			__( 'Resource Owner URL', 'authorizer' ),
			array( OAuth2::get_instance(), 'print_text_oauth2_url_resource' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_oauth2_auto_login',
			__( 'OAuth2 automatic login', 'authorizer' ),
			array( OAuth2::get_instance(), 'print_checkbox_oauth2_auto_login' ),
			'authorizer',
			'auth_settings_external'
		);

		add_settings_field(
			'auth_settings_external_google',
			__( 'Google Logins', 'authorizer' ),
			array( Google::get_instance(), 'print_checkbox_auth_external_google' ),
			'authorizer',
			'auth_settings_external',
			array(
				'class' => 'border-top',
			)
		);
		add_settings_field(
			'auth_settings_google_clientid',
			__( 'Google Client ID', 'authorizer' ),
			array( Google::get_instance(), 'print_text_google_clientid' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_google_clientsecret',
			__( 'Google Client Secret', 'authorizer' ),
			array( Google::get_instance(), 'print_text_google_clientsecret' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_google_hosteddomain',
			__( 'Google Hosted Domain', 'authorizer' ),
			array( Google::get_instance(), 'print_text_google_hosteddomain' ),
			'authorizer',
			'auth_settings_external'
		);

		add_settings_field(
			'auth_settings_external_cas',
			__( 'CAS Logins', 'authorizer' ),
			array( Cas::get_instance(), 'print_checkbox_auth_external_cas' ),
			'authorizer',
			'auth_settings_external',
			array(
				'class' => 'border-top',
			)
		);
		add_settings_field(
			'auth_settings_cas_custom_label',
			__( 'CAS custom label', 'authorizer' ),
			array( Cas::get_instance(), 'print_text_cas_custom_label' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_cas_host',
			__( 'CAS server hostname', 'authorizer' ),
			array( Cas::get_instance(), 'print_text_cas_host' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_cas_port',
			__( 'CAS server port', 'authorizer' ),
			array( Cas::get_instance(), 'print_text_cas_port' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_cas_path',
			__( 'CAS server path/context', 'authorizer' ),
			array( Cas::get_instance(), 'print_text_cas_path' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_cas_method',
			__( 'CAS server method', 'authorizer' ),
			array( Cas::get_instance(), 'print_select_cas_method' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_cas_version',
			__( 'CAS server protocol', 'authorizer' ),
			array( Cas::get_instance(), 'print_select_cas_version' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_cas_attr_email',
			__( 'CAS attribute containing email address', 'authorizer' ),
			array( Cas::get_instance(), 'print_text_cas_attr_email' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_cas_attr_first_name',
			__( 'CAS attribute containing first name', 'authorizer' ),
			array( Cas::get_instance(), 'print_text_cas_attr_first_name' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_cas_attr_last_name',
			__( 'CAS attribute containing last name', 'authorizer' ),
			array( Cas::get_instance(), 'print_text_cas_attr_last_name' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_cas_attr_update_on_login',
			__( 'CAS attribute update', 'authorizer' ),
			array( Cas::get_instance(), 'print_select_cas_attr_update_on_login' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_cas_auto_login',
			__( 'CAS automatic login', 'authorizer' ),
			array( Cas::get_instance(), 'print_checkbox_cas_auto_login' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_cas_link_on_username',
			__( 'CAS users linked by username', 'authorizer' ),
			array( Cas::get_instance(), 'print_checkbox_cas_link_on_username' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_external_ldap',
			__( 'LDAP Logins', 'authorizer' ),
			array( Ldap::get_instance(), 'print_checkbox_auth_external_ldap' ),
			'authorizer',
			'auth_settings_external',
			array(
				'class' => 'border-top',
			)
		);
		add_settings_field(
			'auth_settings_ldap_host',
			__( 'LDAP Host', 'authorizer' ),
			array( Ldap::get_instance(), 'print_text_ldap_host' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_ldap_port',
			__( 'LDAP Port', 'authorizer' ),
			array( Ldap::get_instance(), 'print_text_ldap_port' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_ldap_tls',
			__( 'Use STARTTLS', 'authorizer' ),
			array( Ldap::get_instance(), 'print_checkbox_ldap_tls' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_ldap_search_base',
			__( 'LDAP Search Base', 'authorizer' ),
			array( Ldap::get_instance(), 'print_text_ldap_search_base' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_ldap_search_filter',
			__( 'LDAP Search Filter', 'authorizer' ),
			array( Ldap::get_instance(), 'print_text_ldap_search_filter' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_ldap_uid',
			__( 'LDAP attribute containing username', 'authorizer' ),
			array( Ldap::get_instance(), 'print_text_ldap_uid' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_ldap_attr_email',
			__( 'LDAP attribute containing email address', 'authorizer' ),
			array( Ldap::get_instance(), 'print_text_ldap_attr_email' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_ldap_user',
			__( 'LDAP Directory User', 'authorizer' ),
			array( Ldap::get_instance(), 'print_text_ldap_user' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_ldap_password',
			__( 'LDAP Directory User Password', 'authorizer' ),
			array( Ldap::get_instance(), 'print_password_ldap_password' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_ldap_lostpassword_url',
			__( 'Custom lost password URL', 'authorizer' ),
			array( Ldap::get_instance(), 'print_text_ldap_lostpassword_url' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_ldap_attr_first_name',
			__( 'LDAP attribute containing first name', 'authorizer' ),
			array( Ldap::get_instance(), 'print_text_ldap_attr_first_name' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_ldap_attr_last_name',
			__( 'LDAP attribute containing last name', 'authorizer' ),
			array( Ldap::get_instance(), 'print_text_ldap_attr_last_name' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_ldap_attr_update_on_login',
			__( 'LDAP attribute update', 'authorizer' ),
			array( Ldap::get_instance(), 'print_select_ldap_attr_update_on_login' ),
			'authorizer',
			'auth_settings_external'
		);
		add_settings_field(
			'auth_settings_ldap_test_user',
			__( 'LDAP test connection', 'authorizer' ),
			array( Ldap::get_instance(), 'print_text_button_ldap_test_user' ),
			'authorizer',
			'auth_settings_external'
		);

		// Create Advanced Settings section.
		add_settings_section(
			'auth_settings_advanced',
			'',
			array( Advanced::get_instance(), 'print_section_info_advanced' ),
			'authorizer'
		);
		add_settings_field(
			'auth_settings_advanced_lockouts',
			__( 'Limit invalid login attempts', 'authorizer' ),
			array( Advanced::get_instance(), 'print_text_auth_advanced_lockouts' ),
			'authorizer',
			'auth_settings_advanced'
		);
		add_settings_field(
			'auth_settings_advanced_hide_wp_login',
			__( 'Hide WordPress Login', 'authorizer' ),
			array( Advanced::get_instance(), 'print_checkbox_auth_advanced_hide_wp_login' ),
			'authorizer',
			'auth_settings_advanced'
		);
		add_settings_field(
			'auth_settings_advanced_disable_wp_login',
			__( 'Disable WordPress Logins', 'authorizer' ),
			array( Advanced::get_instance(), 'print_checkbox_auth_advanced_disable_wp_login' ),
			'authorizer',
			'auth_settings_advanced'
		);
		add_settings_field(
			'auth_settings_advanced_branding',
			__( 'Custom WordPress login branding', 'authorizer' ),
			array( Advanced::get_instance(), 'print_radio_auth_advanced_branding' ),
			'authorizer',
			'auth_settings_advanced'
		);
		add_settings_field(
			'auth_settings_advanced_admin_menu',
			__( 'Authorizer admin menu item location', 'authorizer' ),
			array( Advanced::get_instance(), 'print_radio_auth_advanced_admin_menu' ),
			'authorizer',
			'auth_settings_advanced'
		);
		add_settings_field(
			'auth_settings_advanced_usermeta',
			__( 'Show custom usermeta in user list', 'authorizer' ),
			array( Advanced::get_instance(), 'print_select_auth_advanced_usermeta' ),
			'authorizer',
			'auth_settings_advanced'
		);
		add_settings_field(
			'auth_settings_advanced_users_per_page',
			__( 'Number of users per page', 'authorizer' ),
			array( Advanced::get_instance(), 'print_text_auth_advanced_users_per_page' ),
			'authorizer',
			'auth_settings_advanced'
		);
		add_settings_field(
			'auth_settings_advanced_users_sort_by',
			__( 'Approved users sort method', 'authorizer' ),
			array( Advanced::get_instance(), 'print_select_auth_advanced_users_sort_by' ),
			'authorizer',
			'auth_settings_advanced'
		);
		add_settings_field(
			'auth_settings_advanced_users_sort_order',
			__( 'Approved users sort order', 'authorizer' ),
			array( Advanced::get_instance(), 'print_select_auth_advanced_users_sort_order' ),
			'authorizer',
			'auth_settings_advanced'
		);
		add_settings_field(
			'auth_settings_advanced_widget_enabled',
			__( 'Show dashboard widget to admin users', 'authorizer' ),
			array( Advanced::get_instance(), 'print_checkbox_auth_advanced_widget_enabled' ),
			'authorizer',
			'auth_settings_advanced'
		);
		// On multisite installs, add an option to override all multisite settings on individual sites.
		if ( is_multisite() ) {
			add_settings_field(
				'auth_settings_advanced_override_multisite',
				__( 'Override multisite options', 'authorizer' ),
				array( Advanced::get_instance(), 'print_checkbox_auth_advanced_override_multisite' ),
				'authorizer',
				'auth_settings_advanced'
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
	 * Output the HTML for the options page.
	 */
	public function create_network_admin_page() {
		if ( ! current_user_can( 'manage_network_options' ) ) {
			wp_die( wp_kses( __( 'You do not have sufficient permissions to access this page.', 'authorizer' ), Helper::$allowed_html ) );
		}
		$options       = Options::get_instance();
		$access_lists  = Access_Lists::get_instance();
		$login_access  = Login_Access::get_instance();
		$public_access = Public_Access::get_instance();
		$external      = External::get_instance();
		$google        = Google::get_instance();
		$cas           = Cas::get_instance();
		$ldap          = Ldap::get_instance();
		$oauth2        = OAuth2::get_instance();
		$advanced      = Advanced::get_instance();
		$auth_settings = get_blog_option( get_main_site_id( get_main_network_id() ), 'auth_multisite_settings', array() );
		?>
		<div class="wrap">
			<form method="post" action="" autocomplete="off">
				<h2><?php esc_html_e( 'Authorizer Settings', 'authorizer' ); ?></h2>
				<p><?php echo wp_kses( __( 'Most <strong>Authorizer</strong> settings are set in the individual sites, but you can specify a few options here that apply to <strong>all sites in the network</strong>. These settings will override settings in the individual sites.', 'authorizer' ), Helper::$allowed_html ); ?></p>

				<p><input type="checkbox" id="auth_settings_multisite_override" name="auth_settings[multisite_override]" value="1"<?php checked( 1 === intval( $auth_settings['multisite_override'] ) ); ?> /><label for="auth_settings_multisite_override"><?php esc_html_e( 'Override individual site settings with the settings below', 'authorizer' ); ?></label></p>
				<p><input type="checkbox" id="auth_settings_prevent_override_multisite" name="auth_settings[prevent_override_multisite]" value="1"<?php checked( 1 === intval( $auth_settings['prevent_override_multisite'] ) ); ?> /><label for="auth_settings_prevent_override_multisite"><?php esc_html_e( 'Prevent site administrators from overriding any multisite settings defined here (via Authorizer > Advanced > Override multisite options)', 'authorizer' ); ?></label></p>

				<div id="auth_multisite_settings_disabled_overlay" style="display: none;"></div>

				<div class="wrap" id="auth_multisite_settings">
					<?php $options->print_section_info_tabs( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?>

					<?php wp_nonce_field( 'save_auth_settings', 'nonce_save_auth_settings' ); ?>

					<?php // Custom access lists (for network, we only really want approved list, not pending or blocked). ?>
					<div id="section_info_access_lists" class="section_info">
						<p><?php esc_html_e( 'Manage who has access to all sites in the network.', 'authorizer' ); ?></p>
					</div>
					<table class="form-table"><tbody>
						<tr>
							<th scope="row"><?php esc_html_e( 'Who can log in to sites in this network?', 'authorizer' ); ?></th>
							<td><?php $login_access->print_radio_auth_access_who_can_login( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Who can view sites in this network?', 'authorizer' ); ?></th>
							<td><?php $public_access->print_radio_auth_access_who_can_view( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Approved Users (All Sites)', 'authorizer' ); ?><br /><small><em><?php echo wp_kses( __( 'Note: these users will <strong>not</strong> receive welcome emails when approved. Only users approved from individual sites can receive these messages.', 'authorizer' ), Helper::$allowed_html ); ?></em></small></th>
							<td><?php $access_lists->print_combo_auth_access_users_approved( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
					</tbody></table>

					<?php $external->print_section_info_external(); ?>
					<table class="form-table"><tbody>
						<tr>
							<th scope="row"><?php esc_html_e( 'Default role for new users', 'authorizer' ); ?></th>
							<td><?php $external->print_select_auth_access_default_role( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr class="border-top">
							<th scope="row"><?php esc_html_e( 'OAuth2 Logins', 'authorizer' ); ?></th>
							<td><?php $oauth2->print_checkbox_auth_external_oauth2( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'OAuth2 Provider', 'authorizer' ); ?></th>
							<td><?php $oauth2->print_select_oauth2_provider( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Custom Label', 'authorizer' ); ?></th>
							<td><?php $oauth2->print_text_oauth2_custom_label( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Client ID', 'authorizer' ); ?></th>
							<td><?php $oauth2->print_text_oauth2_clientid( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Client Secret', 'authorizer' ); ?></th>
							<td><?php $oauth2->print_text_oauth2_clientsecret( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'OAuth2 Hosted Domain', 'authorizer' ); ?></th>
							<td><?php $oauth2->print_text_oauth2_hosteddomain( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Tenant ID', 'authorizer' ); ?></th>
							<td><?php $oauth2->print_text_oauth2_tenant_id( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Authorization URL', 'authorizer' ); ?></th>
							<td><?php $oauth2->print_text_oauth2_url_authorize( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Access Token URL', 'authorizer' ); ?></th>
							<td><?php $oauth2->print_text_oauth2_url_token( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Resource Owner URL', 'authorizer' ); ?></th>
							<td><?php $oauth2->print_text_oauth2_url_resource( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'OAuth2 automatic login', 'authorizer' ); ?></th>
							<td><?php $oauth2->print_checkbox_oauth2_auto_login( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr class="border-top">
							<th scope="row"><?php esc_html_e( 'Google Logins', 'authorizer' ); ?></th>
							<td><?php $google->print_checkbox_auth_external_google( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Google Client ID', 'authorizer' ); ?></th>
							<td><?php $google->print_text_google_clientid( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Google Client Secret', 'authorizer' ); ?></th>
							<td><?php $google->print_text_google_clientsecret( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Google Hosted Domain', 'authorizer' ); ?></th>
							<td><?php $google->print_text_google_hosteddomain( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr class="border-top">
							<th scope="row"><?php esc_html_e( 'CAS Logins', 'authorizer' ); ?></th>
							<td><?php $cas->print_checkbox_auth_external_cas( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'CAS Custom Label', 'authorizer' ); ?></th>
							<td><?php $cas->print_text_cas_custom_label( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'CAS server hostname', 'authorizer' ); ?></th>
							<td><?php $cas->print_text_cas_host( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'CAS server port', 'authorizer' ); ?></th>
							<td><?php $cas->print_text_cas_port( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'CAS server path/context', 'authorizer' ); ?></th>
							<td><?php $cas->print_text_cas_path( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'CAS server method', 'authorizer' ); ?></th>
							<td><?php $cas->print_select_cas_method( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'CAS server protocol', 'authorizer' ); ?></th>
							<td><?php $cas->print_select_cas_version( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'CAS attribute containing email', 'authorizer' ); ?></th>
							<td><?php $cas->print_text_cas_attr_email( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'CAS attribute containing first name', 'authorizer' ); ?></th>
							<td><?php $cas->print_text_cas_attr_first_name( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'CAS attribute containing last name', 'authorizer' ); ?></th>
							<td><?php $cas->print_text_cas_attr_last_name( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'CAS attribute update', 'authorizer' ); ?></th>
							<td><?php $cas->print_select_cas_attr_update_on_login( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'CAS automatic login', 'authorizer' ); ?></th>
							<td><?php $cas->print_checkbox_cas_auto_login( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'CAS users linked by username', 'authorizer' ); ?></th>
							<td><?php $cas->print_checkbox_cas_link_on_username( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr class="border-top">
							<th scope="row"><?php esc_html_e( 'LDAP Logins', 'authorizer' ); ?></th>
							<td><?php $ldap->print_checkbox_auth_external_ldap( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'LDAP Host', 'authorizer' ); ?></th>
							<td><?php $ldap->print_text_ldap_host( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'LDAP Port', 'authorizer' ); ?></th>
							<td><?php $ldap->print_text_ldap_port( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Use STARTTLS', 'authorizer' ); ?></th>
							<td><?php $ldap->print_checkbox_ldap_tls( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'LDAP Search Base', 'authorizer' ); ?></th>
							<td><?php $ldap->print_text_ldap_search_base( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'LDAP Search Filter', 'authorizer' ); ?></th>
							<td><?php $ldap->print_text_ldap_search_filter( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'LDAP attribute containing username', 'authorizer' ); ?></th>
							<td><?php $ldap->print_text_ldap_uid( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'LDAP attribute containing email', 'authorizer' ); ?></th>
							<td><?php $ldap->print_text_ldap_attr_email( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'LDAP Directory User', 'authorizer' ); ?></th>
							<td><?php $ldap->print_text_ldap_user( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'LDAP Directory User Password', 'authorizer' ); ?></th>
							<td><?php $ldap->print_password_ldap_password( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Custom lost password URL', 'authorizer' ); ?></th>
							<td><?php $ldap->print_text_ldap_lostpassword_url( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'LDAP attribute containing first name', 'authorizer' ); ?></th>
							<td><?php $ldap->print_text_ldap_attr_first_name( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'LDAP attribute containing last name', 'authorizer' ); ?></th>
							<td><?php $ldap->print_text_ldap_attr_last_name( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'LDAP attribute update', 'authorizer' ); ?></th>
							<td><?php $ldap->print_select_ldap_attr_update_on_login( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'LDAP test connection', 'authorizer' ); ?></th>
							<td><?php $ldap->print_text_button_ldap_test_user( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
					</tbody></table>

					<?php $advanced->print_section_info_advanced(); ?>
					<table class="form-table"><tbody>
						<tr>
							<th scope="row"><?php esc_html_e( 'Limit invalid login attempts', 'authorizer' ); ?></th>
							<td><?php $advanced->print_text_auth_advanced_lockouts( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Hide WordPress Logins', 'authorizer' ); ?></th>
							<td><?php $advanced->print_checkbox_auth_advanced_hide_wp_login( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Disable WordPress Logins', 'authorizer' ); ?></th>
							<td><?php $advanced->print_checkbox_auth_advanced_disable_wp_login( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Number of users per page', 'authorizer' ); ?></th>
							<td><?php $advanced->print_text_auth_advanced_users_per_page( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Approved users sort method', 'authorizer' ); ?></th>
							<td><?php $advanced->print_select_auth_advanced_users_sort_by( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Approved users sort order', 'authorizer' ); ?></th>
							<td><?php $advanced->print_select_auth_advanced_users_sort_order( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Show Dashboard Widget', 'authorizer' ); ?></th>
							<td><?php $advanced->print_checkbox_auth_advanced_widget_enabled( array( 'context' => Helper::NETWORK_CONTEXT ) ); ?></td>
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
			array( self::get_instance(), 'create_network_admin_page' ),
			'dashicons-groups',
			89 // Position.
		);
	}


	/**
	 * Create the options page under Dashboard > Settings.
	 *
	 * Action: admin_menu
	 */
	public function add_plugin_page() {
		$options    = Options::get_instance();
		$admin_menu = $options->get( 'advanced_admin_menu' );
		if ( 'settings' === $admin_menu ) {
			// @see http://codex.wordpress.org/Function_Reference/add_options_page
			add_options_page(
				'Authorizer',
				'Authorizer',
				'create_users',
				'authorizer',
				array( self::get_instance(), 'create_admin_page' )
			);
		} else {
			// @see http://codex.wordpress.org/Function_Reference/add_menu_page
			add_menu_page(
				'Authorizer',
				'Authorizer',
				'create_users',
				'authorizer',
				array( self::get_instance(), 'create_admin_page' ),
				'dashicons-groups',
				'99.0018465' // position (decimal is to make overlap with other plugins less likely).
			);
		}
	}


	/**
	 * Load external resources on this plugin's options page.
	 *
	 * Action: load-settings_page_authorizer
	 * Action: load-toplevel_page_authorizer
	 * Action: admin_head-index.php
	 */
	public function load_options_page() {
		wp_enqueue_script( 'authorizer', plugins_url( 'js/authorizer.js', plugin_root() ), array( 'jquery-effects-shake' ), '3.8.4', true );
		wp_localize_script(
			'authorizer',
			'authL10n',
			array(
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

		wp_enqueue_script( 'jquery-autogrow-textarea', plugins_url( 'vendor-custom/jquery.autogrow-textarea/jquery.autogrow-textarea.js', plugin_root() ), array( 'jquery' ), '3.0.7', true );

		wp_enqueue_script( 'jquery.multi-select', plugins_url( 'vendor-custom/jquery.multi-select/0.9.12/js/jquery.multi-select.js', plugin_root() ), array( 'jquery' ), '0.9.12', true );

		wp_register_style( 'authorizer-css', plugins_url( 'css/authorizer.css', plugin_root() ), array(), '3.8.4' );
		wp_enqueue_style( 'authorizer-css' );

		wp_register_style( 'jquery-multi-select-css', plugins_url( 'vendor-custom/jquery.multi-select/0.9.12/css/multi-select.css', plugin_root() ), array(), '0.9.12' );
		wp_enqueue_style( 'jquery-multi-select-css' );

		add_action( 'admin_notices', array( self::get_instance(), 'admin_notices' ) ); // Add any notices to the top of the options page.
		add_action( 'admin_head', array( self::get_instance(), 'admin_head' ) ); // Add help documentation to the options page.
	}
}
