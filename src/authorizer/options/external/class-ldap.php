<?php
/**
 * Authorizer
 *
 * @license  GPL-2.0+
 * @link     https://github.com/uhm-coe/authorizer
 * @package  authorizer
 */

namespace Authorizer\Options\External;

use Authorizer\Helper;
use Authorizer\Options;

/**
 * Contains functions for rendering the LDAP options in the External Service
 * tab in Authorizer Settings.
 */
class Ldap {

	/**
	 * Plugin instance.
	 *
	 * @var object Plugin instance.
	 */
	protected static $instance = null;


	/**
	 * Access this plugin's working instance.
	 *
	 * @return object Object of this class.
	 */
	public static function get_instance() {
		return null === self::$instance ? new self() : self::$instance;
	}


	/**
	 * Constructor intentionally left empty and public.
	 */
	public function __construct() {
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_checkbox_auth_external_ldap( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'ldap';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Make sure php5-ldap extension is installed on server.
		$ldap_installed_message = ! function_exists( 'ldap_connect' ) ? '<span style="color: red;">(' . __( 'Warning: <a href="http://www.php.net/manual/en/ldap.installation.php" target="_blank" style="color: red;">PHP LDAP extension</a> is <strong>not</strong> installed', 'authorizer' ) . ')</span>' : '';

		// Print option elements.
		?>
		<input type="checkbox" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="1"<?php checked( 1 === intval( $auth_settings_option ) ); ?> /><label for="auth_settings_<?php echo esc_attr( $option ); ?>"><?php esc_html_e( 'Enable LDAP Logins', 'authorizer' ); ?></label> <?php echo wp_kses( $ldap_installed_message, Helper::$allowed_html ); ?>
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
		$options              = Options::get_instance();
		$option               = 'ldap_host';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

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
		$options              = Options::get_instance();
		$option               = 'ldap_port';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

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
		$options              = Options::get_instance();
		$option               = 'ldap_tls';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

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
		$options              = Options::get_instance();
		$option               = 'ldap_search_base';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

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
		$options              = Options::get_instance();
		$option               = 'ldap_uid';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

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
		$options              = Options::get_instance();
		$option               = 'ldap_attr_email';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" />
		<br /><label for="auth_settings_<?php echo esc_attr( $option ); ?>" class="helper"><?php esc_html_e( 'Example:  mail', 'authorizer' ); ?></label>
		<br /><small><?php echo wp_kses( __( "Note: If your LDAP server doesn't return an attribute containing an email, you can specify the @domain portion of the email address here, and the email address will be constructed from it and the username. For example, if user 'bob' logs in and his email address should be bob@example.edu, then enter <strong>@example.edu</strong> in this field.", 'authorizer' ), Helper::$allowed_html ); ?></small>
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
		$options              = Options::get_instance();
		$option               = 'ldap_user';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

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
		$options              = Options::get_instance();
		$option               = 'ldap_password';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="password" id="garbage_to_stop_autofill" name="garbage" value="" autocomplete="off" style="display:none;" />

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
		$options              = Options::get_instance();
		$option               = 'ldap_lostpassword_url';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

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
		$options              = Options::get_instance();
		$option               = 'ldap_attr_first_name';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

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
		$options              = Options::get_instance();
		$option               = 'ldap_attr_last_name';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

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
		$options              = Options::get_instance();
		$option               = 'ldap_attr_update_on_login';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="checkbox" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="1"<?php checked( 1 === intval( $auth_settings_option ) ); ?> /><label for="auth_settings_<?php echo esc_attr( $option ); ?>"><?php esc_html_e( 'Update first and last name fields on login (will overwrite any name the user has supplied in their profile)', 'authorizer' ); ?></label>
		<?php
	}
}
