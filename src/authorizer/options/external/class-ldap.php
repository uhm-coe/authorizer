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
class Ldap extends \Authorizer\Singleton {

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
		$ldap_installed_message = ! function_exists( 'ldap_connect' ) ? '<span style="color: #dc3232;">(' . __( 'Warning: <a href="http://www.php.net/manual/en/ldap.installation.php" target="_blank" style="color: #dc3232;">PHP LDAP extension</a> is <strong>not</strong> installed', 'authorizer' ) . ')</span>' : '';

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
		<textarea id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" placeholder="" style="width:330px;"><?php echo esc_attr( $auth_settings_option ); ?></textarea>
		<p class="description"><?php esc_html_e( 'Specify either a hostname (for example, ldap.example.edu) or a full LDAP URI (for example, ldaps://ldap.example.edu:636).', 'authorizer' ); ?>
			<br>
			<small><?php esc_html_e( 'If you have multiple LDAP servers (failover or high-availability configuration), separate them by newlines (one per line).', 'authorizer' ); ?></small>
		</p>
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
		<p class="description">
			<?php esc_html_e( 'Example:  389', 'authorizer' ); ?>
			<br>
			<small><?php esc_html_e( 'If a full LDAP URI (ldaps://hostname:port) is specified above, this field is ignored.', 'authorizer' ); ?></small>
		</p>
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
		<input type="checkbox" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="1"<?php checked( 1 === intval( $auth_settings_option ) ); ?> /><label for="auth_settings_<?php echo esc_attr( $option ); ?>"><?php esc_html_e( 'Use STARTTLS', 'authorizer' ); ?></label>
		<p class="description"><small><?php esc_html_e( 'If an ldaps:// URL (and therefore Implicit TLS) is used, this checkbox is ignored.', 'authorizer' ); ?></small></p>
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
		<p class="description"><?php esc_html_e( 'Example:  ou=people,dc=example,dc=edu', 'authorizer' ); ?>
			<br>
			<small><?php esc_html_e( 'If you have multiple search bases, separate them by newlines (one per line).', 'authorizer' ); ?></small>
		</p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_text_ldap_search_filter( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'ldap_search_filter';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<textarea id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" placeholder="" style="width:330px;"><?php echo esc_attr( $auth_settings_option ); ?></textarea>
		<p class="description"><?php esc_html_e( 'Example:  (memberOf=cn=wp_users,ou=people,dc=example,dc=edu)', 'authorizer' ); ?>
		<br>
		<small><?php esc_html_e( 'If you wish to use an LDAP search filter, enter it here. Otherwise leave this field blank.', 'authorizer' ); ?></small>
		</p>
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
		<p class="description"><?php esc_html_e( 'Example:  uid', 'authorizer' ); ?></p>
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
		<p class="description"><?php esc_html_e( 'Example:  mail', 'authorizer' ); ?>
			<br>
			<small><?php echo wp_kses( __( "Note: If your LDAP server doesn't return an attribute containing an email, you can specify the @domain portion of the email address here, and the email address will be constructed from it and the username. For example, if user 'bob' logs in and his email address should be bob@example.edu, then enter <strong>@example.edu</strong> in this field.", 'authorizer' ), Helper::$allowed_html ); ?></small>
		</p>
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

		// If secret is overridden by filter or constant, don't expose the value;
		// just print an informational message.
		if ( has_filter( 'authorizer_ldap_user' ) ) {
			?>
			<input type="hidden" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="" />
			<p class="description">
				<?php
				echo wp_kses_post(
					sprintf(
						/* TRANSLATORS: %s: authorizer_ldap_user (filter name) */
						__( 'This setting is not editable since it has been defined in the %s filter.', 'authorizer' ),
						'<code>authorizer_ldap_user</code>'
					)
				);
				?>
			</p>
			<?php
			return;
		} elseif ( defined( 'AUTHORIZER_LDAP_USER' ) ) {
			?>
			<input type="hidden" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="" />
			<p class="description">
				<?php
				echo wp_kses_post(
					sprintf(
						/* TRANSLATORS: %s: AUTHORIZER_LDAP_USER (defined constant name) */
						__( 'This setting is not editable since it has been defined in wp-config.php via %s', 'authorizer' ),
						"<code>define( 'AUTHORIZER_LDAP_USER', '...' );</code>"
					)
				);
				?>
			</p>
			<?php
			return;
		}

		// Print option elements.
		?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" style="width:330px;" />
		<p class="description"><?php esc_html_e( 'Example:  cn=directory-user,ou=specials,dc=example,dc=edu', 'authorizer' ); ?>
			<br>
			<small>
				<?php
				echo wp_kses(
					sprintf(
						/* TRANSLATORS: %s: Username wildcard */
						__( 'Note: You can use the %s wildcard to bind as the username of the user logging in instead of a directory user service account.', 'authorizer' ),
						'<strong>[username]</strong>'
					), Helper::$allowed_html
				);
				?>
			</small>
			<br>
			<small>
				<?php
				echo wp_kses(
					sprintf(
						/* TRANSLATORS: %s: Username wildcard */
						__( 'Example: <strong>uid=%s,ou=people,dc=example,dc=edu</strong>.', 'authorizer' ),
						'[username]'
					), Helper::$allowed_html
				);
				?>
			</small>
			<br>
			<small><?php echo wp_kses( __( 'Leave the LDAP Directory User Password field below blank, and the bind will be attempted with the user-supplied password.', 'authorizer' ), Helper::$allowed_html ); ?></small>
		</p>
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

		// If secret is overridden by filter or constant, don't expose the value;
		// just print an informational message.
		if ( has_filter( 'authorizer_ldap_password' ) ) {
			?>
			<input type="hidden" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="" />
			<p class="description">
				<?php
				echo wp_kses_post(
					sprintf(
						/* TRANSLATORS: %s: authorizer_ldap_password (filter name) */
						__( 'This setting is not editable since it has been defined in the %s filter.', 'authorizer' ),
						'<code>authorizer_ldap_password</code>'
					)
				);
				?>
			</p>
			<?php
			return;
		} elseif ( defined( 'AUTHORIZER_LDAP_PASSWORD' ) ) {
			?>
			<input type="hidden" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="" />
			<p class="description">
				<?php
				echo wp_kses_post(
					sprintf(
						/* TRANSLATORS: %s: AUTHORIZER_LDAP_PASSWORD (defined constant name) */
						__( 'This setting is not editable since it has been defined in wp-config.php via %s', 'authorizer' ),
						"<code>define( 'AUTHORIZER_LDAP_PASSWORD', '...' );</code>"
					)
				);
				?>
			</p>
			<?php
			return;
		}

		// Print option elements.
		?>
		<input type="password" id="garbage_to_stop_autofill" name="garbage" value="" autocomplete="off" style="display:none;" />
		<input type="password" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( Helper::decrypt( $auth_settings_option ) ); ?>" autocomplete="new-password" />

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
		<p class="description"><?php esc_html_e( 'Example:  https://myschool.example.edu:8888/am-forgot-password', 'authorizer' ); ?></p>
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
		<p class="description"><?php esc_html_e( 'Example:  givenname', 'authorizer' ); ?></p>
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
		<p class="description"><?php esc_html_e( 'Example:  sn', 'authorizer' ); ?></p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_select_ldap_attr_update_on_login( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'ldap_attr_update_on_login';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );
		$values               = array(
			''                => __( 'Do not update first and last name fields on login', 'authorizer' ),
			'1'               => __( 'Update first and last name fields on login', 'authorizer' ),
			'update-if-empty' => __( 'Update first and last name fields on login only if they are empty', 'authorizer' ),
		);

		// Print option elements.
		?>
		<select id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]">
			<?php foreach ( $values as $value => $label ) : ?>
				<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $auth_settings_option, $value ); ?>><?php echo esc_html( $label ); ?></option>
			<?php endforeach; ?>
		</select>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_text_button_ldap_test_user( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'ldap_test_user';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="<?php esc_attr_e( 'username', 'authorizer' ); ?>" />
		<input type="password" id="garbage_to_stop_autofill_test" name="garbage" value="" autocomplete="off" style="display:none;" />
		<input type="password" id="auth_settings_ldap_test_pass" value="" autocomplete="new-password" placeholder="<?php esc_attr_e( 'password', 'authorizer' ); ?>" />
		<input type="button" id="<?php echo esc_attr( $option ); ?>_submit" class="button button-secondary" value="<?php esc_attr_e( 'Test', 'authorizer' ); ?>" />
		<span class="spinner" id="<?php echo esc_attr( $option ); ?>_spinner"></span>
		<p class="description">
			<small><?php esc_html_e( 'Note: Make sure to save any changes to LDAP settings before clicking the Test button.', 'authorizer' ); ?></small>
		</p>
		<textarea id="<?php echo esc_attr( $option ); ?>_result" readonly="readonly" style="display: none;" rows="8"></textarea>
		<?php
	}
}
