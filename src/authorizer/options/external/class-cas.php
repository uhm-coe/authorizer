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
 * Contains functions for rendering the CAS options in the External Service
 * tab in Authorizer Settings.
 */
class Cas extends \Authorizer\Singleton {

	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_checkbox_auth_external_cas( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'cas';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Make sure php5-curl extension is installed on server.
		$curl_installed_message = ! function_exists( 'curl_init' ) ? __( '<a href="http://www.php.net//manual/en/curl.installation.php" target="_blank" style="color: #dc3232;">PHP CURL extension</a> is not installed', 'authorizer' ) : '';

		// Make sure php_openssl extension is installed on server.
		$openssl_installed_message = ! extension_loaded( 'openssl' ) ? __( '<a href="http://stackoverflow.com/questions/23424459/enable-php-openssl-not-working" target="_blank" style="color: #dc3232;">PHP openssl extension</a> is not installed', 'authorizer' ) : '';

		// Build error message string.
		$error_message = '';
		if ( strlen( $curl_installed_message ) > 0 || strlen( $openssl_installed_message ) > 0 ) {
			$error_message = '<span style="color: #dc3232;">(' .
				__( 'Warning', 'authorizer' ) . ': ' .
				$curl_installed_message .
				( strlen( $curl_installed_message ) > 0 && strlen( $openssl_installed_message ) > 0 ? '; ' : '' ) .
				$openssl_installed_message .
				')</span>';
		}

		// Print option elements.
		?>
		<input type="checkbox" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="1"<?php checked( 1 === intval( $auth_settings_option ) ); ?> /><label for="auth_settings_<?php echo esc_attr( $option ); ?>"><?php esc_html_e( 'Enable CAS Logins', 'authorizer' ); ?></label> <?php echo wp_kses( $error_message, Helper::$allowed_html ); ?>
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
		$options              = Options::get_instance();
		$option               = 'cas_auto_login';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="checkbox" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="1"<?php checked( 1 === intval( $auth_settings_option ) ); ?> /><label for="auth_settings_<?php echo esc_attr( $option ); ?>"><?php esc_html_e( "Immediately redirect to CAS login form if it's the only enabled external service and WordPress logins are hidden", 'authorizer' ); ?></label>
		<p class="description"><?php esc_html_e( 'Note: This feature will only work if you have checked "Hide WordPress Logins" in Advanced settings, and if CAS is the only enabled service (i.e., no Google or LDAP). If you have enabled CAS Single Sign-On (SSO), and a user has already logged into CAS elsewhere, enabling this feature will allow automatic logins without any user interaction.', 'authorizer' ); ?></p>
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
		$options              = Options::get_instance();
		$option               = 'cas_custom_label';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		esc_html_e( 'The button on the login page will read:', 'authorizer' );
		?>
		<p><a class="button button-primary button-large button-external button-cas"><span class="dashicons dashicons-lock"></span> <strong><?php esc_html_e( 'Sign in with', 'authorizer' ); ?> </strong><input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="CAS" /></a></p>
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
		$options              = Options::get_instance();
		$option               = 'cas_host';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" />
		<p class="description"><?php esc_html_e( 'Example:  authn.example.edu', 'authorizer' ); ?></p>
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
		$options              = Options::get_instance();
		$option               = 'cas_port';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" style="width:50px;" />
		<p class="description"><?php esc_html_e( 'Example:  443', 'authorizer' ); ?></p>
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
		$options              = Options::get_instance();
		$option               = 'cas_path';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" />
		<p class="description"><?php esc_html_e( 'Example:  /cas', 'authorizer' ); ?></p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_select_cas_method( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'cas_method';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );
		$auth_settings_option = $this->sanitize_cas_method( $auth_settings_option );
		$select_options       = array(
			'CLIENT' => 'Client',
			'PROXY'  => 'Proxy',
		);

		// Print option elements.
		?>
		<select id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]">
			<?php foreach ( $select_options as $method => $label ) : ?>
					<option value="<?php echo esc_attr( $method ); ?>" <?php selected( $auth_settings_option, $method ); ?>><?php echo esc_html( $label ); ?></option>
			<?php endforeach; ?>
		</select>
		<p class="description"><small><?php esc_html_e( '"Client" is the most common, but use "Proxy" if your CAS server is behind a proxy server.', 'authorizer' ); ?></small></p>
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
		$options              = Options::get_instance();
		$option               = 'cas_version';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );
		$auth_settings_option = $this->sanitize_cas_version( $auth_settings_option );

		// Print option elements.
		?>
		<select id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]">
			<?php foreach ( array_reverse( \phpCAS::getSupportedProtocols() ) as $version => $label ) : ?>
				<option value="<?php echo esc_attr( $version ); ?>" <?php selected( $auth_settings_option, $version ); ?>><?php echo esc_html( $label ); ?></option>
			<?php endforeach; ?>
		</select>
		<?php
	}


	/**
	 * Validate supplied CAS method.
	 *
	 * @param  string $cas_method CAS method string.
	 *
	 * @return string             CAS method string 'PROXY' or 'CLIENT' (default).
	 */
	public function sanitize_cas_method( $cas_method = '' ) {
		$cas_methods = array( 'PROXY', 'CLIENT' );
		if ( empty( $cas_method ) || ! in_array( $cas_method, $cas_methods, true ) ) {
			$cas_method = array_pop( $cas_methods ); // Default to 'CLIENT'.
		}

		return $cas_method;
	}


	/**
	 * Validate supplied CAS version against phpCAS. Older versions of Authorizer
	 * stored custom protocol version strings, so we handle converting those here.
	 *
	 * @param  string $cas_version CAS protocol string.
	 *
	 * @return string              CAS protocol string supported by phpCAS::client().
	 */
	public function sanitize_cas_version( $cas_version = '' ) {
		if ( ! class_exists( 'phpCAS' ) ) {
			return '';
		}

		$cas_versions = \phpCAS::getSupportedProtocols();
		if ( empty( $cas_version ) ) {
			$cas_version = array_key_last( $cas_versions ); // Should be SAML 1.1.
		} elseif ( ! in_array( $cas_version, array_keys( $cas_versions ), true ) ) {
			// Backwards compatibility with constant strings from Authorizer < 3.0.11.
			if ( 'SAML_VERSION_1_1' === $cas_version ) {
				$cas_version = 'S1';
			} elseif ( 'CAS_VERSION_3_0' === $cas_version ) {
				$cas_version = '3.0';
			} elseif ( 'CAS_VERSION_2_0' === $cas_version ) {
				$cas_version = '2.0';
			} elseif ( 'CAS_VERSION_1_0' === $cas_version ) {
				$cas_version = '1.0';
			} else {
				$cas_version = array_key_last( $cas_versions );
			}
		}

		return $cas_version;
	}


	/**
	 * Package phpCAS 1.6.0 asserts that the service URL provided by the user
	 * logging in matches the URL specified here (to prevent nefarious clients
	 * from modifying the http headers with their own values). Note: here we
	 * handle common port/protocol variants in case get_option( 'siteurl' )
	 * doesn't match the actual protocol.
	 *
	 * @return array protocol://domain:port of current WordPress site (both http and https).
	 */
	public function get_valid_cas_service_urls() {
		$valid_base_url_parts = wp_parse_url( site_url( '', 'login' ) );
		$valid_base_url       = ! empty( $valid_base_url_parts['host'] ) ? $valid_base_url_parts['host'] : '';
		$valid_base_url      .= ! empty( $valid_base_url_parts['port'] ) ? ':' . $valid_base_url_parts['port'] : '';
		$valid_base_urls      = array(
			'http://' . $valid_base_url,
			'https://' . $valid_base_url,
		);

		return $valid_base_urls;
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_text_cas_attr_email( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'cas_attr_email';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" />
		<p class="description">
			<?php esc_html_e( 'Example:  mail', 'authorizer' ); ?>
			<br>
			<small><?php echo wp_kses( __( "Note: If your CAS server doesn't return an attribute containing an email, you can specify the @domain portion of the email address here, and the email address will be constructed from it and the username. For example, if user 'bob' logs in and his email address should be bob@example.edu, then enter <strong>@example.edu</strong> in this field.", 'authorizer' ), Helper::$allowed_html ); ?></small>
		</p>
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
		$options              = Options::get_instance();
		$option               = 'cas_attr_first_name';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" />
		<p class="description"><?php esc_html_e( 'Example:  givenName', 'authorizer' ); ?></p>
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
		$options              = Options::get_instance();
		$option               = 'cas_attr_last_name';
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
	public function print_select_cas_attr_update_on_login( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'cas_attr_update_on_login';
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
	public function print_checkbox_cas_link_on_username( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'cas_link_on_username';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="checkbox" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="1"<?php checked( 1 === intval( $auth_settings_option ) ); ?> /><label for="auth_settings_<?php echo esc_attr( $option ); ?>"><?php esc_html_e( 'Link CAS accounts to WordPress accounts by their username (leave this off to link by email address)', 'authorizer' ); ?></label>
		<p class="description"><?php esc_html_e( "Note: The default (and most secure) behavior is to associate WordPress accounts with CAS accounts by the email they have in common. However, some uncommon CAS server configurations don't contain email addresses for users. Enable this option if your CAS server doesn't have an attribute containing an email, or if you have WordPress accounts that don't have emails.", 'authorizer' ); ?></p>
		<?php
	}
}
