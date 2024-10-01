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
 * Contains functions for rendering the OAuth2 options in the External Service
 * tab in Authorizer Settings.
 */
class OAuth2 extends \Authorizer\Singleton {

	/**
	 * List of supported oauth2 providers and their details.
	 *
	 * @var array
	 */
	private $providers = array(
		/**
		 * 'amazon' => array(
		 *   'name'             => 'Amazon',
		 *   'composer'         => '"luchianenco/oauth2-amazon": "^1.1"',
		 *   'instructions_url' => 'https://aws.amazon.com/blogs/security/how-to-add-authentication-single-page-web-application-with-amazon-cognito-oauth2-implementation/',
		 * ),
		 */
		'azure'   => array(
			'name'             => 'Microsoft Azure',
			'instructions_url' => 'https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app',
		),
		'github'  => array(
			'name'             => 'GitHub',
			'instructions_url' => 'https://github.com/settings/applications/new',
		),
		'generic' => array(
			'name'             => 'Other (generic OAuth2 provider)',
			'instructions_url' => 'https://github.com/thephpleague/oauth2-client#authorization-code-grant',
		),
	);

	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_checkbox_auth_external_oauth2( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'oauth2';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="checkbox" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="1"<?php checked( 1 === intval( $auth_settings_option ) ); ?> /><label for="auth_settings_<?php echo esc_attr( $option ); ?>"><?php esc_html_e( 'Enable OAuth2 Logins', 'authorizer' ); ?></label>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_select_oauth2_provider( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'oauth2_provider';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Override generic provider name to make it translatable (can't use functions above in the variable definition).
		if ( ! empty( $this->providers['generic'] ) ) {
			$this->providers['generic']['name'] = __( 'Other (generic OAuth2 provider)', 'authorizer' );
		}

		// Print option elements.
		?>
		<select id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]">
			<option value=""<?php selected( '' === $auth_settings_option ); ?>><?php esc_html_e( '-- None --', 'authorizer' ); ?></option>
			<?php foreach ( $this->providers as $provider => $provider_data ) : ?>
				<option value="<?php echo esc_attr( $provider ); ?>"<?php selected( $provider, $auth_settings_option ); ?>><?php echo esc_html( $provider_data['name'] ); ?></option>
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
	public function print_text_oauth2_custom_label( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'oauth2_custom_label';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		esc_html_e( 'The button on the login page will read:', 'authorizer' );
		?>
		<p><a class="button button-primary button-large button-external"><span class="dashicons dashicons-lock"></span> <strong><?php esc_html_e( 'Sign in with', 'authorizer' ); ?> </strong><input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="OAuth2" /></a></p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_text_oauth2_clientid( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'oauth2_clientid';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		$site_url_parts = wp_parse_url( get_site_url() );
		$site_url_host  = $site_url_parts['scheme'] . '://' . $site_url_parts['host'] . '/';
		?>
		<p>
			<?php esc_html_e( 'Generate your Client ID and Secret for your selected provider by following their specific instructions.', 'authorizer' ); ?>
			<?php esc_html_e( 'If asked for a redirect or callback URL, use:' ); ?>
			<strong><?php echo esc_html( site_url( '/wp-login.php?external=oauth2' ) ); ?></strong>
		</p>
		<p>
			<?php esc_html_e( 'If using Microsoft Azure, omit the querystring; use:' ); ?>
			<strong><?php echo esc_html( site_url( '/wp-login.php' ) ); ?></strong>
		</p>
		<ol>
			<?php foreach ( $this->providers as $provider => $provider_data ) : ?>
				<li><a href="<?php echo esc_attr( $provider_data['instructions_url'] ); ?>" target="_blank"><?php echo esc_html( $provider_data['name'] ); ?></a></li>
			<?php endforeach; ?>
		</ol>
		<?php
		// If ID is overridden by filter or constant, don't expose the value;
		// just print an informational message.
		if ( has_filter( 'authorizer_oauth2_client_id' ) ) {
			?>
			<input type="hidden" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="" />
			<p class="description">
				<?php
				echo wp_kses_post(
					sprintf(
						/* TRANSLATORS: %s: authorizer_oauth2_client_id (filter name) */
						__( 'This setting is not editable since it has been defined in the %s filter.', 'authorizer' ),
						'<code>authorizer_oauth2_client_id</code>'
					)
				);
				?>
			</p>
			<?php
			return;
		} elseif ( defined( 'AUTHORIZER_OAUTH2_CLIENT_ID' ) ) {
			?>
			<input type="hidden" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="" />
			<p class="description">
				<?php
				echo wp_kses_post(
					sprintf(
						/* TRANSLATORS: %s: AUTHORIZER_OAUTH2_CLIENT_ID (defined constant name) */
						__( 'This setting is not editable since it has been defined in wp-config.php via %s', 'authorizer' ),
						"<code>define( 'AUTHORIZER_OAUTH2_CLIENT_ID', '...' );</code>"
					)
				);
				?>
			</p>
			<?php
			return;
		}

		?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" />
		<p class="description"><?php esc_html_e( 'Example:  0123456789abcdef0123', 'authorizer' ); ?></p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_text_oauth2_clientsecret( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'oauth2_clientsecret';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// If secret is overridden by filter or constant, don't expose the value;
		// just print an informational message.
		if ( has_filter( 'authorizer_oauth2_client_secret' ) ) {
			?>
			<input type="hidden" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="" />
			<p class="description">
				<?php
				echo wp_kses_post(
					sprintf(
						/* TRANSLATORS: %s: authorizer_oauth2_client_secret (filter name) */
						__( 'This setting is not editable since it has been defined in the %s filter.', 'authorizer' ),
						'<code>authorizer_oauth2_client_secret</code>'
					)
				);
				?>
			</p>
			<?php
			return;
		} elseif ( defined( 'AUTHORIZER_OAUTH2_CLIENT_SECRET' ) ) {
			?>
			<input type="hidden" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="" />
			<p class="description">
				<?php
				echo wp_kses_post(
					sprintf(
						/* TRANSLATORS: %s: AUTHORIZER_OAUTH2_CLIENT_SECRET (defined constant name) */
						__( 'This setting is not editable since it has been defined in wp-config.php via %s', 'authorizer' ),
						"<code>define( 'AUTHORIZER_OAUTH2_CLIENT_SECRET', '...' );</code>"
					)
				);
				?>
			</p>
			<?php
			return;
		}

		// Print option elements.
		?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" style="width:220px;" />
		<p class="description"><?php esc_html_e( 'Example:  0123456789abcdef0123456789abcdef', 'authorizer' ); ?></p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_text_oauth2_hosteddomain( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'oauth2_hosteddomain';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<textarea id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" placeholder="" style="width:220px;"><?php echo esc_html( $auth_settings_option ); ?></textarea>
		<p class="description"><?php esc_html_e( 'Restrict OAuth2 logins to a specific domain (for example, mycollege.edu). Leave blank to allow all valid sign-ins.', 'authorizer' ); ?> <?php esc_html_e( 'If restricting to multiple domains, add one domain per line.', 'authorizer' ); ?></p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_text_oauth2_tenant_id( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'oauth2_tenant_id';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="common" autocomplete="off" />
		<p class="description"><?php esc_html_e( 'Example:  "common", or a specific Azure Directory Tenant ID', 'authorizer' ); ?></p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_text_oauth2_url_authorize( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'oauth2_url_authorize';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="text" class="wide" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" />
		<p class="description"><?php esc_html_e( 'Example:  https://example.edu/login/oauth/authorize', 'authorizer' ); ?></p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_text_oauth2_url_token( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'oauth2_url_token';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="text" class="wide" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" />
		<p class="description"><?php esc_html_e( 'Example:  https://example.edu/login/oauth/access_token', 'authorizer' ); ?></p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_text_oauth2_url_resource( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'oauth2_url_resource';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="text" class="wide" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" />
		<p class="description"><?php esc_html_e( 'Example:  https://api.example.edu/user', 'authorizer' ); ?></p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_text_oauth2_attr_username( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'oauth2_attr_username';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" autocomplete="off" />
		<p class="description">
			<?php esc_html_e( 'Example: preferred_username', 'authorizer' ); ?>
			<br>
			<?php esc_html_e( 'Leave blank to use the default username returned by the external service.', 'authorizer' ); ?>
		</p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_text_oauth2_attr_email( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'oauth2_attr_email';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" autocomplete="off" />
		<p class="description">
			<?php esc_html_e( 'Example: email', 'authorizer' ); ?>
			<br>
			<?php esc_html_e( 'Leave blank to use the default email returned by the external service.', 'authorizer' ); ?>
		</p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_text_oauth2_attr_first_name( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'oauth2_attr_first_name';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" autocomplete="off" />
		<p class="description"><?php esc_html_e( 'Example:  given_name', 'authorizer' ); ?></p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_text_oauth2_attr_last_name( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'oauth2_attr_last_name';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" autocomplete="off" />
		<p class="description"><?php esc_html_e( 'Example:  family_name', 'authorizer' ); ?></p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_select_oauth2_attr_update_on_login( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'oauth2_attr_update_on_login';
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
	public function print_checkbox_oauth2_auto_login( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'oauth2_auto_login';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="checkbox" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="1"<?php checked( 1 === intval( $auth_settings_option ) ); ?> /><label for="auth_settings_<?php echo esc_attr( $option ); ?>"><?php esc_html_e( "Immediately redirect to OAuth2 login form if it's the only enabled external service and WordPress logins are hidden", 'authorizer' ); ?></label>
		<p class="description"><?php esc_html_e( 'Note: This feature will only work if you have checked "Hide WordPress Logins" in Advanced settings, and if OAuth2 is the only enabled service (i.e., no Google, LDAP, or CAS).', 'authorizer' ); ?></p>
		<?php
	}


	/**
	 * Restore any redirect_to value saved during an Azure login (in the
	 * `authenticate` hook). This is needed since the Azure portal needs an
	 * approved URI to visit after logging in, and cannot have a variable
	 * redirect_to param in it like the normal WordPress redirect flow.
	 *
	 * @hook login_redirect
	 *
	 * @param string $redirect_to Destination URL.
	 */
	public function maybe_redirect_after_azure_login( $redirect_to ) {
		if ( ! empty( $_SESSION['azure_redirect_to'] ) ) {
			$redirect_to = sanitize_url( $_SESSION['azure_redirect_to'] );
		}

		return $redirect_to;
	}
}
