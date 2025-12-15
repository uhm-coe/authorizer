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
 * Contains functions for rendering the OIDC options in the External Service
 * tab in Authorizer Settings.
 */
class Oidc extends \Authorizer\Singleton {

	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_checkbox_auth_external_oidc( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'oidc';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="checkbox" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="1"<?php checked( 1 === intval( $auth_settings_option ) ); ?> /><label for="auth_settings_<?php echo esc_attr( $option ); ?>"><?php esc_html_e( 'Enable OIDC Logins', 'authorizer' ); ?></label>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_select_oidc_auto_login( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'oidc_auto_login';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );
		$oidc_num_servers     = max( 1, min( 20, intval( $args['oidc_num_servers'] ?? 1 ) ) );

		// Print option elements.
		?>
		<select id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]">
			<option value="" <?php selected( $auth_settings_option, '' ); ?>><?php echo esc_html_e( 'Off', 'default' ); ?></option>
			<?php foreach ( range( 1, $oidc_num_servers ) as $server_num ) : ?>
					<option value="<?php echo esc_attr( $server_num ); ?>" <?php selected( $auth_settings_option, strval( $server_num ) ); ?>>
						<?php
						echo esc_html( sprintf(
							/* TRANSLATORS: OIDC server number */
							__( 'Immediately redirect to OIDC server #%s', 'authorizer' ),
							strval( $server_num )
						) );
						?>
					</option>
			<?php endforeach; ?>
		</select>
		<p class="description">
			<?php esc_html_e( "Immediately redirect to OIDC login form if it's the only enabled external service and WordPress logins are hidden", 'authorizer' ); ?>
			<br>
			<small><?php esc_html_e( 'Note: This feature will only work if you have checked "Hide WordPress Logins" in Advanced settings, and if OIDC is the only enabled service (i.e., no Google, LDAP, OAuth2, or CAS).', 'authorizer' ); ?></small>
		</p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode, oidc_num_server).
	 * @return void
	 */
	public function print_number_oidc_num_servers( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'oidc_num_servers';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );
		$auth_settings_option = max( 1, min( 20, intval( $auth_settings_option ) ) );

		// Print option elements.
		?>
		<input type="number" min="1" max="20" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" />
		<p class="description"><?php esc_html_e( 'Note: Save changes after increasing this value to see the options for additional OIDC servers below.', 'authorizer' ); ?></p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode, oidc_num_server).
	 * @return void
	 */
	public function print_text_oidc_custom_label( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$suffix               = empty( $args['oidc_num_server'] ) || 1 === $args['oidc_num_server'] ? '' : '_' . $args['oidc_num_server'];
		$option               = 'oidc_custom_label' . $suffix;
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		esc_html_e( 'The button on the login page will read:', 'authorizer' );
		?>
		<p><a class="button button-primary button-large button-external button-oidc"><span class="dashicons dashicons-lock"></span> <strong><?php esc_html_e( 'Sign in with', 'authorizer' ); ?> </strong><input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="OIDC" /></a></p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode, oidc_num_server).
	 * @return void
	 */
	public function print_text_oidc_issuer( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$suffix               = empty( $args['oidc_num_server'] ) || 1 === $args['oidc_num_server'] ? '' : '_' . $args['oidc_num_server'];
		$option               = 'oidc_issuer' . $suffix;
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="text" class="wide" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" />
		<p class="description"><?php esc_html_e( 'Example:  https://login.microsoftonline.com/{tenant}/v2.0 or https://keycloak.example.com/realms/{realm}', 'authorizer' ); ?></p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode, oidc_num_server).
	 * @return void
	 */
	public function print_text_oidc_client_id( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$suffix               = empty( $args['oidc_num_server'] ) || 1 === $args['oidc_num_server'] ? '' : '_' . $args['oidc_num_server'];
		$oidc_num_server      = empty( $args['oidc_num_server'] ) || 1 === $args['oidc_num_server'] ? 1 : intval( $args['oidc_num_server'] );
		$option               = 'oidc_client_id' . $suffix;
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );


		// Omit server id=1 from redirect_uri for consistency with CAS and OAuth2
		// implementations.
		$redirect_uri = site_url( '/wp-login.php?external=oidc' );
		if ( $oidc_num_server > 1 ) {
			$redirect_uri .= '&id=' . $oidc_num_server;
		}

		// Print option elements.
		?>
		<p>
			<?php esc_html_e( 'Generate your Client ID and Secret for your OIDC provider by following their specific instructions.', 'authorizer' ); ?>
		</p>
		<?php
		// If ID is overridden by filter or constant, don't expose the value;
		// just print an informational message.
		// Note: constant/filter overrides are only supported for a single OIDC server (server 1).
		if ( has_filter( 'authorizer_oidc_client_id' ) && 1 === $oidc_num_server ) {
			?>
			<input type="hidden" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="" />
			<p class="description">
				<?php
				echo wp_kses_post(
					sprintf(
						/* TRANSLATORS: %s: filter name */
						__( 'This setting is not editable since it has been defined in the %s filter.', 'authorizer' ),
						'<code>authorizer_oidc_client_id</code>'
					)
				);
				?>
			</p>
			<?php
			return;
		} elseif ( defined( 'AUTHORIZER_OIDC_CLIENT_ID' ) && 1 === $oidc_num_server ) {
			?>
			<input type="hidden" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="" />
			<p class="description">
				<?php
				echo wp_kses_post(
					sprintf(
						/* TRANSLATORS: %s: defined constant name */
						__( 'This setting is not editable since it has been defined in wp-config.php via %s', 'authorizer' ),
						"<code>define( 'AUTHORIZER_OIDC_CLIENT_ID', '...' );</code>"
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
	 * @param  string $args Args (e.g., multisite admin mode, oidc_num_server).
	 * @return void
	 */
	public function print_text_oidc_client_secret( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$suffix               = empty( $args['oidc_num_server'] ) || 1 === $args['oidc_num_server'] ? '' : '_' . $args['oidc_num_server'];
		$oidc_num_server      = empty( $args['oidc_num_server'] ) || 1 === $args['oidc_num_server'] ? 1 : intval( $args['oidc_num_server'] );
		$option               = 'oidc_client_secret' . $suffix;
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// If secret is overridden by filter or constant, don't expose the value;
		// just print an informational message.
		// Note: constant/filter overrides are only supported for a single OIDC server (server 1).
		if ( has_filter( 'authorizer_oidc_client_secret' ) && 1 === $oidc_num_server ) {
			?>
			<input type="hidden" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="" />
			<p class="description">
				<?php
				echo wp_kses_post(
					sprintf(
						/* TRANSLATORS: %s: filter name */
						__( 'This setting is not editable since it has been defined in the %s filter.', 'authorizer' ),
						'<code>authorizer_oidc_client_secret</code>'
					)
				);
				?>
			</p>
			<?php
			return;
		} elseif ( defined( 'AUTHORIZER_OIDC_CLIENT_SECRET' ) && 1 === $oidc_num_server ) {
			?>
			<input type="hidden" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="" />
			<p class="description">
				<?php
				echo wp_kses_post(
					sprintf(
						/* TRANSLATORS: %s: defined constant name */
						__( 'This setting is not editable since it has been defined in wp-config.php via %s', 'authorizer' ),
						"<code>define( 'AUTHORIZER_OIDC_CLIENT_SECRET', '...' );</code>"
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
	public function print_text_oidc_scopes( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$suffix               = empty( $args['oidc_num_server'] ) || 1 === $args['oidc_num_server'] ? '' : '_' . $args['oidc_num_server'];
		$option               = 'oidc_scopes' . $suffix;
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="text" class="wide" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="openid email profile" />
		<p class="description"><?php esc_html_e( 'Space-separated list of scopes to request. Default: openid email profile', 'authorizer' ); ?></p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_text_oidc_prompt( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$suffix               = empty( $args['oidc_num_server'] ) || 1 === $args['oidc_num_server'] ? '' : '_' . $args['oidc_num_server'];
		$option               = 'oidc_prompt' . $suffix;
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" />
		<p class="description"><?php esc_html_e( 'Optional: prompt parameter (e.g., login, consent, select_account). Leave blank for default behavior.', 'authorizer' ); ?></p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_text_oidc_login_hint( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$suffix               = empty( $args['oidc_num_server'] ) || 1 === $args['oidc_num_server'] ? '' : '_' . $args['oidc_num_server'];
		$option               = 'oidc_login_hint' . $suffix;
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" />
		<p class="description"><?php esc_html_e( 'Optional: login_hint parameter (e.g., user@example.com). Leave blank for default behavior.', 'authorizer' ); ?></p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_text_oidc_max_age( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$suffix               = empty( $args['oidc_num_server'] ) || 1 === $args['oidc_num_server'] ? '' : '_' . $args['oidc_num_server'];
		$option               = 'oidc_max_age' . $suffix;
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" />
		<p class="description"><?php esc_html_e( 'Optional: max_age parameter (seconds since last authentication). Leave blank for default behavior.', 'authorizer' ); ?></p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_text_oidc_attr_username( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$suffix               = empty( $args['oidc_num_server'] ) || 1 === $args['oidc_num_server'] ? '' : '_' . $args['oidc_num_server'];
		$option               = 'oidc_attr_username' . $suffix;
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="preferred_username" autocomplete="off" />
		<p class="description">
			<?php esc_html_e( 'Example: preferred_username', 'authorizer' ); ?>
			<br>
			<?php esc_html_e( 'Leave blank to use the default username returned by the external service (will fallback to sub claim).', 'authorizer' ); ?>
		</p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_text_oidc_attr_email( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$suffix               = empty( $args['oidc_num_server'] ) || 1 === $args['oidc_num_server'] ? '' : '_' . $args['oidc_num_server'];
		$option               = 'oidc_attr_email' . $suffix;
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="email" autocomplete="off" />
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
	public function print_text_oidc_attr_first_name( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$suffix               = empty( $args['oidc_num_server'] ) || 1 === $args['oidc_num_server'] ? '' : '_' . $args['oidc_num_server'];
		$option               = 'oidc_attr_first_name' . $suffix;
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="given_name" autocomplete="off" />
		<p class="description"><?php esc_html_e( 'Example:  given_name', 'authorizer' ); ?></p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_text_oidc_attr_last_name( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$suffix               = empty( $args['oidc_num_server'] ) || 1 === $args['oidc_num_server'] ? '' : '_' . $args['oidc_num_server'];
		$option               = 'oidc_attr_last_name' . $suffix;
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="family_name" autocomplete="off" />
		<p class="description"><?php esc_html_e( 'Example:  family_name', 'authorizer' ); ?></p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_select_oidc_attr_update_on_login( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$suffix               = empty( $args['oidc_num_server'] ) || 1 === $args['oidc_num_server'] ? '' : '_' . $args['oidc_num_server'];
		$option               = 'oidc_attr_update_on_login' . $suffix;
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
	public function print_checkbox_oidc_require_verified_email( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$suffix               = empty( $args['oidc_num_server'] ) || 1 === $args['oidc_num_server'] ? '' : '_' . $args['oidc_num_server'];
		$option               = 'oidc_require_verified_email' . $suffix;
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="checkbox" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="1"<?php checked( 1 === intval( $auth_settings_option ) ); ?> /><label for="auth_settings_<?php echo esc_attr( $option ); ?>"><?php esc_html_e( 'Require verified email address', 'authorizer' ); ?></label>
		<p class="description"><?php esc_html_e( 'If checked, users must have a verified email address (email_verified claim) to log in.', 'authorizer' ); ?></p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_text_oidc_hosteddomain( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$suffix               = empty( $args['oidc_num_server'] ) || 1 === $args['oidc_num_server'] ? '' : '_' . $args['oidc_num_server'];
		$option               = 'oidc_hosteddomain' . $suffix;
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<textarea id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" placeholder="" style="width:220px;"><?php echo esc_html( $auth_settings_option ); ?></textarea>
		<p class="description"><?php esc_html_e( 'Restrict OIDC logins to a specific domain (for example, mycollege.edu). Leave blank to allow all valid sign-ins.', 'authorizer' ); ?> <?php esc_html_e( 'If restricting to multiple domains, add one domain per line.', 'authorizer' ); ?></p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode, oidc_num_server).
	 * @return void
	 */
	public function print_checkbox_oidc_link_on_username( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$suffix               = empty( $args['oidc_num_server'] ) || 1 === $args['oidc_num_server'] ? '' : '_' . $args['oidc_num_server'];
		$option               = 'oidc_link_on_username' . $suffix;
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="checkbox" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="1"<?php checked( 1 === intval( $auth_settings_option ) ); ?> /><label for="auth_settings_<?php echo esc_attr( $option ); ?>"><?php esc_html_e( 'Link OIDC accounts to WordPress accounts by their username (leave this off to link by email address)', 'authorizer' ); ?></label>
		<p class="description"><?php esc_html_e( "Note: The default (and most secure) behavior is to associate WordPress accounts with OIDC accounts by the email they have in common. However, some uncommon OIDC provider configurations don't contain email addresses for users. Enable this option if your OIDC provider doesn't have an attribute containing an email, or if you have WordPress accounts that don't have emails.", 'authorizer' ); ?></p>
		<?php
	}


	/**
	 * Restore any redirect_to value saved during an OIDC login (in the
	 * `authenticate` hook). This is needed since OIDC providers may drop
	 * querystring parameters during the authentication flow.
	 *
	 * @hook login_redirect
	 *
	 * @param string $redirect_to Destination URL.
	 */
	public function maybe_redirect_after_oidc_login( $redirect_to ) {
		if ( ! empty( $_SESSION['oidc_redirect_to'] ) ) {
			$redirect_to = sanitize_url( $_SESSION['oidc_redirect_to'] );
			unset( $_SESSION['oidc_redirect_to'] );
		}

		return $redirect_to;
	}

	/**
	 * Unset OIDC session variables to prevent session pollution during any of the
	 * login failure cases (e.g., successful OIDC authentication, but user blocked
	 * in WordPress).
	 */
	public function maybe_unset_oidc_session_vars() {
		if ( PHP_SESSION_ACTIVE === session_status() ) {
			unset( $_SESSION['oidc_server_id'] );
			unset( $_SESSION['oidc_redirect_to'] );
		}
	}

	/**
	 * Delete OIDC user meta when a user signs out.
	 *
	 * @param int $user_id ID of user logging out.
	 */
	public function delete_oidc_user_meta( $user_id = 0 ) {
		if ( ! empty( $user_id ) ) {
			delete_user_meta( $user_id, 'oidc_id_token' );
			delete_user_meta( $user_id, 'oidc_server_id' );
		}
	}
}

