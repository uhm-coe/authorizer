<?php
/**
 * Authorizer
 *
 * @license  GPL-2.0+
 * @link     https://github.com/uhm-coe/authorizer
 * @package  authorizer
 */

namespace Authorizer\Options;

use Authorizer\Helper;
use Authorizer\Options;

/**
 * Contains functions for rendering the External Service tab in Authorizer Settings.
 */
class External extends \Authorizer\Singleton {

	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_section_info_external( $args = '' ) {
		?>
		<div id="section_info_external" class="section_info">
			<p><?php esc_html_e( 'Enter your external server settings below.', 'authorizer' ); ?></p>
		</div>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_select_auth_access_default_role( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'access_default_role';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<select id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]">
			<?php wp_dropdown_roles( $auth_settings_option ); ?>
			<option value=""<?php selected( '' === $auth_settings_option ); ?>><?php esc_html_e( '-- None --', 'authorizer' ); ?></option>
		</select>
		<?php
	}
}
