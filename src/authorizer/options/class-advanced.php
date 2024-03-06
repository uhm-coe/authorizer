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
 * Contains functions for rendering the Advanced tab in Authorizer Settings.
 */
class Advanced extends \Authorizer\Singleton {

	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_section_info_advanced( $args = '' ) {
		?>
		<div id="section_info_advanced" class="section_info">
			<p><?php esc_html_e( 'You may optionally specify some advanced settings below.', 'authorizer' ); ?></p>
		</div>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_text_auth_advanced_lockouts( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'advanced_lockouts';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		esc_html_e( 'After', 'authorizer' );
		?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>_attempts_1" name="auth_settings[<?php echo esc_attr( $option ); ?>][attempts_1]" value="<?php echo esc_attr( $auth_settings_option['attempts_1'] ); ?>" placeholder="10" style="width:40px;" />
		<?php esc_html_e( 'invalid password attempts, delay further attempts on that user for', 'authorizer' ); ?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>_duration_1" name="auth_settings[<?php echo esc_attr( $option ); ?>][duration_1]" value="<?php echo esc_attr( $auth_settings_option['duration_1'] ); ?>" placeholder="1" style="width:40px;" />
		<?php esc_html_e( 'minute(s).', 'authorizer' ); ?>
		<br />
		<?php esc_html_e( 'After', 'authorizer' ); ?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>_attempts_2" name="auth_settings[<?php echo esc_attr( $option ); ?>][attempts_2]" value="<?php echo esc_attr( $auth_settings_option['attempts_2'] ); ?>" placeholder="10" style="width:40px;" />
		<?php esc_html_e( 'more invalid attempts, increase the delay to', 'authorizer' ); ?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>_duration_2" name="auth_settings[<?php echo esc_attr( $option ); ?>][duration_2]" value="<?php echo esc_attr( $auth_settings_option['duration_2'] ); ?>" placeholder="10" style="width:40px;" />
		<?php esc_html_e( 'minutes.', 'authorizer' ); ?>
		<br />
		<?php esc_html_e( 'Reset the delays after', 'authorizer' ); ?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>_reset_duration" name="auth_settings[<?php echo esc_attr( $option ); ?>][reset_duration]" value="<?php echo esc_attr( $auth_settings_option['reset_duration'] ); ?>" placeholder="240" style="width:50px;" />
		<?php esc_html_e( 'minutes with no invalid attempts.', 'authorizer' ); ?>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_checkbox_auth_advanced_hide_wp_login( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'advanced_hide_wp_login';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="checkbox" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="1"<?php checked( 1 === intval( $auth_settings_option ) ); ?> /><label for="auth_settings_<?php echo esc_attr( $option ); ?>"><?php esc_html_e( 'Hide WordPress Logins', 'authorizer' ); ?></label>
		<p class="description"><?php esc_html_e( 'Note: You can always access the WordPress logins by adding external=wordpress to the wp-login URL, like so:', 'authorizer' ); ?><br /><a href="<?php echo esc_attr( wp_login_url() ); ?>?external=wordpress" target="_blank"><?php echo esc_html( wp_login_url() ); ?>?external=wordpress</a>.</p>
			<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_checkbox_auth_advanced_disable_wp_login( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'advanced_disable_wp_login';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="checkbox" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="1"<?php checked( 1 === intval( $auth_settings_option ) ); ?> /><label for="auth_settings_<?php echo esc_attr( $option ); ?>"><?php esc_html_e( 'Disable WordPress Logins', 'authorizer' ); ?></label>
		<p class="description"><?php esc_html_e( 'Warning: Disabling WordPress logins means you will not be able to access WordPress administration if your external service(s) are not working. Use with caution. Note: If no external services are enabled, WordPress logins will not be disabled.', 'authorizer' ); ?></p>
			<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_radio_auth_advanced_branding( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'advanced_branding';
		$auth_settings_option = $options->get( $option );

		// Print option elements.
		?>
		<fieldset>
			<label><input type="radio" id="radio_auth_settings_<?php echo esc_attr( $option ); ?>_default" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="default"<?php checked( 'default' === $auth_settings_option ); ?> /> <?php esc_html_e( 'Default WordPress login screen', 'authorizer' ); ?></label>
			<?php

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
				if ( ! ( is_array( $branding_option ) && array_key_exists( 'value', $branding_option ) && array_key_exists( 'description', $branding_option ) ) ) {
					continue;
				}
				?>
				<label><input type="radio" id="radio_auth_settings_<?php echo esc_attr( $option ); ?>_<?php echo esc_attr( sanitize_title( $branding_option['value'] ) ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $branding_option['value'] ); ?>"<?php checked( $branding_option['value'] === $auth_settings_option ); ?> /> <?php echo esc_html( $branding_option['description'] ); ?></label>
				<?php
			}

			// Print message about adding custom brands if there are none.
			if ( count( $branding_options ) === 0 ) {
				?>
				<p class="description"><?php echo wp_kses( __( '<strong>Note for theme developers</strong>: Add more options here by using the `authorizer_add_branding_option` filter in your theme. You can see an example theme that implements this filter in the plugin directory under sample-theme-add-branding.', 'authorizer' ), Helper::$allowed_html ); ?></p>
				<?php
			}
			?>
		</fieldset>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_radio_auth_advanced_admin_menu( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'advanced_admin_menu';
		$auth_settings_option = $options->get( $option );

		// Print option elements.
		?>
		<fieldset>
			<label><input type="radio" id="radio_auth_settings_<?php echo esc_attr( $option ); ?>_settings" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="settings"<?php checked( 'settings' === $auth_settings_option ); ?> /> <?php esc_html_e( 'Show in Settings menu', 'authorizer' ); ?></label>
			<br>
			<label><input type="radio" id="radio_auth_settings_<?php echo esc_attr( $option ); ?>_top" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="top"<?php checked( 'top' === $auth_settings_option ); ?> /> <?php esc_html_e( 'Show in sidebar (top level)', 'authorizer' ); ?></label>
		</fieldset>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_select_auth_advanced_usermeta( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'advanced_usermeta';
		$auth_settings_option = $options->get( $option );

		// Print option elements.
		?>
		<select id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]">
			<option value=""><?php esc_html_e( '-- None --', 'authorizer' ); ?></option>
			<?php
			if ( class_exists( 'acf' ) ) :
				// Get ACF 5 fields. Note: it would be much easier to use `get_field_objects()`
				// or `get_field_objects( 'user_' . get_current_user_id() )`, but neither will
				// list fields that have never been given values for users (i.e., new ACF
				// fields). Therefore we fall back on finding any ACF fields applied to users
				// (user_role or user_form location rules in the field group definition).
				$fields              = array();
				$acf_field_group_ids = array();
				$acf_field_groups    = new \WP_Query(
					array(
						'post_type' => 'acf-field-group',
					)
				);
				while ( $acf_field_groups->have_posts() ) : $acf_field_groups->the_post();
					if ( strpos( get_the_content(), 's:5:"param";s:9:"user_role"' ) !== false || strpos( get_the_content(), 's:5:"param";s:9:"user_form"' ) !== false ) :
						array_push( $acf_field_group_ids, get_the_ID() );
					endif;
				endwhile;
				wp_reset_postdata();
				foreach ( $acf_field_group_ids as $acf_field_group_id ) :
					$acf_fields = new \WP_Query(
						array(
							'post_type'   => 'acf-field',
							'post_parent' => $acf_field_group_id,
						)
					);
					while ( $acf_fields->have_posts() ) : $acf_fields->the_post();
						global $post;
						$fields[ $post->post_name ] = get_field_object( $post->post_name );
					endwhile;
					wp_reset_postdata();
				endforeach;
				// Get ACF 4 fields.
				$acf4_field_groups = new \WP_Query(
					array(
						'post_type' => 'acf',
					)
				);
				while ( $acf4_field_groups->have_posts() ) : $acf4_field_groups->the_post();
					$field_group_rules = get_post_meta( get_the_ID(), 'rule', true );
					if ( is_array( $field_group_rules ) && array_key_exists( 'param', $field_group_rules ) && 'ef_user' === $field_group_rules['param'] ) :
						$acf4_fields = get_post_custom( get_the_ID() );
						foreach ( $acf4_fields as $meta_key => $meta_value ) :
							if ( strpos( $meta_key, 'field_' ) === 0 ) :
								$meta_value          = unserialize( $meta_value[0] );
								$fields[ $meta_key ] = $meta_value;
							endif;
						endforeach;
					endif;
				endwhile;
				wp_reset_postdata();
				?>
				<optgroup label="ACF User Fields:">
					<?php foreach ( (array) $fields as $field => $field_object ) : ?>
						<option value="acf___<?php echo esc_attr( $field_object['key'] ); ?>"<?php selected( "acf___{$field_object['key']}" === $auth_settings_option ); ?>><?php echo esc_html( $field_object['label'] ); ?></option>
					<?php endforeach; ?>
				</optgroup>
			<?php endif; ?>
			<optgroup label="<?php esc_attr_e( 'All Usermeta:', 'authorizer' ); ?>">
				<?php
				foreach ( Helper::get_all_usermeta_keys() as $meta_key ) :
					if ( substr( $meta_key, 0, 3 ) === 'wp_' ) :
						continue;
					endif;
					?>
					<option value="<?php echo esc_attr( $meta_key ); ?>"<?php selected( $auth_settings_option === $meta_key ); ?>><?php echo esc_html( $meta_key ); ?></option>
				<?php endforeach; ?>
			</optgroup>
		</select>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_text_auth_advanced_users_per_page( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'advanced_users_per_page';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="" size="4" />
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_select_auth_advanced_users_sort_by( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'advanced_users_sort_by';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<select id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]">
			<option value="created" <?php selected( $auth_settings_option, 'created' ); ?>><?php esc_html_e( 'Date approved', 'authorizer' ); ?></option>
			<option value="email" <?php selected( $auth_settings_option, 'email' ); ?>><?php esc_html_e( 'Email', 'authorizer' ); ?></option>
			<option value="role" <?php selected( $auth_settings_option, 'role' ); ?>><?php esc_html_e( 'Role', 'authorizer' ); ?></option>
			<option value="date_added" <?php selected( $auth_settings_option, 'date_added' ); ?>><?php esc_html_e( 'Date registered', 'authorizer' ); ?></option>
		</select>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_select_auth_advanced_users_sort_order( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'advanced_users_sort_order';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<select id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]">
			<option value="asc" <?php selected( $auth_settings_option, 'asc' ); ?>><?php esc_html_e( 'Ascending', 'authorizer' ); ?></option>
			<option value="desc" <?php selected( $auth_settings_option, 'desc' ); ?>><?php esc_html_e( 'Descending', 'authorizer' ); ?></option>
		</select>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_checkbox_auth_advanced_widget_enabled( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'advanced_widget_enabled';
		$auth_settings_option = $options->get( $option, Helper::get_context( $args ), 'allow override', 'print overlay' );

		// Print option elements.
		?>
		<input type="checkbox" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="1"<?php checked( 1 === intval( $auth_settings_option ) ); ?> /><label for="auth_settings_<?php echo esc_attr( $option ); ?>"><?php esc_html_e( 'Show Dashboard Widget', 'authorizer' ); ?></label>
		<p class="description"><?php esc_html_e( 'Note: Only users with the create_users capability will be able to see the dashboard widget.', 'authorizer' ); ?></p>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_checkbox_auth_advanced_override_multisite( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'advanced_override_multisite';
		$auth_settings_option = $options->get( $option );

		// Don't print option if site administrators are prevented from overriding.
		if ( ! empty( $options->get( 'prevent_override_multisite', Helper::NETWORK_CONTEXT ) ) ) {
			?>
			(<?php esc_html_e( 'This setting is overridden by a', 'authorizer' ); ?> <a href="<?php echo esc_attr( network_admin_url( 'admin.php?page=authorizer' ) ); ?>"><?php esc_html_e( 'multisite option', 'authorizer' ); ?></a>.)
			<?php
			return;
		}

		// Print option elements.
		?>
		<input type="checkbox" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="1"<?php checked( 1 === intval( $auth_settings_option ) ); ?> /><label for="auth_settings_<?php echo esc_attr( $option ); ?>"><?php esc_html_e( "Configure this site independently (don't inherit any multisite settings)", 'authorizer' ); ?></label>
		<?php
	}
}
