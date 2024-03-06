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
 * Contains functions for rendering the Login Access tab in Authorizer Settings.
 */
class Login_Access extends \Authorizer\Singleton {

	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_section_info_access_login( $args = '' ) {
		?>
		<div id="section_info_access_login" class="section_info">
			<?php wp_nonce_field( 'save_auth_settings', 'nonce_save_auth_settings' ); ?>
			<p><?php esc_html_e( 'Choose who is able to log into this site below.', 'authorizer' ); ?></p>
		</div>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_radio_auth_access_who_can_login( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'access_who_can_login';
		$admin_mode           = Helper::get_context( $args );
		$auth_settings_option = $options->get( $option, $admin_mode, 'allow override', 'print overlay' );

		// If this site is configured independently of any multisite overrides (and
		// is not prevented from doing so), make sure we are not grabbing the
		// multisite value; otherwise, grab the multisite value to show behind the
		// disabled overlay.
		if ( is_multisite() && 1 === intval( $options->get( 'advanced_override_multisite' ) ) && empty( $options->get( 'prevent_override_multisite', Helper::NETWORK_CONTEXT ) ) ) {
			$auth_settings_option = $options->get( $option );
		} elseif ( is_multisite() && Helper::SINGLE_CONTEXT === $admin_mode && $options->get( 'multisite_override', Helper::NETWORK_CONTEXT ) === '1' ) {
			// Workaround: javascript code hides/shows other settings based
			// on the selection in this option. If this option is overridden
			// by a multisite option, it should show that value in order to
			// correctly display the other appropriate options.
			// Side effect: this site option will be overwritten by the
			// multisite option on save. Since this is a 2-item radio, we
			// determined this was acceptable.
			$auth_settings_option = $options->get( $option, Helper::NETWORK_CONTEXT );
		}

		// Print option elements.
		?>
		<fieldset>
			<label><input type="radio" id="radio_auth_settings_<?php echo esc_attr( $option ); ?>_external_users" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="external_users"<?php checked( 'external_users' === $auth_settings_option ); ?> /> <?php esc_html_e( 'All authenticated users (All external service users and all WordPress users)', 'authorizer' ); ?></label>
			<br>
			<label><input type="radio" id="radio_auth_settings_<?php echo esc_attr( $option ); ?>_approved_users" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="approved_users"<?php checked( 'approved_users' === $auth_settings_option ); ?> /> <?php esc_html_e( 'Only', 'authorizer' ); ?> <a href="javascript:chooseTab('access_lists' );" id="dashboard_link_approved_users"><?php esc_html_e( 'approved users', 'authorizer' ); ?></a> <?php esc_html_e( '(Approved external users and all WordPress users)', 'authorizer' ); ?></label>
		</fieldset>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_select_auth_access_role_receive_pending_emails( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'access_role_receive_pending_emails';
		$auth_settings_option = $options->get( $option );

		// Print option elements.
		?>
		<select id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]">
			<option value="---" <?php selected( $auth_settings_option, '---' ); ?>><?php esc_html_e( "None (Don't send notification emails)", 'authorizer' ); ?></option>
			<?php wp_dropdown_roles( $auth_settings_option ); ?>
		</select>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_wysiwyg_auth_access_pending_redirect_to_message( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'access_pending_redirect_to_message';
		$auth_settings_option = $options->get( $option );

		// Print option elements.
		wp_editor(
			wpautop( $auth_settings_option ),
			"auth_settings_$option",
			array(
				'media_buttons' => false,
				'textarea_name' => "auth_settings[$option]",
				'textarea_rows' => 5,
				'tinymce'       => true,
				'teeny'         => true,
				'quicktags'     => false,
			)
		);
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_wysiwyg_auth_access_blocked_redirect_to_message( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'access_blocked_redirect_to_message';
		$auth_settings_option = $options->get( $option );

		// Print option elements.
		wp_editor(
			wpautop( $auth_settings_option ),
			"auth_settings_$option",
			array(
				'media_buttons' => false,
				'textarea_name' => "auth_settings[$option]",
				'textarea_rows' => 5,
				'tinymce'       => true,
				'teeny'         => true,
				'quicktags'     => false,
			)
		);
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_checkbox_auth_access_should_email_approved_users( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'access_should_email_approved_users';
		$auth_settings_option = $options->get( $option );

		// Print option elements.
		?>
		<input type="checkbox" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="1"<?php checked( 1 === intval( $auth_settings_option ) ); ?> /><label for="auth_settings_<?php echo esc_attr( $option ); ?>"><?php esc_html_e( 'Send a welcome email when approving a new user', 'authorizer' ); ?></label>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_text_auth_access_email_approved_users_subject( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'access_email_approved_users_subject';
		$auth_settings_option = $options->get( $option );

		// Print option elements.
		?>
		<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="<?php echo esc_attr( $auth_settings_option ); ?>" placeholder="Welcome to [site_name]!" style="width:320px;" /><br /><small><?php echo wp_kses( __( 'You can use the <b>[site_name]</b> shortcode.', 'authorizer' ), Helper::$allowed_html ); ?></small>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_wysiwyg_auth_access_email_approved_users_body( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'access_email_approved_users_body';
		$auth_settings_option = $options->get( $option );

		// Print option elements.
		wp_editor(
			wpautop( $auth_settings_option ),
			"auth_settings_$option",
			array(
				'media_buttons' => false,
				'textarea_name' => "auth_settings[$option]",
				'textarea_rows' => 9,
				'tinymce'       => true,
				'teeny'         => true,
				'quicktags'     => false,
			)
		);
		?>
		<small>
			<?php
			printf(
				/* TRANSLATORS: 1: Shortcode for site name 2: Shortcode for site URL 3: Shortcode for user email */
				wp_kses( __( 'You can use %1$s, %2$s, and %3$s shortcodes.', 'authorizer' ), Helper::$allowed_html ),
				'<b>[site_name]</b>',
				'<b>[site_url]</b>',
				'<b>[user_email]</b>'
			);
			?>
		</small>
		<?php
	}
}
