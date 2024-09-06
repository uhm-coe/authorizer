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
 * Contains functions for rendering the Public Access tab in Authorizer Settings.
 */
class Public_Access extends \Authorizer\Singleton {

	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_section_info_access_public( $args = '' ) {
		?>
		<div id="section_info_access_public" class="section_info">
			<p><?php esc_html_e( 'Choose your public access options here.', 'authorizer' ); ?></p>
		</div>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_radio_auth_access_who_can_view( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'access_who_can_view';
		$admin_mode           = Helper::get_context( $args );
		$auth_settings_option = $options->get( $option, $admin_mode, 'allow override', 'print overlay' );

		// If this site is configured independently of any multisite overrides (and
		// is not prevented from doing so), make sure we are not grabbing the
		// multisite value; otherwise, grab the multisite value to show behind the
		// disabled overlay.
		if ( is_multisite() && 1 === intval( $options->get( 'advanced_override_multisite' ) ) && empty( $options->get( 'prevent_override_multisite', Helper::NETWORK_CONTEXT ) ) ) {
			$auth_settings_option = $options->get( $option );
		} elseif ( is_multisite() && Helper::SINGLE_CONTEXT === $admin_mode && '1' === $options->get( 'multisite_override', Helper::NETWORK_CONTEXT ) ) {
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
			<label><input type="radio" id="radio_auth_settings_<?php echo esc_attr( $option ); ?>_everyone" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="everyone"<?php checked( 'everyone' === $auth_settings_option ); ?> /> <?php esc_html_e( 'Everyone can see the site', 'authorizer' ); ?></label>
			<br>
			<label><input type="radio" id="radio_auth_settings_<?php echo esc_attr( $option ); ?>_logged_in_users" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="logged_in_users"<?php checked( 'logged_in_users' === $auth_settings_option ); ?> /> <?php esc_html_e( 'Only logged in users can see the site', 'authorizer' ); ?></label>
		</fieldset>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_radio_auth_access_redirect( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'access_redirect';
		$auth_settings_option = $options->get( $option );

		// Print option elements.
		?>
		<fieldset>
			<label><input type="radio" id="radio_auth_settings_<?php echo esc_attr( $option ); ?>_to_login" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="login"<?php checked( 'login' === $auth_settings_option ); ?> /> <?php esc_html_e( 'Send them to the login screen', 'authorizer' ); ?></label>
			<br>
			<label><input type="radio" id="radio_auth_settings_<?php echo esc_attr( $option ); ?>_to_message" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="message"<?php checked( 'message' === $auth_settings_option ); ?> /> <?php esc_html_e( 'Show them the anonymous access message (below)', 'authorizer' ); ?></label>
		</fieldset>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_radio_auth_access_public_warning( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'access_public_warning';
		$auth_settings_option = $options->get( $option );

		// Print option elements.
		?>
		<fieldset>
			<label><input type="radio" id="radio_auth_settings_<?php echo esc_attr( $option ); ?>_no" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="no_warning"<?php checked( 'no_warning' === $auth_settings_option ); ?> /> <?php echo wp_kses( __( 'Show them the page <strong>without</strong> the anonymous access message', 'authorizer' ), Helper::$allowed_html ); ?></label>
			<br>
			<label><input type="radio" id="radio_auth_settings_<?php echo esc_attr( $option ); ?>" name="auth_settings[<?php echo esc_attr( $option ); ?>]" value="warning"<?php checked( 'warning' === $auth_settings_option ); ?> /> <?php echo wp_kses( __( 'Show them the page <strong>with</strong> the anonymous access message (marked up as a <a href="http://getbootstrap.com/components/#alerts-dismissible" target="_blank">Bootstrap Dismissible Alert</a>)', 'authorizer' ), Helper::$allowed_html ); ?></label>
		</fieldset>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_wysiwyg_auth_access_redirect_to_message( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'access_redirect_to_message';
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
	public function print_multiselect_auth_access_public_pages( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'access_public_pages';
		$auth_settings_option = $options->get( $option );
		$auth_settings_option = is_array( $auth_settings_option ) ? $auth_settings_option : array();

		$post_types = array_merge( array( 'page', 'post' ), get_post_types( array( '_builtin' => false ), 'names' ) );
		$post_types = is_array( $post_types ) ? $post_types : array();

		// Print option elements.
		?>
		<select id="auth_settings_<?php echo esc_attr( $option ); ?>" multiple="multiple" name="auth_settings[<?php echo esc_attr( $option ); ?>][]">
			<optgroup label="<?php esc_attr_e( 'Home', 'authorizer' ); ?>">
				<option value="home" <?php selected( in_array( 'home', $auth_settings_option, true ) ); ?>><?php esc_html_e( 'Home Page', 'authorizer' ); ?></option>
				<option value="auth_public_404" <?php selected( in_array( 'auth_public_404', $auth_settings_option, true ) ); ?>><?php esc_html_e( 'Nonexistent (404) Pages', 'authorizer' ); ?></option>
			</optgroup>
			<?php foreach ( $post_types as $post_type ) : ?>
				<optgroup label="<?php echo esc_attr( ucfirst( $post_type ) ); ?>">
				<?php
				$pages = get_posts(
					array(
						'post_type'      => $post_type,
						'posts_per_page' => 1000, // phpcs:ignore WordPress.WP.PostsPerPage.posts_per_page_posts_per_page
						// Disable caches to minimize memory footprint.
						'cache_results'          => false,
						'update_post_meta_cache' => false,
						'update_post_term_cache' => false,
						'update_menu_item_cache' => false,
					)
				);
				$pages = is_array( $pages ) ? $pages : array();
				foreach ( $pages as $page ) :
					?>
					<option value="<?php echo esc_attr( $page->ID ); ?>" <?php selected( in_array( strval( $page->ID ), $auth_settings_option, true ) ); ?>><?php echo esc_html( $page->post_title ); ?></option>
				<?php endforeach; ?>
				</optgroup>
			<?php endforeach; ?>
			<optgroup label="<?php esc_attr_e( 'Categories', 'authorizer' ); ?>">
				<?php foreach ( get_categories( array( 'hide_empty' => false ) ) as $category ) : ?>
					<option value="<?php echo esc_attr( 'cat_' . $category->slug ); ?>" <?php selected( in_array( 'cat_' . $category->slug, $auth_settings_option, true ) ); ?>><?php echo esc_html( $category->name ); ?></option>
				<?php endforeach; ?>
			</optgroup>
		</select>
		<?php
	}
}
