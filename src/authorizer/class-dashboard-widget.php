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

/**
 * Builds the Dashboard widget.
 */
class Dashboard_Widget extends Singleton {

	/**
	 * Load Authorizer dashboard widget if it's enabled.
	 *
	 * Action: wp_dashboard_setup
	 */
	public function add_dashboard_widgets() {
		$options        = Options::get_instance();
		$widget_enabled = $options->get( 'advanced_widget_enabled', Helper::SINGLE_CONTEXT, 'allow override' ) === '1';

		// Load authorizer dashboard widget if it's enabled and user has permission.
		if ( current_user_can( 'create_users' ) && $widget_enabled ) {
			// Add dashboard widget for adding/editing users with access.
			wp_add_dashboard_widget( 'auth_dashboard_widget', __( 'Authorizer Settings', 'authorizer' ), array( $this, 'add_auth_dashboard_widget' ) );
		}
	}


	/**
	 * Render Authorizer dashboard widget (callback).
	 */
	public function add_auth_dashboard_widget() {
		$access_lists = Access_Lists::get_instance();
		$login_access = Login_Access::get_instance();

		// Get link to Authorizer options (for dashboard widget settings button).
		$options      = Options::get_instance();
		$admin_menu   = $options->get( 'advanced_admin_menu' );
		$settings_url = 'settings' === $admin_menu ? admin_url( 'options-general.php?page=authorizer&tab=access_lists' ) : admin_url( 'admin.php?page=authorizer&tab=access_lists' );
		?>
		<form method="post" id="auth_settings_access_form" action="">
			<?php $login_access->print_section_info_access_login(); ?>
			<div>
				<h2><?php esc_html_e( 'Pending Users', 'authorizer' ); ?></h2>
				<?php $access_lists->print_combo_auth_access_users_pending(); ?>
			</div>
			<br class="clear" />
			<div>
				<h2><?php esc_html_e( 'Approved Users', 'authorizer' ); ?></h2>
				<?php $access_lists->print_combo_auth_access_users_approved(); ?>
			</div>
			<br class="clear" />
			<div>
				<h2><?php esc_html_e( 'Blocked Users', 'authorizer' ); ?></h2>
				<?php $access_lists->print_combo_auth_access_users_blocked(); ?>
			</div>
			<br class="clear" />
		</form>
		<button type="button" class="handlediv js-toggle-auth_settings_dashboard_widget_control" aria-expanded="true" data-href="<?php echo esc_attr( $settings_url ); ?>">
			<span class="screen-reader-text"><?php esc_html_e( 'Settings', 'authorizer' ); ?></span>
			<span class="toggle-indicator" aria-hidden="true"></span>
		</button>
		<?php
	}

	/**
	 * Add scripts for dashboard widget.
	 *
	 * Action: admin_head-index.php
	 */
	public function widget_scripts() {
		?>
		<script type="text/javascript">
		/* <![CDATA[ */
		jQuery( function( $ ) {
			if ( $( '#auth_dashboard_widget' ).length ) {
				// Widget settings toggle.
				var toggle = $( '.js-toggle-auth_settings_dashboard_widget_control' );
				toggle.appendTo( '#auth_dashboard_widget .handle-actions' );
				toggle.click( function( e ) {
					e.preventDefault();
					e.stopImmediatePropagation();
					window.location.href = $( this ).data( 'href' );
				} );
			}
		} );
		/* ]]> */
		</script>
		<?php
	}
}
