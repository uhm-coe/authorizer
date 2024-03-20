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
 * Contains functions for rendering the Access Lists tab in Authorizer Settings.
 */
class Access_Lists extends \Authorizer\Singleton {

	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_section_info_access_lists( $args = '' ) {
		$admin_mode = Helper::get_context( $args );
		?>
		<div id="section_info_access_lists" class="section_info">
			<p><?php esc_html_e( 'Manage who has access to this site using these lists.', 'authorizer' ); ?></p>
			<ol>
				<li><?php echo wp_kses( __( "<strong>Pending</strong> users are users who have successfully logged in to the site, but who haven't yet been approved (or blocked) by you.", 'authorizer' ), Helper::$allowed_html ); ?></li>
				<li><?php echo wp_kses( __( '<strong>Approved</strong> users have access to the site once they successfully log in.', 'authorizer' ), Helper::$allowed_html ); ?></li>
				<li><?php echo wp_kses( __( '<strong>Blocked</strong> users will receive an error message when they try to visit the site after authenticating.', 'authorizer' ), Helper::$allowed_html ); ?><br><?php esc_html_e( 'Note: if you want to block all email addresses from a domain, say anyone@example.com, simply add "@example.com" to the blocked list.', 'authorizer' ); ?></li>
			</ol>
		</div>
		<table class="form-table">
			<tbody>
				<tr>
					<th scope="row"><?php esc_html_e( 'Pending Users', 'authorizer' ); ?> <em>(<?php echo esc_html( $this->get_user_count_from_list( 'pending', $admin_mode ) ); ?>)</em></th>
					<td><?php $this->print_combo_auth_access_users_pending(); ?></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Approved Users', 'authorizer' ); ?> <em>(<?php echo esc_html( $this->get_user_count_from_list( 'approved', $admin_mode ) ); ?>)</em></th>
					<td><?php $this->print_combo_auth_access_users_approved(); ?></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Blocked Users', 'authorizer' ); ?> <em>(<?php echo esc_html( $this->get_user_count_from_list( 'blocked', $admin_mode ) ); ?>)</em></th>
					<td><?php $this->print_combo_auth_access_users_blocked(); ?></td>
				</tr>
			</tbody>
		</table>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_combo_auth_access_users_pending( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'access_users_pending';
		$auth_settings_option = $options->get( $option );
		$auth_settings_option = is_array( $auth_settings_option ) ? $auth_settings_option : array();

		// Render wrapper div (for aligning pager to width of content).
		?>
		<div class="wrapper_<?php echo esc_attr( $option ); ?>">
			<ul id="list_auth_settings_access_users_pending">
				<?php
				if ( count( $auth_settings_option ) > 0 ) :
					foreach ( $auth_settings_option as $key => $pending_user ) :
						if ( empty( $pending_user ) || count( $pending_user ) < 1 ) :
							continue;
						endif;
						$pending_user['is_wp_user'] = false;
						?>
						<li>
							<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>_<?php echo esc_attr( $key ); ?>" value="<?php echo esc_attr( $pending_user['email'] ); ?>" readonly="true" class="auth-email" />
							<select id="auth_settings_<?php echo esc_attr( $option ); ?>_<?php echo esc_attr( $key ); ?>_role" class="auth-role">
								<?php Helper::wp_dropdown_permitted_roles( $pending_user['role'] ); ?>
							</select>
							<a href="javascript:void(0);" class="button button-primary dashicons-before dashicons-insert" id="approve_user_<?php echo esc_attr( $key ); ?>" onclick="authAddUser( this, 'approved', false ); authIgnoreUser( this, 'pending' );" title="<?php esc_attr_e( 'Approve', 'authorizer' ); ?>"></a>
							<a href="javascript:void(0);" class="button button-primary dashicons-before dashicons-remove" id="block_user_<?php echo esc_attr( $key ); ?>" onclick="authAddUser( this, 'blocked', false ); authIgnoreUser( this, 'pending' );" title="<?php esc_attr_e( 'Block', 'authorizer' ); ?>"></a>
							<a href="javascript:void(0);" class="button button-secondary dashicons-before dashicons-no" id="ignore_user_<?php echo esc_attr( $key ); ?>" onclick="authIgnoreUser( this, 'pending' );" title="<?php esc_html_e( 'Remove user', 'authorizer' ); ?>" title="<?php esc_html_e( 'Ignore', 'authorizer' ); ?>"></a>
						</li>
					<?php endforeach; ?>
				<?php else : ?>
						<li class="auth-empty"><em><?php esc_html_e( 'No pending users', 'authorizer' ); ?></em></li>
				<?php endif; ?>
			</ul>
		</div>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_combo_auth_access_users_approved( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'access_users_approved';
		$admin_mode           = Helper::get_context( $args );
		$auth_settings_option = $options->get( $option, $admin_mode, 'no override' );
		$auth_settings_option = is_array( $auth_settings_option ) ? $auth_settings_option : array();

		// Get multisite approved users (will be added to top of list, greyed out).
		$auth_override_multisite        = $options->get( 'advanced_override_multisite' );
		$auth_multisite_settings        = $options->get_all( Helper::NETWORK_CONTEXT );
		$auth_settings_option_multisite = array();
		if (
			is_multisite() &&
			! is_network_admin() &&
			( 1 !== intval( $auth_override_multisite ) || ! empty( $auth_multisite_settings['prevent_override_multisite'] ) ) &&
			array_key_exists( 'multisite_override', $auth_multisite_settings ) &&
			'1' === $auth_multisite_settings['multisite_override']
		) {
			$auth_settings_option_multisite = $options->get( $option, Helper::NETWORK_CONTEXT, 'allow override' );
			$auth_settings_option_multisite = is_array( $auth_settings_option_multisite ) ? $auth_settings_option_multisite : array();
			// Add multisite users to the beginning of the main user array.
			foreach ( array_reverse( $auth_settings_option_multisite ) as $approved_user ) {
				$approved_user['multisite_user'] = true;
				array_unshift( $auth_settings_option, $approved_user );
			}
		}

		// Get default role for new user dropdown.
		$access_default_role = $options->get( 'access_default_role', Helper::SINGLE_CONTEXT, 'allow override' );

		// Get custom usermeta field to show.
		$advanced_usermeta = $options->get( 'advanced_usermeta' );

		// Adjust javascript function prefixes if multisite.
		$js_function_prefix      = Helper::NETWORK_CONTEXT === $admin_mode ? 'authMultisite' : 'auth';
		$is_multisite_admin_page = Helper::NETWORK_CONTEXT === $admin_mode;

		// Filter user list to search terms.
		// phpcs:ignore WordPress.Security.NonceVerification
		if ( isset( $_REQUEST['search'] ) && strlen( sanitize_text_field( wp_unslash( $_REQUEST['search'] ) ) ) > 0 ) {
			// phpcs:ignore WordPress.Security.NonceVerification
			$search_term          = sanitize_text_field( wp_unslash( $_REQUEST['search'] ) );
			$auth_settings_option = array_filter(
				$auth_settings_option,
				function ( $user ) use ( $search_term ) {
					return stripos( $user['email'], $search_term ) !== false ||
					stripos( $user['role'], $search_term ) !== false ||
					stripos( $user['date_added'], $search_term ) !== false;
				}
			);
		}

		// Sort user list.
		$sort_by        = $options->get( 'advanced_users_sort_by', Helper::SINGLE_CONTEXT, 'allow override' ); // email, role, date_added (registered), created (date approved).
		$sort_order     = $options->get( 'advanced_users_sort_order', Helper::SINGLE_CONTEXT, 'allow override' ); // asc or desc.
		$sort_dimension = array();
		if ( in_array( $sort_by, array( 'email', 'role', 'date_added' ), true ) ) {
			foreach ( $auth_settings_option as $key => $user ) {
				if ( 'date_added' === $sort_by ) {
					$sort_dimension[ $key ] = wp_date( 'Ymd', strtotime( $user[ $sort_by ] ) );
				} else {
					$sort_dimension[ $key ] = strtolower( $user[ $sort_by ] );
				}
			}
			$sort_order = 'asc' === $sort_order ? SORT_ASC : SORT_DESC;
			array_multisort( $sort_dimension, $sort_order, $auth_settings_option );
		} elseif ( 'created' === $sort_by && 'asc' !== $sort_order ) {
			// If default sort method and reverse order, just reverse the array.
			$auth_settings_option = array_reverse( $auth_settings_option );
		}

		// Ensure array keys run from 0..max (keys in database will be the original,
		// index, and removing users will not reorder the array keys of other users).
		$auth_settings_option = array_values( $auth_settings_option );

		// Get pager params.
		$total_users    = count( $auth_settings_option );
		$users_per_page = intval( $options->get( 'advanced_users_per_page', Helper::SINGLE_CONTEXT, 'allow override' ) );
		// phpcs:ignore WordPress.Security.NonceVerification
		$current_page = isset( $_REQUEST['paged'] ) ? intval( $_REQUEST['paged'] ) : 1;
		$total_pages  = ceil( $total_users / $users_per_page );
		if ( $total_pages < 1 ) {
			$total_pages = 1;
		}

		// Make sure current_page is between 1 and max pages.
		if ( $current_page < 1 ) {
			$current_page = 1;
		} elseif ( $current_page > $total_pages ) {
			$current_page = $total_pages;
		}

		// Render wrapper div (for aligning pager to width of content).
		?>
		<div class="wrapper_<?php echo esc_attr( $option ); ?>">
			<?php $this->render_user_pager( $current_page, $users_per_page, $total_users, 'top' ); ?>
			<ul id="list_auth_settings_access_users_approved" class="<?php echo strlen( $advanced_usermeta ) > 0 ? 'has-usermeta' : ''; ?>">
				<?php
				$offset = ( $current_page - 1 ) * $users_per_page;
				$max    = min( $offset + $users_per_page, count( $auth_settings_option ) );
				for ( $key = $offset; $key < $max; $key++ ) :
					$approved_user = $auth_settings_option[ $key ];
					if ( empty( $approved_user ) || count( $approved_user ) < 1 ) :
						continue;
					endif;
					$this->render_user_element( $approved_user, $key, $option, $admin_mode, $advanced_usermeta );
				endfor;
				?>
			</ul>

			<div id="new_auth_settings_<?php echo esc_attr( $option ); ?>">
				<textarea id="new_approved_user_email" placeholder="<?php esc_attr_e( 'email address', 'authorizer' ); ?>" class="auth-email new autogrow-short" rows="1"></textarea>
				<select id="new_approved_user_role" class="auth-role">
					<?php Helper::wp_dropdown_permitted_roles( $access_default_role, 'not disabled', $admin_mode ); ?>
				</select>
				<div class="btn-group">
					<a href="javascript:void(0);" class="btn button button-primary dashicons-before dashicons-insert button-add-user" id="approve_user_new" onclick="<?php echo esc_attr( $js_function_prefix ); ?>AddUser(this, 'approved' );"><?php esc_html_e( 'Approve', 'authorizer' ); ?></a>
					<button type="button" class="btn button button-primary dropdown-toggle dropdown-toggle-split" data-toggle="dropdown">
						<span class="caret"></span>
						<span class="sr-only"><?php esc_html_e( 'Toggle Dropdown', 'authorizer' ); ?></span>
					</button>
					<ul class="dropdown-menu" role="menu">
						<li><a href="javascript:void(0);" onclick="<?php echo esc_attr( $js_function_prefix ); ?>AddUser( document.getElementById( 'approve_user_new' ), 'approved', true);"><?php esc_html_e( 'Create a new WordPress account, and email the user an activation link.', 'authorizer' ); ?></a></li>
					</ul>
				</div>
			</div>
			<?php $this->render_user_pager( $current_page, $users_per_page, $total_users, 'bottom' ); ?>
		</div>
		<?php
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_combo_auth_access_users_blocked( $args = '' ) {
		// Get plugin option.
		$options              = Options::get_instance();
		$option               = 'access_users_blocked';
		$auth_settings_option = $options->get( $option );
		$auth_settings_option = is_array( $auth_settings_option ) ? $auth_settings_option : array();

		// Get default role for new blocked user dropdown.
		$access_default_role = $options->get( 'access_default_role', Helper::SINGLE_CONTEXT, 'allow override' );

		// Render wrapper div (for aligning pager to width of content).
		?>
		<div class="wrapper_<?php echo esc_attr( $option ); ?>">
			<ul id="list_auth_settings_<?php echo esc_attr( $option ); ?>">
				<?php
				foreach ( $auth_settings_option as $key => $blocked_user ) :
					if ( empty( $blocked_user ) || count( $blocked_user ) < 1 ) :
						continue;
					endif;
					$blocked_wp_user = get_user_by( 'email', $blocked_user['email'] );
					if ( $blocked_wp_user ) :
						$blocked_user['email']      = $blocked_wp_user->user_email;
						$blocked_user['role']       = array_shift( $blocked_wp_user->roles );
						$blocked_user['date_added'] = $blocked_wp_user->user_registered;
						$blocked_user['is_wp_user'] = true;
					else :
						$blocked_user['is_wp_user'] = false;
					endif;
					?>
					<li>
						<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>_<?php echo esc_attr( $key ); ?>" value="<?php echo esc_attr( $blocked_user['email'] ); ?>" readonly="true" class="auth-email" />
						<input type="text" id="auth_settings_<?php echo esc_attr( $option ); ?>_<?php echo esc_attr( $key ); ?>_date_added" value="<?php echo esc_attr( wp_date( 'M Y', strtotime( $blocked_user['date_added'] ) ) ); ?>" readonly="true" class="auth-date-added" />
						<a class="button dashicons-before dashicons-no" id="ignore_user_<?php echo esc_attr( $key ); ?>" onclick="authIgnoreUser( this, 'blocked' );" title="<?php esc_attr_e( 'Remove user', 'authorizer' ); ?>"></a>
					</li>
				<?php endforeach; ?>
			</ul>
			<div id="new_auth_settings_<?php echo esc_attr( $option ); ?>">
				<input type="text" id="new_blocked_user_email" placeholder="<?php esc_attr_e( 'email address', 'authorizer' ); ?>" class="auth-email new" />
				<select id="new_blocked_user_role" class="auth-role">
					<option value="<?php echo esc_attr( $access_default_role ); ?>"><?php echo esc_html( ucfirst( $access_default_role ) ); ?></option>
				</select>
				<a href="javascript:void(0);" class="button button-primary dashicons-before dashicons-remove button-add-user" id="block_user_new" onclick="authAddUser( this, 'blocked' );"><?php esc_html_e( 'Block', 'authorizer' ); ?></a>
			</div>
		</div>
		<?php
	}


	/**
	 * Renders the html elements for the pager above and below the Approved User list.
	 *
	 * @param  integer $current_page   Which page we are currently viewing.
	 * @param  integer $users_per_page How many users to show per page.
	 * @param  integer $total_users    Total count of users in list.
	 * @param  string  $which          Where to render the pager ('top' or 'bottom').
	 * @return void
	 */
	public function render_user_pager( $current_page = 1, $users_per_page = 20, $total_users = 0, $which = 'top' ) {
		$total_pages = ceil( $total_users / $users_per_page );
		if ( $total_pages < 1 ) {
			$total_pages = 1;
		}

		/* TRANSLATORS: %s: number of users */
		$output = ' <span class="displaying-num">' . sprintf( _n( '%s user', '%s users', $total_users, 'authorizer' ), number_format_i18n( $total_users ) ) . '</span>';

		$disable_first = $current_page <= 1;
		$disable_prev  = $current_page <= 1;
		$disable_next  = $current_page >= $total_pages;
		$disable_last  = $current_page >= $total_pages;

		$current_url = '';
		if ( isset( $_SERVER['HTTP_HOST'], $_SERVER['REQUEST_URI'] ) ) {
			$current_url = set_url_scheme( esc_url_raw( wp_unslash( $_SERVER['HTTP_HOST'] ) ) . esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) );
			$current_url = remove_query_arg( wp_removable_query_args(), $current_url );
		}

		$page_links = array();

		$total_pages_before = '<span class="paging-input">';
		$total_pages_after  = '</span></span>';

		if ( $disable_first ) {
			$page_links[] = '<span class="button disabled first-page tablenav-pages-navspan" aria-hidden="true">&laquo;</span>';
		} else {
			$page_links[] = sprintf(
				"<a class='button first-page' href='%s'><span class='screen-reader-text'>%s</span><span aria-hidden='true'>%s</span></a>",
				esc_url( remove_query_arg( 'paged', $current_url ) ),
				__( 'First page' ),
				'&laquo;'
			);
		}

		if ( $disable_prev ) {
			$page_links[] = '<span class="button disabled prev-page tablenav-pages-navspan" aria-hidden="true">&lsaquo;</span>';
		} else {
			$page_links[] = sprintf(
				"<a class='button prev-page' href='%s'><span class='screen-reader-text'>%s</span><span aria-hidden='true'>%s</span></a>",
				esc_url( add_query_arg( 'paged', max( 1, $current_page - 1 ), $current_url ) ),
				__( 'Previous page' ),
				'&lsaquo;'
			);
		}

		if ( 'bottom' === $which ) {
			$html_current_page  = '<span class="current-page-text">' . $current_page . '</span>';
			$total_pages_before = '<span class="screen-reader-text">' . __( 'Current Page' ) . '</span><span id="table-paging" class="paging-input"><span class="tablenav-paging-text">';
		} else {
			$html_current_page = sprintf(
				"%s<input class='current-page' id='current-page-selector' type='text' name='paged' value='%s' size='%d' aria-describedby='table-paging' /><span class='tablenav-paging-text'>",
				'<label for="current-page-selector" class="screen-reader-text">' . __( 'Current Page' ) . '</label>',
				$current_page,
				strlen( $total_pages )
			);
		}
		/* TRANSLATORS: %s: number of pages */
		$html_total_pages = sprintf( "<span class='total-pages'>%s</span>", number_format_i18n( $total_pages ) );
		/* TRANSLATORS: 1: number of current page 2: number of total pages */
		$page_links[] = $total_pages_before . sprintf( _x( '%1$s of %2$s', 'paging' ), $html_current_page, $html_total_pages ) . $total_pages_after;

		if ( $disable_next ) {
			$page_links[] = '<span class="button disabled next-page tablenav-pages-navspan" aria-hidden="true">&rsaquo;</span>';
		} else {
			$page_links[] = sprintf(
				"<a class='button next-page' href='%s'><span class='screen-reader-text'>%s</span><span aria-hidden='true'>%s</span></a>",
				esc_url( add_query_arg( 'paged', min( $total_pages, $current_page + 1 ), $current_url ) ),
				__( 'Next page' ),
				'&rsaquo;'
			);
		}

		if ( $disable_last ) {
			$page_links[] = '<span class="button disabled last-page tablenav-pages-navspan" aria-hidden="true">&raquo;</span>';
		} else {
			$page_links[] = sprintf(
				"<a class='button last-page' href='%s'><span class='screen-reader-text'>%s</span><span aria-hidden='true'>%s</span></a>",
				esc_url( add_query_arg( 'paged', $total_pages, $current_url ) ),
				__( 'Last page' ),
				'&raquo;'
			);
		}

		$pagination_links_class = 'pagination-links';
		$output                .= "\n<span class='$pagination_links_class'>" . join( "\n", $page_links ) . '</span>';

		$search_form = array();
		if ( 'top' === $which ) {
			// phpcs:ignore WordPress.Security.NonceVerification
			$search_term   = isset( $_REQUEST['search'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['search'] ) ) : '';
			$search_form[] = '<div class="search-box">';
			$search_form[] = '<label class="screen-reader-text" for="user-search-input">' . __( 'Search Users', 'authorizer' ) . '</label>';
			$search_form[] = '<input type="search" size="14" id="user-search-input" name="search" value="' . $search_term . '">';
			$search_form[] = '<input type="button" id="search-submit" class="button" value="' . __( 'Search', 'authorizer' ) . '">';
			$search_form[] = '</div>';
		}
		$search_form = join( "\n", $search_form );

		$output = "<div class='tablenav-pages'>$output</div>";
		?>
		<div class="tablenav">
			<?php echo wp_kses( $output, Helper::$allowed_html ); ?>
			<?php echo wp_kses( $search_form, Helper::$allowed_html ); ?>
		</div>
		<?php
	}


	/**
	 * Renders the html <li> element for a given user in a list.
	 *
	 * @param array  $approved_user     User array to render.
	 * @param int    $key               Index of user in list of users.
	 * @param string $option            List user is in (e.g., 'access_users_approved').
	 * @param string $admin_mode        Current admin context.
	 * @param string $advanced_usermeta Usermeta field to display.
	 * @return void
	 */
	public function render_user_element( $approved_user, $key, $option, $admin_mode, $advanced_usermeta ) {
		// Adjust javascript function prefixes if multisite.
		$js_function_prefix      = Helper::NETWORK_CONTEXT === $admin_mode ? 'authMultisite' : 'auth';
		$is_multisite_admin_page = Helper::NETWORK_CONTEXT === $admin_mode;

		$is_multisite_user = $is_multisite_admin_page || ( array_key_exists( 'multisite_user', $approved_user ) && ( true === $approved_user['multisite_user'] || 'true' === $approved_user['multisite_user'] ) );
		$option_prefix     = $is_multisite_user ? 'auth_multisite_settings_' : 'auth_settings_';
		$option_id         = $option_prefix . $option . '_' . $key;
		$approved_wp_user  = get_user_by( 'email', $approved_user['email'] );
		$is_current_user   = $approved_wp_user && get_current_user_id() === $approved_wp_user->ID;

		if ( ! $approved_wp_user ) :
			$approved_user['is_wp_user'] = false;

			// Check if this user (who doesn't yet have a WordPress user) has any
			// stored usermeta (from an admin adding it via the approved list).
			if ( ! empty( $approved_user['usermeta']['meta_key'] ) && ! empty( $advanced_usermeta ) ) :
				if ( strpos( $advanced_usermeta, 'acf___' ) === 0 && class_exists( 'acf' ) && str_replace( 'acf___', '', $advanced_usermeta ) === $approved_user['usermeta']['meta_key'] ) :
					// Get stored value for the user.
					$approved_user['usermeta'] = $approved_user['usermeta']['meta_value'];
				elseif ( $approved_user['usermeta']['meta_key'] === $advanced_usermeta ) :
					// Get regular usermeta value for the user.
					$approved_user['usermeta'] = $approved_user['usermeta']['meta_value'];
				endif;
				if ( is_array( $approved_user['usermeta'] ) || is_object( $approved_user['usermeta'] ) ) :
					$approved_user['usermeta'] = serialize( $approved_user['usermeta'] );
				endif;
			endif;

		else :
			$approved_user['is_wp_user'] = true;
			$approved_user['email']      = $approved_wp_user->user_email;
			$approved_user['role']       = $is_multisite_admin_page || count( $approved_wp_user->roles ) === 0 ? $approved_user['role'] : array_shift( $approved_wp_user->roles );
			$approved_user['date_added'] = $approved_wp_user->user_registered;

			// Get usermeta field from the WordPress user's real usermeta.
			if ( strlen( $advanced_usermeta ) > 0 ) :
				if ( strpos( $advanced_usermeta, 'acf___' ) === 0 && class_exists( 'acf' ) ) :
					// Get ACF Field value for the user.
					$approved_user['usermeta'] = get_field( str_replace( 'acf___', '', $advanced_usermeta ), 'user_' . $approved_wp_user->ID );
				else :
					// Get regular usermeta value for the user.
					$approved_user['usermeta'] = get_user_meta( $approved_wp_user->ID, $advanced_usermeta, true );
				endif;
				if ( is_array( $approved_user['usermeta'] ) || is_object( $approved_user['usermeta'] ) ) :
					$approved_user['usermeta'] = serialize( $approved_user['usermeta'] );
				endif;
			endif;
		endif;
		if ( ! array_key_exists( 'usermeta', $approved_user ) ) :
			$approved_user['usermeta'] = '';
		endif;
		?>
		<li>
			<input
				type="text"
				id="<?php echo esc_attr( $option_id ); ?>"
				value="<?php echo esc_attr( $approved_user['email'] ); ?>"
				readonly="true"
				class="<?php echo esc_attr( Helper::get_css_class_name_for_option( 'email', $is_multisite_user ) ); ?>"
			/>
			<select
				id="<?php echo esc_attr( $option_id ); ?>_role"
				class="<?php echo esc_attr( Helper::get_css_class_name_for_option( 'role', $is_multisite_user ) ); ?>"
				onchange="<?php echo esc_attr( $js_function_prefix ); ?>ChangeRole( this );"
				<?php if ( $is_multisite_user && ! $is_multisite_admin_page ) : ?>
					disabled="disabled"
				<?php endif; ?>
			>
				<?php $disable_input = $is_current_user ? 'disabled' : null; ?>
				<?php Helper::wp_dropdown_permitted_roles( $approved_user['role'], $disable_input, $admin_mode ); ?>
			</select>
			<input
				type="text"
				id="<?php echo esc_attr( $option_id ); ?>_date_added"
				value="<?php echo esc_attr( wp_date( 'M Y', strtotime( $approved_user['date_added'] ) ) ); ?>"
				readonly="true"
				class="<?php echo esc_attr( Helper::get_css_class_name_for_option( 'date-added', $is_multisite_user ) ); ?>"
			/>
			<?php
			if ( strlen( $advanced_usermeta ) > 0 ) :
				$should_show_usermeta_in_text_field = true; // Fallback renderer for usermeta; try to use a select first.
				if ( strpos( $advanced_usermeta, 'acf___' ) === 0 && class_exists( 'acf' ) ) :
					$field_object = get_field_object( str_replace( 'acf___', '', $advanced_usermeta ) );
					if ( is_array( $field_object ) && array_key_exists( 'type', $field_object ) && 'select' === $field_object['type'] ) :
						$should_show_usermeta_in_text_field = false;
						?>
						<select
							id="<?php echo esc_attr( $option_id ); ?>_usermeta"
							class="<?php echo esc_attr( Helper::get_css_class_name_for_option( 'usermeta', $is_multisite_user ) ); ?>"
							onchange="<?php echo esc_attr( $js_function_prefix ); ?>UpdateUsermeta( this );"
						>
							<option value=""<?php selected( empty( $approved_user['usermeta'] ) ); ?>><?php esc_html_e( '-- None --', 'authorizer' ); ?></option>
							<?php foreach ( $field_object['choices'] as $key => $labels ) : ?>
								<?php if ( is_array( $labels ) ) : // Handle ACF select with optgroups. ?>
									<optgroup label="<?php echo esc_attr( $key ); ?>">
								<?php else : ?>
									<?php $labels = array( $key => $labels ); ?>
								<?php endif; ?>
								<?php foreach ( $labels as $key => $label ) : ?>
									<option value="<?php echo esc_attr( $key ); ?>"<?php selected( $key === $approved_user['usermeta'] || ( isset( $approved_user['usermeta']['meta_value'] ) && $key === $approved_user['usermeta']['meta_value'] ) ); ?>><?php echo esc_html( $label ); ?></option>
								<?php endforeach; ?>
								<?php if ( is_array( $labels ) ) : ?>
									</optgroup>
								<?php endif; ?>
							<?php endforeach; ?>
						</select>
					<?php endif; ?>
				<?php endif; ?>
				<?php if ( $should_show_usermeta_in_text_field ) : ?>
					<input
						type="text"
						id="<?php echo esc_attr( $option_id ); ?>_usermeta"
						value="<?php echo esc_attr( $approved_user['usermeta'] ); ?>"
						class="<?php echo esc_attr( Helper::get_css_class_name_for_option( 'usermeta', $is_multisite_user ) ); ?>"
					/>
					<a class="button button-primary dashicons-before dashicons-edit update-usermeta" id="update_usermeta_<?php echo esc_attr( $key ); ?>" onclick="<?php echo esc_attr( $js_function_prefix ); ?>UpdateUsermeta( this );" title="Update usermeta"></a>
				<?php endif; ?>
			<?php endif; ?>

			<?php if ( $is_multisite_admin_page ) : // On multisite admin, render buttons: multisite user, ignore. ?>
				<a title="WordPress Multisite user" class="button disabled auth-multisite-user dashicons-before dashicons-admin-site"></a>
				<a class="button dashicons-before dashicons-no<?php echo $is_current_user ? ' invisible' : ''; ?>" id="ignore_user_<?php echo esc_attr( $key ); ?>" onclick="<?php echo esc_attr( $js_function_prefix ); ?>IgnoreUser(this, 'approved' );" title="<?php esc_attr_e( 'Remove user', 'authorizer' ); ?>"></a>
			<?php elseif ( $is_multisite_user ) : // On single site admin, but showing multisite user, render buttons: multisite user (x2). ?>
				<a title="WordPress Multisite user" class="button disabled auth-multisite-user dashicons-before dashicons-admin-site"></a>
				<a title="WordPress Multisite user" class="button disabled auth-multisite-user dashicons-before dashicons-admin-site"></a>
			<?php else : // On single site admin showing single site user, render buttons: block, ignore. ?>
				<a class="button button-primary dashicons-before dashicons-remove<?php echo $is_current_user ? ' invisible' : ''; ?>" id="block_user_<?php echo esc_attr( $key ); ?>" onclick="<?php echo esc_attr( $js_function_prefix ); ?>AddUser( this, 'blocked', false ); <?php echo esc_attr( $js_function_prefix ); ?>IgnoreUser( this, 'approved' );" title="<?php esc_attr_e( 'Block/Ban user', 'authorizer' ); ?>"></a>
				<a class="button dashicons-before dashicons-no<?php echo $is_current_user ? ' invisible' : ''; ?>" id="ignore_user_<?php echo esc_attr( $key ); ?>" onclick="<?php echo esc_attr( $js_function_prefix ); ?>IgnoreUser(this, 'approved' );" title="<?php esc_attr_e( 'Remove user', 'authorizer' ); ?>"></a>
			<?php endif; ?>
		</li>
		<?php
	}


	/**
	 * Helper function to get number of users (including multisite users)
	 * in a given list (pending, approved, or blocked).
	 *
	 * @param  string $user_list  List to get count of.
	 * @param  string $admin_mode Helper::SINGLE_CONTEXT or Helper::NETWORK_CONTEXT determines whether to include multisite users.
	 * @return int                Number of users in list.
	 */
	protected function get_user_count_from_list( $user_list, $admin_mode = Helper::SINGLE_CONTEXT ) {
		$options                    = Options::get_instance();
		$auth_settings_access_users = array();

		switch ( $user_list ) {
			case 'pending':
				$auth_settings_access_users = $options->get( 'access_users_pending', Helper::SINGLE_CONTEXT );
				break;
			case 'blocked':
				$auth_settings_access_users = $options->get( 'access_users_blocked', Helper::SINGLE_CONTEXT );
				break;
			case 'approved':
				if ( Helper::SINGLE_CONTEXT !== $admin_mode ) {
					// Get multisite users only.
					$auth_settings_access_users = $options->get( 'access_users_approved', Helper::NETWORK_CONTEXT );
				} elseif ( is_multisite() && 1 === intval( $options->get( 'advanced_override_multisite' ) ) && empty( $options->get( 'prevent_override_multisite', Helper::NETWORK_CONTEXT ) ) ) {
					// This site has overridden any multisite settings (and is not
					// prevented from doing so), so only get its users.
					$auth_settings_access_users = $options->get( 'access_users_approved', Helper::SINGLE_CONTEXT );
				} else {
					// Get all site users and all multisite users.
					$auth_settings_access_users = array_merge(
						$options->get( 'access_users_approved', Helper::SINGLE_CONTEXT ),
						$options->get( 'access_users_approved', Helper::NETWORK_CONTEXT )
					);
				}
		}

		return count( $auth_settings_access_users );
	}
}
