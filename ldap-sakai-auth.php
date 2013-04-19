<?php
/*
Plugin Name: LDAP Sakai Authorization
Plugin URI: http://hawaii.edu/coe/dcdc/
Description: LDAP Sakai Authorization restricts access to students enrolled in university courses, using LDAP for authentication and Sakai for course rosters.
Version: 0.1
Author: Paul Ryan
Author URI: http://www.linkedin.com/in/paulrryan/
License: GPL2
*/
/*
Copyright 2013  Paul Ryan  (email : prar@hawaii.edu)

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License, version 2, as 
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
/*
Portions forked from Restricted Site Access plugin: http://10up.com/plugins/restricted-site-access-wordpress/
Portions forked from Simple LDAP Login: http://clifgriffin.com/2009/05/13/simple-ldap-login-13-for-wordpress/
*/


/**
 * Include adLDAP external library for ActiveDirectory connections.
 * @see http://adldap.sourceforge.net/download.php
 */
require_once(dirname(__FILE__) . '/inc/adLDAP/src/adLDAP.php');


/**
 * Define class for plugin: LDAP Sakai Auth.
 */
if (!class_exists('WP_Plugin_LDAP_Sakai_Auth')) {
  class WP_Plugin_LDAP_Sakai_Auth {
    
    /**
     * Constructor.
     */
    public function __construct() {
      //$adldap = new adLDAP();

      // Register filters.
      add_filter('authenticate', 'ldap_authenticate', 1, 3); // Custom wp authentication routine using LDAP
      add_filter("plugin_action_links_".plugin_basename(__FILE__), array($this, 'plugin_settings_link')); // Create settings link on Plugins page

      // Register actions.
      add_action('admin_menu', array($this, 'add_plugin_page')); // Create menu item in Settings
      add_action('admin_init', array($this, 'page_init')); // Create options page
      add_action('load-settings_page_ldap-sakai-auth', array($this, 'load_options_page')); // Enqueue javascript only on the plugin's options page
      add_action('wp_ajax_lsa_ip_check', array($this, 'ajax_lsa_ip_check')); // ajax IP verification check

    } // END __construct()


    /**
     * Plugin activation.
     */
    public function activate() {
      // Do nothing.
    } // END activate()


    /**
     * Plugin deactivation.
     */
    public function deactivate() {
      // Do nothing.
    } // END deactivate()


    /**
     ****************************
     * LDAP Authentication
     ****************************
     */


    /**
     * Authenticate using LDAP credentials.
     */
    public function ldap_authenticate($user, $username, $password) {
      // Pass through if already authenticated.
      if (is_a($user, 'WP_User')) {
        return $user;
      }
    }


    /**
     ****************************
     * Options page
     ****************************
     */


    /**
     * Add a link to this plugin's settings page from the WordPress Plugins page.
     * Called from "plugin_action_links" filter in __construct() above.
     */
    public function plugin_settings_link($links) {
      $settings_link = '<a href="options-general.php?page=ldap-sakai-auth">Settings</a>';
      array_unshift($links, $settings_link);
      return $links;
    } // END plugin_settings_link()


    /**
     * Create the options page under Dashboard > Settings
     * Run on action hook: admin_menu
     */
    public function add_plugin_page() {
      // @see http://codex.wordpress.org/Function_Reference/add_options_page
      add_options_page(
        'LDAP Sakai Authorization', // Page title
        'LDAP Sakai Auth', // Menu title
        'manage_options', // Capability
        'ldap-sakai-auth', // Menu slug
        array($this, 'create_admin_page') // function
      );
    }


    /**
     * Output the HTML for the options page
     */
    public function create_admin_page() {
      ?>
      <div class="wrap">
        <?php screen_icon(); ?>
        <h2>LDAP Sakai Authorization Settings</h2>
        <form method="post" action="options.php" autocomplete="off">
          <?php
            // This prints out all hidden settings fields
            // @see http://codex.wordpress.org/Function_Reference/settings_fields
            settings_fields('lsa_settings_group');
            // This prints out all the sections
            // @see http://codex.wordpress.org/Function_Reference/do_settings_sections
            do_settings_sections('ldap-sakai-auth');
          ?>
          <?php submit_button(); ?>
        </form>
      </div>
      <?php
    }


    /**
     * Load external resources on this plugin's options page.
     * Run on action hook: load-settings_page_ldap-sakai-auth
     */
    public function load_options_page() {
      wp_enqueue_script(
        'ldap-sakai-auth',
        plugin_dir_url(__FILE__) . 'ldap-sakai-auth.js',
        array('jquery-effects-shake'), '5.0', true
      );

      add_action('admin_notices', array($this, 'admin_notices')); // Add any notices to the top of the options page.
      add_action('admin_head', array($this, 'admin_head')); // Add help documentation to the options page.


      // @todo: copy this from restricted access plugin
      //$this->set_option_defaults();
    }


    /**
     * Add notices to the top of the options page.
     * Run on action hook chain: load-settings_page_ldap-sakai-auth > admin_notices
     * @todo: add warning messages.
     */
    public function admin_notices() {
      // Check for invalid settings combinations and show a warning message, e.g.:
      // if (sakai base url inaccessible) {
      //   print "<div class='updated settings-error'><p>Can't reach Sakai.</p></div>";
      // }
    }


    /**
     * Add help documentation to the options page.
     * Run on action hook chain: load-settings_page_ldap-sakai-auth > admin_head
     * @todo: add documentation.
     */
    public function admin_head() {
      $screen = get_current_screen();
      
      // Add help tab for LDAP Settings
      $screen->add_help_tab(array(
        'id' => 'help_lsa_settings_ldap',
        'title' => 'LDAP Settings',
        'content' => '
          <p><strong>LDAP Host</strong>: Enter the URL of the LDAP server you authenticate against.</p>
          <p><strong>LDAP Search Base</strong>: Enter the LDAP string that represents the search base, e.g., ou=people,dc=yourcompany,dc=com</p>
          <p><strong>LDAP Directory User</strong>: Enter the name of the LDAP user that has permissions to browse the directory.</p>
          <p><strong>LDAP Directory User Password</strong>: Enter the password for the LDAP user that has permission to browse the directory.</p>
          <p><strong>LDAP Installation type</strong>: Select whether your LDAP server is running an Active Directory-compatible LDAP instance, or an OpenLDAP-compatible instance.</p>
          <p><strong>Secure Connection (TLS)</strong>: Select whether all communication with the LDAP server should be performed over a TLS-secured connection.</p>
        ',
      ));

      // Add help tab for Sakai Settings

      // Add help tab for Access Settings      
    }


    /**
     * validate IP address entry on demand (AJAX)
     */
    public function ajax_lsa_ip_check() {
      if (empty($_POST['ip_address'])) {
        die('1');
      } else if ($this->is_ip(stripslashes($_POST['ip_address']))) {
        die; // success
      } else {
        die('1');
      }
    }

    /**
     * Is it a valid IP address? v4/v6 with subnet range
     */
    public function is_ip($ip_address) {
      // very basic validation of ranges
      if (strpos($ip_address, '/')) {
        $ip_parts = explode('/', $ip_address);
        if (empty($ip_parts[1]) || !is_numeric($ip_parts[1]) || strlen($ip_parts[1]) > 3)
          return false;
        $ip_address = $ip_parts[0];
      }

      // confirm IP part is a valid IPv6 or IPv4 IP
      if (empty($ip_address) || !inet_pton(stripslashes($ip_address)))
        return false;

      return true;
    }


    /**
     * Create sections and options
     * Run on action hook: admin_init
     */
    public function page_init() {
      // Create one setting that holds all the options (array)
      // @see http://codex.wordpress.org/Function_Reference/register_setting
      register_setting(
        'lsa_settings_group', // Option group
        'lsa_settings', // Option name
        array($this, 'sanitize_lsa_settings') // Sanitize callback
      );

      // @see http://codex.wordpress.org/Function_Reference/add_settings_section
      add_settings_section(
        'lsa_settings_ldap', // HTML element ID
        'LDAP Settings', // HTML element Title
        array($this, 'print_section_info_ldap'), // Callback (echos section content)
        'ldap-sakai-auth' // Page this section is shown on (slug)
      );

      // @see http://codex.wordpress.org/Function_Reference/add_settings_field
      add_settings_field(
        'lsa_settings_ldap_host', // HTML element ID
        'LDAP Host', // HTML element Title
        array($this, 'print_text_lsa_ldap_host'), // Callback (echos form element)
        'ldap-sakai-auth', // Page this setting is shown on (slug)
        'lsa_settings_ldap' // Section this setting is shown on
      );
      add_settings_field(
        'lsa_settings_ldap_search_base', // HTML element ID
        'LDAP Search Base', // HTML element Title
        array($this, 'print_text_lsa_ldap_search_base'), // Callback (echos form element)
        'ldap-sakai-auth', // Page this setting is shown on (slug)
        'lsa_settings_ldap' // Section this setting is shown on
      );
      add_settings_field(
        'lsa_settings_ldap_user', // HTML element ID
        'LDAP Directory User', // HTML element Title
        array($this, 'print_text_lsa_ldap_user'), // Callback (echos form element)
        'ldap-sakai-auth', // Page this setting is shown on (slug)
        'lsa_settings_ldap' // Section this setting is shown on
      );
      add_settings_field(
        'lsa_settings_ldap_password', // HTML element ID
        'LDAP Directory User Password', // HTML element Title
        array($this, 'print_password_lsa_ldap_password'), // Callback (echos form element)
        'ldap-sakai-auth', // Page this setting is shown on (slug)
        'lsa_settings_ldap' // Section this setting is shown on
      );
      add_settings_field(
        'lsa_settings_ldap_type', // HTML element ID
        'LDAP installation type', // HTML element Title
        array($this, 'print_radio_lsa_ldap_type'), // Callback (echos form element)
        'ldap-sakai-auth', // Page this setting is shown on (slug)
        'lsa_settings_ldap' // Section this setting is shown on
      );
      add_settings_field(
        'lsa_settings_ldap_tls', // HTML element ID
        'Secure Connection (TLS)', // HTML element Title
        array($this, 'print_checkbox_lsa_ldap_tls'), // Callback (echos form element)
        'ldap-sakai-auth', // Page this setting is shown on (slug)
        'lsa_settings_ldap' // Section this setting is shown on
      );

      // @see http://codex.wordpress.org/Function_Reference/add_settings_section
      add_settings_section(
        'lsa_settings_sakai', // HTML element ID
        'Sakai Settings', // HTML element Title
        array($this, 'print_section_info_sakai'), // Callback (echos section content)
        'ldap-sakai-auth' // Page this section is shown on (slug)
      );

      // @see http://codex.wordpress.org/Function_Reference/add_settings_field
      add_settings_field(
        'lsa_settings_sakai_base_url', // HTML element ID
        'Sakai Base URL', // HTML element Title
        array($this, 'print_text_lsa_sakai_base_url'), // Callback (echos form element)
        'ldap-sakai-auth', // Page this setting is shown on (slug)
        'lsa_settings_sakai' // Section this setting is shown on
      );

      // @see http://codex.wordpress.org/Function_Reference/add_settings_section
      add_settings_section(
        'lsa_settings_access', // HTML element ID
        'Access Settings', // HTML element Title
        array($this, 'print_section_info_access'), // Callback (echos section content)
        'ldap-sakai-auth' // Page this section is shown on (slug)
      );

      // @see http://codex.wordpress.org/Function_Reference/add_settings_field
      add_settings_field(
        'lsa_settings_access_restriction', // HTML element ID
        'Limit access to', // HTML element Title
        array($this, 'print_radio_lsa_access_restriction'), // Callback (echos form element)
        'ldap-sakai-auth', // Page this setting is shown on (slug)
        'lsa_settings_access' // Section this setting is shown on
      );
      add_settings_field(
        'lsa_settings_access_courses', // HTML element ID
        'Course Site IDs with access (one per line)', // HTML element Title
        array($this, 'print_textarea_lsa_access_courses'), // Callback (echos form element)
        'ldap-sakai-auth', // Page this setting is shown on (slug)
        'lsa_settings_access' // Section this setting is shown on
      );
      add_settings_field(
        'lsa_settings_access_redirect', // HTML element ID
        'Handle unauthorized visitors', // HTML element Title
        array($this, 'print_radio_lsa_access_redirect'), // Callback (echos form element)
        'ldap-sakai-auth', // Page this setting is shown on (slug)
        'lsa_settings_access' // Section this setting is shown on
      );
      add_settings_field(
        'lsa_settings_access_redirect_to_url', // HTML element ID
        'Redirect to URL', // HTML element Title
        array($this, 'print_text_lsa_access_redirect_to_url'), // Callback (echos form element)
        'ldap-sakai-auth', // Page this setting is shown on (slug)
        'lsa_settings_access' // Section this setting is shown on
      );
      add_settings_field(
        'lsa_settings_access_redirect_to_message', // HTML element ID
        'Restriction message', // HTML element Title
        array($this, 'print_wysiwyg_lsa_access_redirect_to_message'), // Callback (echos form element)
        'ldap-sakai-auth', // Page this setting is shown on (slug)
        'lsa_settings_access' // Section this setting is shown on
      );
      add_settings_field(
        'lsa_settings_access_redirect_to_page', // HTML element ID
        'Redirect to restricted notice page', // HTML element Title
        array($this, 'print_select_lsa_access_redirect_to_page'), // Callback (echos form element)
        'ldap-sakai-auth', // Page this setting is shown on (slug)
        'lsa_settings_access' // Section this setting is shown on
      );
      add_settings_field(
        'lsa_settings_access_ips', // HTML element ID
        'Unrestricted IP addresses', // HTML element Title
        array($this, 'print_combo_lsa_access_ips'), // Callback (echos form element)
        'ldap-sakai-auth', // Page this setting is shown on (slug)
        'lsa_settings_access' // Section this setting is shown on
      );
    }


    /**
     * Settings sanitizer callback
     * @todo: add sanitizer filters for the different options fields.
     */
    function sanitize_lsa_settings($lsa_settings) {
      // Sanitize LDAP Host setting
      if (filter_var($lsa_settings['ldap_host'], FILTER_SANITIZE_URL) === FALSE) {
        $lsa_settings['ldap_host'] = '';
      }
      // Obfuscate LDAP directory user password
      if (strlen($lsa_settings['ldap_password']) > 0) {
        // base64 encode the directory user password for some minor obfuscation in the database.
        $lsa_settings['ldap_password'] = base64_encode($this->encrypt($lsa_settings['ldap_password']));
      }
      // Default to "Everyone" access restriction
      if (!in_array($lsa_settings['access_restriction'], array("everyone", "university", "course"))) {
        $lsa_settings['access_restriction'] = "everyone";
      }
      // Sanitize ABC setting
      if (false) {
        $lsa_settings['somesetting'] = '';
      }

      return $lsa_settings;
    }


    /**
     * Settings print callbacks
     */
    function print_section_info_ldap() {
      print 'Enter your LDAP server settings below:';
    }
    function print_text_lsa_ldap_host($args) {
      $lsa_settings = get_option('lsa_settings');
      ?><input type="text" id="lsa_settings_ldap_host" name="lsa_settings[ldap_host]" value="<?php print $lsa_settings['ldap_host']; ?>" /><?php
    }
    function print_text_lsa_ldap_search_base($args) {
      $lsa_settings = get_option('lsa_settings');
      ?><input type="text" id="lsa_settings_ldap_search_base" name="lsa_settings[ldap_search_base]" value="<?php print $lsa_settings['ldap_search_base']; ?>" style="width:225px;" /><?php
    }
    function print_text_lsa_ldap_user($args) {
      $lsa_settings = get_option('lsa_settings');
      ?><input type="text" id="lsa_settings_ldap_user" name="lsa_settings[ldap_user]" value="<?php print $lsa_settings['ldap_user']; ?>" style="width:275px;" /><?php
    }
    function print_password_lsa_ldap_password($args) {
      $lsa_settings = get_option('lsa_settings');
      ?><input type="password" id="lsa_settings_ldap_password" name="lsa_settings[ldap_password]" value="<?php print $this->decrypt(base64_decode($lsa_settings['ldap_password'])); ?>" /><?php
    }
    function print_radio_lsa_ldap_type($args) {
      $lsa_settings = get_option('lsa_settings');
      ?><input type="radio" name="lsa_settings[ldap_type]" value="ad"<?php checked('ad' == $lsa_settings['ldap_type']); ?> /> Active Directory<br />
        <input type="radio" name="lsa_settings[ldap_type]" value="openldap"<?php checked('openldap' == $lsa_settings['ldap_type']); ?> /> OpenLDAP<?php
    }
    function print_checkbox_lsa_ldap_tls($args) {
      $lsa_settings = get_option('lsa_settings');
      ?><input type="checkbox" name="lsa_settings[ldap_tls]" value="1"<?php checked( 1 == $lsa_settings['ldap_tls'] ); ?> /> Use TLS<?php
    }

    function print_section_info_sakai() {
      print 'Enter your Sakai-based course management system settings below:';
    }
    function print_text_lsa_sakai_base_url($args) {
      $lsa_settings = get_option('lsa_settings');
      ?><input type="text" id="lsa_settings_sakai_base_url" name="lsa_settings[sakai_base_url]" value="<?php print $lsa_settings['sakai_base_url']; ?>" /><?php
    }

    function print_section_info_access() {
      print 'Choose how you want to restrict access to this site below:';
    }
    function print_radio_lsa_access_restriction($args) {
      $lsa_settings = get_option('lsa_settings');
      ?><input type="radio" id="radio_lsa_settings_access_restriction_everyone" name="lsa_settings[access_restriction]" value="everyone"<?php checked('everyone' == $lsa_settings['access_restriction']); ?> /> Everyone<br />
        <input type="radio" id="radio_lsa_settings_access_restriction_university" name="lsa_settings[access_restriction]" value="university"<?php checked('university' == $lsa_settings['access_restriction']); ?> /> University community<br />
        <input type="radio" id="radio_lsa_settings_access_restriction_course" name="lsa_settings[access_restriction]" value="course"<?php checked('course' == $lsa_settings['access_restriction']); ?> /> Students enrolled in specific course(s)<?php
    }
    // @todo: migrate this to a combo tool like below in Unrestricted IP addresses
    function print_textarea_lsa_access_courses($args) {
      $lsa_settings = get_option('lsa_settings');
      ?><textarea name="lsa_settings[access_courses]" cols="35" rows="5"><?php print $lsa_settings['access_courses']; ?></textarea><?php
      // If we have Sakai details, try to grab course details to display.
      if (strlen($lsa_settings['sakai_base_url'])) {
        ?><p><strong>Details for Site IDs entered above :</strong></p><?php
        $site_ids = explode(PHP_EOL, $lsa_settings['access_courses']);
        foreach ($site_ids as $site_id) {
          $course_name = 'asdf'; // @todo: get course name from sakai
          ?><p><?php print $course_name; ?> (<?php print $site_id; ?>)</p><?php
        }
      }
    }
    function print_radio_lsa_access_redirect($args) {
      $lsa_settings = get_option('lsa_settings');
      ?><input type="radio" id="radio_lsa_settings_access_redirect_to_login" name="lsa_settings[access_redirect]" value="login"<?php checked('login' == $lsa_settings['access_redirect']); ?> /> Send them to the WordPress login screen<br />
        <input type="radio" id="radio_lsa_settings_access_redirect_to_url" name="lsa_settings[access_redirect]" value="url"<?php checked('url' == $lsa_settings['access_redirect']); ?> /> Redirect them to a specific URL<br />
        <input type="radio" id="radio_lsa_settings_access_redirect_to_message" name="lsa_settings[access_redirect]" value="message"<?php checked('message' == $lsa_settings['access_redirect']); ?> /> Show them a simple message<br />
        <input type="radio" id="radio_lsa_settings_access_redirect_to_page" name="lsa_settings[access_redirect]" value="page"<?php checked('page' == $lsa_settings['access_redirect']); ?> /> Show them a specific WordPress page<?php
    }
    function print_text_lsa_access_redirect_to_url($args) {
      $lsa_settings = get_option('lsa_settings');
      ?><input type="text" id="lsa_settings_access_redirect_to_url" name="lsa_settings[access_redirect_to_url]" value="<?php print $lsa_settings['access_redirect_to_url']; ?>" placeholder="http://www.example.com/" /><?php
    }
    function print_wysiwyg_lsa_access_redirect_to_message($args) {
      $lsa_settings = get_option('lsa_settings');
      wp_editor($lsa_settings['access_redirect_to_message'], 'lsa_settings_access_redirect_to_message', array(
        'media_buttons' => false,
        'textarea_name' => 'lsa_settings[access_redirect_to_message]',
        'textarea_rows' => 5,
        'tinymce' => false,
      ));
    }
    function print_select_lsa_access_redirect_to_page($args) {
      $lsa_settings = get_option('lsa_settings');
      wp_dropdown_pages(array( 
        'selected' => $lsa_settings['access_redirect_to_page'],
        'show_option_none' => 'Select a page',
        'name' => 'lsa_settings[access_redirect_to_page]',
        'id' => 'lsa_settings_access_redirect_to_page',
      ));
    }
    function print_combo_lsa_access_ips($args) {
      $lsa_settings = get_option('lsa_settings');
      ?><ul id="list_lsa_settings_access_ips" style="margin:0;">
        <?php foreach ($lsa_settings['access_ips'] as $key => $ip): ?>
          <?php if (empty($ip)) continue; ?>
          <li>
            <input type="text" id="lsa_settings_access_ips_<?php print $key; ?>" name="lsa_settings[access_ips][]" value="<?php print esc_attr($ip); ?>" readonly="true" />
            <input type="button" class="button" id="remove_ip_<?php print $key; ?>" onclick="lsa_remove_ip(this);" value="Remove" />
          </li>
        <?php endforeach; ?>
      </ul>
      <div id="new_lsa_settings_access_ips">
        <input type="text" name="newip" id="newip" placeholder="127.0.0.1" />
        <input class="button" type="button" id="addip" onclick="lsa_add_ip(jQuery('#newip').val());" value="Add" />
        <label for="newip"><span class="description">Enter a single IP address or a range using a subnet prefix</span></label>
        <?php if (!empty($_SERVER['REMOTE_ADDR'])): ?>
          <br /><input class="button" type="button" onclick="lsa_add_ip('<?php print esc_attr($_SERVER['REMOTE_ADDR']); ?>');" value="Add My Current IP Address" /><br />
        <?php endif; ?>
      </div>
      <?php
    }

    /**
     ****************************
     * Helper functions
     ****************************
     */


    /**
     * Basic encryption using a public (not secret!) key. Used for general
     * database obfuscation of passwords.
     */
    private static $key = "8QxnrvjdtweisvCBKEY!+0";
    function encrypt($text) {
      return mcrypt_encrypt(MCRYPT_RIJNDAEL_256, self::$key, $text, MCRYPT_MODE_ECB, "abcdefghijklmnopqrstuvwxyz012345");
    }
    function decrypt($secret) {
      return rtrim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, self::$key, $secret, MCRYPT_MODE_ECB, "abcdefghijklmnopqrstuvwxyz012345"), "\0");
    }

  } // END class WP_Plugin_LDAP_Sakai_Auth
}

// Installation and uninstallation hooks.
register_activation_hook(__FILE__, array('WP_Plugin_LDAP_Sakai_Auth', 'activate'));
register_deactivation_hook(__FILE__, array('WP_Plugin_LDAP_Sakai_Auth', 'deactivate'));

// Instantiate the plugin class.
$wp_plugin_ldap_sakai_auth = new WP_Plugin_LDAP_Sakai_Auth();
