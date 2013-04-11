<?php
class lsa_options {
  public function __construct() {
    if (is_admin()) {
      add_action('admin_menu', array($this, 'add_plugin_page'));
      add_action('admin_init', array($this, 'page_init'));
    }
  }

  // Create the options page under Dashboard > Settings
  // Run on action hook: admin_menu
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

  // Output the HTML for the options page
  public function create_admin_page() {
    ?>
    <div class="wrap">
      <?php screen_icon(); ?>
      <h2>Settings</h2>
      <form method="post" action="options.php">
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

  // Create sections and options
  // Run on action hook: admin_init
  public function page_init() {
    // @see http://codex.wordpress.org/Function_Reference/add_settings_section
    add_settings_section(
      'lsa_settings_ldap', // HTML element ID
      'LDAP Settings', // HTML element Title
      array($this, 'print_section_info_ldap'), // Callback (echos section content)
      'ldap-sakai-auth' // Page this section is shown on (slug)
    );

    // @see http://codex.wordpress.org/Function_Reference/register_setting
    register_setting(
      'lsa_settings_group', // Option group
      'lsa_ldap_host', // Option name
      array($this, 'sanitize_lsa_ldap_host') // Sanitize callback
    );
    // @see http://codex.wordpress.org/Function_Reference/add_settings_field
    add_settings_field(
      'lsa_ldap_host', // HTML element ID
      'LDAP Directory Host', // HTML element Title
      array($this, 'print_text_lsa_ldap_host'), // Callback (echos form element)
      'ldap-sakai-auth', // Page this setting is shown on (slug)
      'lsa_settings_ldap' // Section this setting is shown on
    );
  }

  // Setting sanitizer callbacks
  function sanitize_lsa_ldap_host($input) {

  }

  // Setting print callbacks
  function print_section_info_ldap() {
    print 'Enter your LDAP server settings below:';
  }
  function print_text_lsa_ldap_host() {
    ?><input type="text" id="lsa_ldap_host" name="lsa_ldap_host" value="<?php get_option('lsa_ldap_host'); ?>" /><?php
  }
}

$lsa_options = new lsa_options();
