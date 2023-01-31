# Authorizer

* WordPress Plugin: [https://wordpress.org/plugins/authorizer/][wp]
* Changelog: [https://github.com/uhm-coe/authorizer/blob/master/readme.txt][changelog]

*Authorizer* is a WordPress plugin that restricts access to specific users, typically students enrolled in a university course. It maintains a list of approved users that you can edit to determine who has access. It also replaces the default WordPress login/authorization system with one relying on an external server, such as Google, CAS, LDAP, or an OAuth2 provider. Finally, *Authorizer* lets you limit invalid login attempts to prevent bots from compromising your users' accounts.

*Authorizer* requires the following:

* **CAS server** or **LDAP server** (plugin needs the URL)
* PHP extensions: php-ldap, php-curl, php-dom

*Authorizer* provides the following options:

* **Authentication**: WordPress accounts; Google accounts; CAS accounts; LDAP accounts; OAuth2 accounts
* **Login Access**: All authenticated users (all local and all external can log in); Only specific users (all local and approved external users can log in)
* **View Access**: Everyone (open access); Only logged in users
* **Limit Login Attempts**: Progressively increase the amount of time required between invalid login attempts.
* **Shortcode**: Use the `[authorizer_login_form]` shortcode to embed a wp_login_form() outside of wp-login.php.

## Screenshots

![](assets/screenshot-1.png?raw=true "WordPress Login screen with Google Logins and CAS Logins enabled.")
![](assets/screenshot-2.png?raw=true "Authorizer Dashboard Widget.")
![](assets/screenshot-3.png?raw=true "Authorizer Options: Access Lists.")

[wp]: https://wordpress.org/plugins/authorizer/
[changelog]: https://github.com/uhm-coe/authorizer/blob/master/readme.txt
