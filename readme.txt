=== Authorizer ===
Contributors: figureone
Tags: cas, authentication, authorization, access, education, ldap, limit login attempts
Requires at least: 3.0.1
Tested up to: 3.9
Stable tag: trunk
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Authorizer limits login attempts, restricts access to specified users, and authenticates against external sources (e.g., LDAP, CAS).

== Description ==

*Authorizer* restricts access to a WordPress site to specific users, typically students enrolled in a university course. It maintains a list of approved users that you can edit to determine who has access. It also replaces the default WordPress login/authorization system with one relying on an external server, such as CAS or LDAP. Finally, *Authorizer* lets you limit invalid login attempts to prevent bots from compromising your users' accounts.

*Authorizer* requires the following:

* **CAS server** or **LDAP server** (plugin needs the URL)

*Authorizer* provides the following options:

* **Authentication**: Local (no CAS); Local first, then CAS; CAS-only (except for admins)
* **Access**: Everyone (all have access); University members (all local and all CAS); Specific users (all local and specific CAS)
* **Limit Login Attempts**: Progressively increase the amount of time required between invalid login attempts.

== Installation ==

1. Upload the `authorizer` directory to the `/wp-content/plugins/` directory
1. Activate the plugin through the 'Plugins' menu in WordPress
1. Specify your server details in the 'Settings' menu in WordPress

== Frequently Asked Questions ==

= Where is this plugin used? =

The [University of Hawai'i][uh], which provides authentication for student, faculty, and staff members via a centralized service (CAS or LDAP).

[uh]: http://hawaii.edu/

== Screenshots ==

1. Options screen.

== Changelog ==

= 1.1 =
* Rename to Authorizer
* Add LDAP support

= 1.0 =
* First stable release.

= 0.2 =
* Switch to CAS instead of LDAP/Sakai.
* Thu Jul 11, 2013

= 0.1 =
* Initial development build.
* Wed Apr 10, 2013

== Upgrade Notice ==

= 1.0 =
Upgrade now to get the latest features.
