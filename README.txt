=== OpenAM Authentication ===
Contributors: forgerock1, forgerock, marius-g, qcastel, bjornjohansen, degerstrom, vscheuber
Link: http://www.forgerock.org/
Tags: OpenAM, Authentication, REST, OpenAM 11.0.1, OpenAM 12.0, OpenAM 13.0, Wordpress 3.9 & 4.4.2
Requires at least: 3.9
Tested up to: 4.7.5
Stable tag: 1.5
License: CDDLv1.0
License URI: https://forgerock.org/cddlv1-0/

Integrate Wordpress Authentication with OpenAM. Redirection to OpenAM is optional. SSO if there is already an active session.

== Description ==

Integrate Wordpress Authentication with OpenAM. Authenticates directly from the Wordpress login screen, without the need to redirect to OpenAM. If the authentication module or Service Chain configured requires only user and password, no redirection needed, otherwise the redirection is optional. Implements SSO if there is already a valid session in OpenAM in the same domain as the wordpress installation. Lightweight implementation using REST.


== Contributing ==
The easiest way to contribute to this plugin is to submit a GitHub pull request. Here's the repo:
https://github.com/forgerock/openam-authentication


== Installation ==

1. Upload `openam-wordpress-plugin` directory to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. As a Wordpress administrator, of to the page 'Settings'>'OpenAM-REST Plugin' and configure your OpenAM parameters

== Frequently Asked Questions ==
= What is it needed to make this plug-in work =
1. An OpenAM server up and running. It can be installed anywhere, as long as Wordpress can reach it. The OpenAM requires certain REST APIs, hence OpenAM 10.x and above is required.
2. Your wordpress installation up and running. This plug-in was written and tested for Wordpress 3.9.2 to 4.4.2, but it might work with previous versions.

= Do I need an OpenAM Policy Agent? =
No, a Policy Agent is not needed

= Does the Plug-In requires redirect to the OpenAM Login page? =
Not necessarily. If the OpenAM Authentication module or Service chain you are using, does not require more credentials than user and password, then no redirect is necessary

Redirection is optional and it is configurable from the settings page.  Redirection is recommended if your authentication is more complex, for example if you use multifactor authentication or your credentials are more than user and password.

= How does it implement SSO with OpenAM? =
It looks for a session cookie in the domain where the WordPress is installed, if there is no such session cookie, then it will require to authenticate.  If the cookie is found with a session pointer valid, then the plugin will authenticate automatically to WordPress.
A proper cookie domain setting is necessary for SSO to work. You need to check with your OpenAM Administrator what domain is used to set the session cookie.

Once the authentication has taken place, it will set the session in the cookie that you have configured in the plug-in (this is usually the same cookie as the one the OpenAM is using).

= Does the plug-in logs me out from OpenAM when I logout from Wordpress? =
Logging-out from OpenAM is optional. It is configurable by the administrator.

= Why did you write this plug-in? =
We have implemented this plugin keeping in mind that the latest plugins are obsolete and were written for OpenSSO. They have not evolved, hence have become obsolete or unusable with the newest version of Wordpress. Also this plugin takes advantage of the REST interface in OpenAM and makes it lightweight.

== Screenshots ==


== Changelog ==

= 0.5 =
* Initial drop

= 0.6 =
* A more advanced version than the initial drop.
* Realm, Module, Service Chain are supported
* Supports also redirect to OpenAM, if needed.
* Optional global logout configurable
= 0.9 =
Clean some debug statements and updated the README
= 1.0 =
First release in Wordpress plugins

= 1.0.1 =
Updated user access to use roles and not levels
= 1.1 =
* Introduced the Legacy REST API mode to support OpenAM versions older than 11.0
* An option to enable debugging and specify the name of the debug file was introduced
= 1.2 =
* Added an option to specify the domain where the SSO cookie will be set.
* The uid and email address attribute name were hardcoded, now they are properly done.
* Change a little bit the Options (Settings) page
= 1.3 =
* Enhancements to comply more with WordPress (SSO, Logout, codestyle, etc)
* I18n (Translations are welcome)
* Cookie Domain default option changed (Please learn about cookies and domains!)
* Debugging enhancements
= 1.4 =
* New option to indicate what page to return in WordPress after successful OpenAM Login, when OpenAM Redirect has been enabled.
* Cookie Domain default option fixed. The default now appears without the port component
= 1.5 =
* Fixes compatibility with OpenAM 5.X
