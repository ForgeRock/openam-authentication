# openam-authentication plugin

## Warning
**This code is not supported by ForgeRock and it is your responsibility to verify that the software is suitable and safe for use.**

## About

Wordpress plugin to authenticate using OpenAM
<b>OpenAM Authentication</b>
<table border="0">
<tr><td>Contributors:</td><td>forgerock1, forgerock, marius-g, qcastel, bjornjohansen, degerstrom, vscheuber</td></tr>
<tr><td>Link:</td><td> http://www.forgerock.org/</td></tr>
<tr><td>Tags:</td><td> OpenAM, Authentication, REST, OpenAM 11.0.1, OpenAM 12.0, Wordpress 3.9 & 4.4.2</td></tr>
<tr><td>Requires at least:</td><td> 3.9</td></tr>
<tr><td>Tested up to:</td><td>4.7.5</td></tr>
<tr><td>Stable tag:</td><td>1.5</td></tr>
<tr><td>License:</td><td> CDDLv1.0</td></tr>
<tr><td>License URL</td><td>http://forgerock.org/cddlv1-0/</td></tr>
</table>
<br/>
<b>Description</b>
<br/>
Integrate Wordpress Authentication with OpenAM. Authenticates directly from the Wordpress login screen, without the need to redirect to OpenAM. If the authentication module or Service Chain configured requires only user and password, no redirection needed, otherwise the redirection is optional. Implements SSO if there is already a valid session in OpenAM in the same domain as the wordpress installation. Lightweight implementation using REST.
<br/>

<b>Contributing</b>
<br/>
The easiest way to contribute to this plugin is to submit a GitHub pull request. Here's the repo:
https://github.com/forgerock/openam-authentication
<br/>

<b>Installation</b>
<br/>
<ol>
<li> Upload the `openam-authentication` plugin directory to the `/wp-content/plugins/` directory
<li>Activate the plugin through the 'Plugins' menu in WordPress
<li>As a Wordpress administrator, go to the page 'Settings'>'OpenAM-REST Plugin' and configure your OpenAM parameters
</ol>

<b>Frequently Asked Questions</b>
<dl>
<dt>
What is it needed to make this plug-in work
<dd>
<ol>
<li>An OpenAM server up and running. It can be installed anywhere, as long as Wordpress can reach it. The OpenAM requires certain REST APIs, hence OpenAM 10.X and above is required.
<li> For versions of OpenAM 11.0 and older, the Legacy API mode will need to be enabled in the plugin
<li>Your wordpress installation up and running. This plug-in was written and tested for Wordpress 3.9.2 up to 4.4.2 but it might work with previous versions.
</ol>
<dt>
Do I need an OpenAM Policy Agent?
<dd>
No, a Policy Agent is not needed
<dt>
Does the Plug-In requires redirect to the OpenAM Login page?
<dd>Not necessarily. If the OpenAM Authentication module or Service chain you are using, does not require more credentials than user and password, then no redirect is necessary
<dd>
Redirection is optional and it is configurable from the settings page.  Redirection is recommended if your authentication is more complex, for example if you use multifactor authentication or your credentials are more than user and password.
<dt>
How does it implement SSO with OpenAM?
<dd>It looks for a session cookie in the domain where the WordPress is installed, if there is no such session cookie, then it will require to authenticate.  If the cookie is found with a session pointer valid, then the plugin will authenticate automatically to WordPress.
A proper cookie domain setting is necessary for SSO to work. You need to check with your OpenAM Administrator what domain is used to set the session cookie.
<dd>
Once the authentication has taken place, it will set the session in the cookie that you have configured in the plug-in (this is usually the same cookie as the one the OpenAM is using).

<dt>Does the plug-in logs me out from OpenAM when I logout from Wordpress?
<dd>Logging-out from OpenAM is optional. It is configurable by the administrator.
<dt>
Why did you write this plug-in?
<dd>We have implemented this plugin keeping in mind that the latest plugins are obsolete and were written for OpenSSO. They have not evolved, hence have become obsolete or unusable with the newest version of Wordpress. Also this plugin takes advantage of the REST interface in OpenAM and makes it lightweight.  
</dl>
<br>
<b>Screenshots</b>
<br>
<b>Changelog</b>
<dl>
<dt>
0.5
<dd>Initial drop
<dt>
0.6
<dd>A more advanced version than the initial drop.
<dd>Realm, Module, Service Chain are supported
<dd>Supports also redirect to OpenAM, if needed.
<dd>Optional global logout configurable
<dt>
0.9
<dd>
Clean some debug statements and updated the README.md
<dt>
1.0
<dd>First release in Wordpress plugins
<dt>1.0.1
<dd>
Updated user access to use roles and not levels
<dt>
1.1
<dd>Introduced the Legacy REST API mode to support OpenAM versions older than 11.0
<dd>An option to enable debugging and specify the name of the debug file was introduced
<dt>
1.2
<dd>Added an option to specify the domain where the SSO cookie will be set.
<dd>The uid and email address attribute name were hardcoded, now they are properly done.
<dd>Change a little bit the Options (Settings) page
<dt>
1.3
<dd>Enhancements to comply more with WordPress (SSO, Logout, codestyle, etc)
<dd>I18n (Transaltions are welcome)
<dd>Cookie Domain default option changed (Please learn about cookies and domains!)
<dd>Debugging enhancements
<dt>
1.4
<dd>New option to indicate what page to return in WordPress after successful OpenAM Login, when OpenAM Redirect has been enabled.
<dd>Cookie Domain default option fixed. The default now appears without the port component
<dt>
1.5
<dd>Fixes compatibility with OpenAM 5.X
</dl>
