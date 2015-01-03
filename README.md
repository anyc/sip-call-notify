sip-call-notify
---------------

Rudimentary SIP client based on eXosip/osip that shows a small notification
on each incoming call using libnotify.

Author: Mario Kicherer (http://kicherer.org)  
License: GPL v2 (http://www.gnu.org/licenses/gpl-2.0.txt)

Modern wireless routers like a AVM FritzBox also include telephony features
like a DECT base station and VoIP connectivity. Consequently, an incoming
call can be routed to the DECT and VoIP phones in parallel. This tool acts
as a VoIP phone using the SIP protocol and just shows a small notification
for every incoming call. Hence, you can immediately see who is calling
without having to look for your DECT phone.

For an introduction into eXosip, see:
   http://www.antisip.com/doc/exosip2/modules.html

Usage example:
<code>
    sip-call-notify -s sip.server.com -u my_user -p my_password \
      -f "echo displayname: %s username: %s (From: %s)"
</code>