[![SnertSoft: We Serve Your Server](Img/logo-300x74.png)](http://software.snert.com/)


milter-spamc
============

Copyright 2003, 2024 by Anthony Howe.  All rights reserved.


WARNING
-------

THIS IS MAIL FILTERING SOFTWARE AND WILL BLOCK MAIL THAT FAILS TO PASS A GIVEN SET OF TESTS.  SNERTSOFT AND THE AUTHOR DO NOT ACCEPT ANY RESPONSIBLITY FOR MAIL REJECTED OR POSSIBLE LOSS OF BUSINESSS THROUGH THE USE OF THIS SOFTWARE.  BY INSTALLING THIS SOFTWARE THE CLIENT UNDERSTANDS AND ACCEPTS THE RISKS INVOLVED.


Description
-----------

[SpamAssassin](http://www.spamassassin.org/) is a well established free open-source mail classification tool, however it has no means by which to interface with [Sendmail](http://www.sendmail.org/).  `milter-spamc` provides such an interface between Sendmail and SpamAssassin.

By default `milter-spamc` sends the message headers and the first part of a message as given by `spamd-max-size` to the SpamAssassin spamd daemon for classification.  The result returned by SpamAssassin will be inserted as part of the message headers leaving the message body untouched.  If SpamAssassin thinks the message is spam, then `milter-spamc` will prefix the `Subject:` header with the `subject-tag` then send redirect or `Bcc:` a copy to the `mail-spam` collection address.

The headers inserted by `milter-spamc` are:

* `X-Spam-Flag`  Boolean "YES" or "NO" as to whether the message is spam.
* `X-Spam-Level`  Zero or more 'x' characters representing the message score.  Note that the choice of 'x' is intentional, since its a neutral character.  Asterisk, '*', and many other punctuation characters have special mean in regular expressions and some other pattern matching languages, that they can be error prone to scan for as literals.
* `X-Spam-Status`  A summary line stating "YES" or "NO", the message score, and the SpamAssassin spam threshold.
* `X-Spam-Report`  The report as returned by SpamAssassin.  It normally provides a summary of the rules triggered, their scores, and brief description.  The report format can be customised through SpamAssassin's `/etc/mail/spamassassin/local.cf` file.
* `X-Original-Recipient`  When a spam message is redirected to a collection address, one or more of these headers are added for each `RCPT` address given to Sendmail.  These headers can be used should there be a need to resend a message to the original recipients.
* `X-Scanned-By`  The milter name, version number, host name, host IP, and timestamp.  Note there might be multiple instances of this header, one for each participating scan milter, in which case they should represent the most recent to oldest, similar to `Received:` header behaviour.  This ordering is handled by Sendmail and not configurable.

*Please note that national privacy laws vary from country to country and that it may be illegal to scan or archive electronic correspondence, even for the purpose of filtering unsolicited bulk email.  It is the responsibility of businesses and system administrators to determine what are their rights with respect to electronic mail filtering in their country of residence.*


Usage
-----

        milter-spamc [options ...] [arguments ...]

Options can be expressed in four different ways.  Boolean options are expressed as `+option` or `-option` to turn the option on or off respectively.  Options that required a value are expressed as `option=value` or `option+=value` for appending to a value list.  Note that the `+option` and `-option` syntax are equivalent to `option=1` and `option=0` respectively.  Option names are case insensitive.

Some options, like `+help` or `-help`, are treated as immediate actions or commands.  Unknown options are ignored.  The first command-line argument is that which does not adhere to the above option syntax.  The special command-line argument `--` can be used to explicitly signal an end to the list of options.

The default options, as shown below, can be altered by specifying them on the command-line or within an option file, which simply contains command-line options one or more per line and/or on multiple lines.  Comments are allowed and are denoted by a line starting with a hash (#) character.  If the `file=` option is defined and not empty, then it is parsed first followed by the command-line options.

Note that there may be additional options that are listed in the option summary given by `+help` or `-help` that are not described here.


- - -
### access-db=/etc/mail/access.db

The type and location of the read-only access key-value map.  It provides a centralised means to black and white list hosts, domains, mail addresses, etc.  The following methods are supported:

        text!/path/map.txt                      R/O text file, memory hash
        /path/map.db                            Berkeley DB hash format
        db!/path/map.db                         Berkeley DB hash format
        db!btree!/path/map.db                   Berkeley DB btree format
        sql!/path/database                      An SQLite3 database
        socketmap!host:port                     Sendmail style socket-map
        socketmap!/path/local/socket            Sendmail style socket-map
        socketmap!123.45.67.89:port             Sendmail style socket-map
        socketmap![2001:0DB8::1234]:port        Sendmail style socket-map

If `:port` is omitted, the default is `7953`.

The `access-db` contains key-value pairs.  Lookups are performed from most to least specific, stopping on the first entry found.  Keys are case-insensitive.

An IPv4 lookup is repeated several times reducing the IP address by one octet from right to left until a match is found.

        tag:192.0.2.9
        tag:192.0.2
        tag:192.0
        tag:192

An IPv6 lookup is repeated several times reducing the IP address by one 16-bit word from right to left until a match is found.

        tag:2001:0DB8:0:0:0:0:1234:5678
        tag:2001:0DB8:0:0:0:0:1234
        tag:2001:0DB8:0:0:0:0
        tag:2001:0DB8:0:0:0
        tag:2001:0DB8:0:0
        tag:2001:0DB8:0:0
        tag:2001:0DB8:0
        tag:2001:0DB8
        tag:2001

A domain lookup is repeated several times reducing the domain by one label from left to right until a match is found.

        tag:[ipv6:2001:0DB8::1234:5678]
        tag:[192.0.2.9]
        tag:sub.domain.tld
        tag:domain.tld
        tag:tld
        tag:

An email lookup is similar to a domain lookup, the exact address is first tried, then the address's domain, and finally the local part of the address.

        tag:account@sub.domain.tld
        tag:sub.domain.tld
        tag:domain.tld
        tag:tld
        tag:account@
        tag:

If a key is found and is a milter specific tag (ie. `milter-spamc-Connect`, `milter-spamc-To`), then the value is processed as a pattern list and the result returned.  The Sendmail variants cannot have a pattern list.  A pattern list is a whitespace separated list of _pattern-action_ pairs followed by an optional default _action_.  The supported patterns are:

        [network/cidr]action            Classless Inter-Domain Routing
        !pattern!action                 Simple fast text matching.
        /regex/action                   POSIX Extended Regular Expressions

The CIDR will only ever match for IP address related lookups.

A `!pattern!` uses an astrisk (\*) for a wildcard, scanning over zero or more characters; a question-mark (?) matches any single character; a backslash followed by any character treats it as a literal (it loses any special meaning).

        !abc!           exact match for 'abc'
        !abc*!          match 'abc' at start of string
        !*abc!          match 'abc' at the end of string
        !abc*def!       match 'abc' at the start and match 'def' at the end, maybe with stuff in between.
        !*abc*def*!     find 'abc', then find 'def'

For black-white lookups, the following actions are recognised: `OK` or `RELAY` (allow), `REJECT` or `ERROR` (deny), `DISCARD` (accept & discard), `SKIP` or `DUNNO` (stop lookup, no result), and `NEXT` (opposite of `SKIP`, resume lookup).  Its possible to specify an empty action after a pattern, which is treated like `SKIP` returning an undefined result.  Other options may specify other actions.

Below is a list of supported tags.  Other options may specify additional tags.

        milter-spamc-Connect:client-ip          value           § Can be a pattern list.
        milter-spamc-Connect:[client-ip]        value           § Can be a pattern list.
        milter-spamc-Connect:client-domain      value           § Can be a pattern list.
        milter-spamc-Connect:                   value           § Can be a pattern list.
        Connect:client-ip                       value
        Connect:[client-ip]                     value
        Connect:client-domain                   value

All mail sent by a connecting _client-ip_, unresolved _client-ip_ address or IP addresses that resolve to a _client-domain_ are black or white-listed.  These allows you to white-list your network for mail sent internally and off-site, or connections from outside networks.  *Note that Sendmail also has special semantics for `Connect:` and untagged forms.*

        milter-spamc-Auth:auth_authen           value           § Can be a pattern list.
        milter-spamc-Auth:                      value           § Can be a pattern list.

All mail from the authenticated sender, as given by sendmail's `{auth_authen}` macro, is black or white-listed.  The string searched by the pattern list will be the sender-address.  The empty form of `milter-spamc-Auth:` allows for a milter specific default only when `{auth_authen}` is defined.

        milter-spamc-From:sender-address        value           § Can be a pattern list.
        milter-spamc-From:sender-domain         value           § Can be a pattern list.
        milter-spamc-From:sender@               value           § Can be a pattern list.
        milter-spamc-From:                      value           § Can be a pattern list.
        From:sender-address                     value
        From:sender-domain                      value
        From:sender@                            value

All mail from the _sender-address_, _sender-domain_, or that begins with _sender_ is black or white-listed.  In the case of a _+detailed_ email address, the left hand side of the _+detail_ is used for the _sender@_ lookup.  *Note that Sendmail also has special semantics for From: and untagged forms.*

        milter-spamc-To:recipient-address       value           § Can be a pattern list.
        milter-spamc-To:recipient-domain        value           § Can be a pattern list.
        milter-spamc-To:recipient@              value           § Can be a pattern list.
        milter-spamc-To:                        value           § Can be a pattern list.
        Spam:recipient-address                  value           (FRIEND or HATER are recognised)
        Spam:recipient-domain                   value           (FRIEND or HATER are recognised)
        Spam:recipient@                         value           (FRIEND or HATER are recognised)
        To:recipient-address                    value
        To:recipient-domain                     value
        To:recipient@                           value

All mail to the _recipient-address_, _recipient-domain_, or that begins with _recipient_ is black or white-listed.  In the case of a _+detailed_ email address, the left hand side of the _+detail_ is used for the _recipient@_ lookup.  *Note that Sendmail also has special semantics for `Spam:`, `To:`, and untagged forms.*

The `milter-spamc-Connect:` and `milter-spamc-To:` tags provide a milter specific means to override the Sendmail variants.  For example, you normally white list your local network through any and all milters, but on the odd occasion you might want to actually scan mail from inside going out, without removing the `Connect:` tag that allows Sendmail to relay for your network or white listing for other milters.  So for example if you have Sendmail tags like:

        To:mx.example.com                       RELAY

You might have to add milter specific overrides in order to make sure the mail still gets filtered:

        To:mx.example.com                       RELAY
        milter-spamc-To:mx.example.com          SKIP

Some additional examples:

        milter-spamc-Connect:80.94              [80.94.96.0/20]OK REJECT

Accept connections from the netblock 80.94.96.0/20 (80.94.96.0 through to 80.94.111.255) and rejecting anything else in 80.94.0.0/16.

        milter-spamc-Connect:192.0.2            /^192\.0\.2\.8[0-9]/OK REJECT

Accept connections from 192.0.2.80 through to 192.0.2.89, reject everything else in 192.0.2.0/24.

        milter-spamc-To:example.com             /^john@.+/OK /^fred\+.*@.*/OK REJECT

Accept mail to <john@example.com> and <fred@example.com> when fred's address contains a plus-detail in the address.  Reject everything else to example.com.

        milter-spamc-To:example.net             !*+*@*!REJECT !*.smith@*!REJECT /^[0-9\].*/REJECT

Reject mail to example.net using a plus-detail address or to any user who's last name is "smith" or addresses starting with a digit.  No default given, so B/W processing would continue.

Normally when the _access.db_ lookup matches a milter tag, then the _value_ pattern list is processed and there are no further _access.db_ lookups.  The `NEXT` action allows the _access.db_ lookups to resume and is effectively the opposite of `SKIP`.  Consider the following examples:

        milter-spamc-To:com                     /@com/REJECT  NEXT
        To:com                                  OK

Reject mail to places like _compaq.com_ or _com.com_ if the pattern matches, but resume the _access.db_ lookups otherwise.

        milter-spamc-To:aol.com                 /^[a-zA-Z0-9!#$&'*+=?^_`{|}~.-]{3,16}@aol.com$/NEXT REJECT
        To:fred@aol.com                         OK

AOL local parts are between 3 and 16 characters long and can contain dots and RFC 2822 atext characters except `%` and `/`.  The `NEXT` used above allows one simple regex to validate the format of the address and resume lookups of white listed and/or black listed addresses.


- - -
### +daemon

Start as a background daemon or foreground application.


- - -
### -discard-low-precedence

Discard instead of reject if Precedence is `list' or lower.


- - -
### extra-discard=-1

If the spam score returned by spamd exceeds the threshold required_hits by this many points, then discard the message.  If the score is less than threshold plus `extra-discard`, the message will be tagged or rejected depending on the value of `extra-reject`.  Specify -1 to disable discards; 0 to discard all spam.

- - -
### extra-reject=-1

If the spam score returned by spamd exceeds the threshold `required_hits` by this many points, then reject the message.  If the score is less than threshold plus `extra-reject`, then message will be tagged.  Specify -1 to disable rejections and perform subject tagging only; 0 to reject all spam.


- - -
### file=/etc/mail/milter-spamc.cf

Read the option file before command line options.  This option is set by default.  To disable the use of an option file, simply say `file=''`.


- - -
### -help or +help

Write the option summary to standard output and exit.  The output is suitable for use as an option file.


- - -
### -is-gateway

The server is a mail gateway.  If the `{rcpt_host}` macro passed by Sendmail is an address-literal that is a local-use IP address defined by RFC 3330 or 3513 (10.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/24, FE80::0/10 FEC0::0/10), then spamd is given the local-part before the at-sign (@) to select spamd user preferences.  See also `no-user-config`.

- - -
### mail-archive=
Copy all mail, whether spam or not, to the given email address for archiving.


- - -
### mail-format=
When `mail-policy=redirect` and all the recipients are local accounts, then each email address is reformated according to the format string.  If some or none of the recipients are local, then mail is instead redirected to `mail-spam` address.  See additional commentary.

A `format-path` string comprises of literal characters and percent-sign (%) prefixed format characters:

        %%              A literal percent-sign (%)
        %A              The original address, equivalent of %T%P@%D.
        %D              The domain name portion.
        %L              The left-hand-side of a plus-detailed address or the local part.
        %P              The local-part. If %R is not empty then "%L+%R" else "%L".
        %R              The right-hand-side of a plus-detailed address or the empty string.
        %S              The source-route, ie "@A,@B,@C", or the empty string.
        %T              If %S is not empty, then "%S:" else the empty string.

Some examples:

        Address                         Format          Result
        user@example.com                %T%P@%D         user@example.com
        user+detail@example.com         %P@%D           user+detail@example.com
        user+detail@example.com         %L+bulk@%D      user+bulk@example.com
        user+detail@example.com         bulk+%L@%D      bulk+user@example.com
        user+detail@example.com         bulk+%R@%D      bulk+detail@example.com
        user+detail@example.com         %P@bulk.%D      user+detail@bulk.example.com
        @A,@B:user@example.com          %T%P@bulk.%D    @A,@B:user@bulk.example.com

Note `+detailed` local-parts is a Sendmail convention supported by some 3rd party mail delivery software, such as procmail, Cyrus IMAP, maybe others.  Therefore please make sure your delivery agent understands this technique before using a `+detailed` local-part.  You will require the `FEATURE(`preserve_local_plus_detail')` be specified in your `sendmail.mc` file to enable it.  See The Bat Book 3ed, § 4.8.35, § 12.4.4.


- - -
### mail-ham=

Copy good clean mail to the given mail address.


- - -
### mail-spam=

This is the email address of a spam collection box.  See `mail-policy`.


- - -
### mail-policy=none

This policy specifies what to do with junk mail that is not going to be rejected or discarded.  Specify one of `none`, `copy`, or `redirect`.  The `mail-spam` address will then be used.


- - -
### max-untrusted=-1

This option limits the number of untrusted (not white-listed) recipients that can be specified for any one message.  When this limit is exceeded, all further recipients will be rejected.  Specify -1 to disable (ie. no limit).


- - -
### milter-socket=unix:/var/run/milter/milter-spamc.socket

A socket specifier used to communicate between Sendmail and `milter-spamc`.  Typically a unix named socket or a host:port.  This value must match the value specified for the `INPUT_MAIL_FILTER()` macro in the sendmail.mc file.  The accepted syntax is:

        {unix|local}:/path/to/file              A named pipe. (default)
        inet:port@{hostname|ip-address}         An IPV4 socket.
        inet6:port@{hostname|ip-address}        An IPV6 socket.


- - -
### milter-timeout=7210

The sendmail/milter I/O timeout in seconds.


- - -
### -no-user-config

Disable spamd user configurations and always use the default `spamd-user`.


- - -
### pid-file=/var/run/milter/milter-spamc.pid

The file path of where to save the process-id.

- - -
### -quit or +quit

Quit an already running instance of the milter and exit.  This is equivalent to:

        kill -QUIT `cat /var/run/milter/milter-spamc.pid`.

- - -
### +received-spf-headers

Add `Received-SPF:` trace headers with results of `HELO` and `MAIL FROM:` checks.  There may be multiple instances of this header, one for each participating mail server, in which case they represent the most recent to oldest, similar to the way `Received:` headers are added.  This ordering is handled by Sendmail and not configurable.


- - -
### -restart or +restart

Terminate an already running instance of the milter before starting.


- - -
### run-group=milter

The process runtime group name to be used when started by root.


- - -
### run-user=milter

The process runtime user name to be used when started by root.


- - -
### spamd-command=REPORT

Specify one of `CHECK`, `REPORT_IFSPAM`, or `REPORT` to check the message for spam and never generate a report, generate a report if spam, or always generate a report respectively.  When the report is generated, then the `X-Spam-Report:` header is added to the message with the contents of the report.


- - -
### spamd-max-size=64

The maximum number of kilobytes to pass to spamd.  The default is one body chunk, typically 64KB.  Specify 0 for unlimited.  For efficiency, normally only the first body chunk is passed, however some sites might prefer more accuracy instead of speed.


- - -
### spamd-socket=127.0.0.1,783

The unix domain socket or internet `host[,port]` of the spamd server.  Note when a unix domain socket is given, then it must be read/write by both spamd and `milter-spamc`.


- - -
### spamd-timeout=120

The milter/spamd I/O timeout in seconds; 0 for indefinite.


- - -
### spamd-user=

The default user account used for message processing by spamd when no local user account can be determined or if there is more than one recipient.


- - -
### subject-tag=[SPAM]

Subject tag prefix for invalid messages.  To disable the subject tag specify `subject-tag=''`.


- - -
### -subject-tag-score

Append the score and threshold to the subject tag prefix for spam messages.  See `subject-tag`.


- - -
### verbose=info

A comma separated list of how much detail to write to the mail log.  Those mark with `§` have meaning for this milter.

        §  all          All messages
        §  0            Log nothing.
        §  info         General info messages. (default)
        §  trace        Trace progress through the milter.
        §  parse        Details from parsing addresses or special strings.
        §  debug        Lots of debug messages.
        §  dialog       I/O from Communications dialog
           state        State transitions of message body scanner.
           dns          Trace & debug of DNS operations
           cache        Cache get/put/gc operations.
        §  database     Sendmail database lookups.
        §  socket-fd    socket open & close calls
        §  socket-all   All socket operations & I/O
        §  libmilter    libmilter engine diagnostics


- - -
### work-dir=/var/tmp

The working directory of the process.  Normally serves no purpose unless the kernel option that permits daemon process core dumps is set.


SMTP Responses
--------------

This is the list of possible SMTP responses.

* 550 5.7.1 message was identified as junk mail  
  When the `extra-reject` is used, this response is returned as the final result after the message content, if the message is identified as spam.

* 553 5.1.0 imbalanced angle brackets in path  
  The path given for a `MAIL` or `RCPT` command is missing a closing angle bracket

* 553 5.1.0 address does not conform to RFC 2821 syntax  
  The address is missing the angle brackets, `<` and `>`, as required by the RFC grammar.

* 553 5.1.0 local-part too long  
  The stuff before the `@` is too long.

* 553 5.1.[37] invalid local part  
  The stuff before the `@` sign contains unacceptable characters.

* 553 5.1.0 domain name too long  
  The stuff after the `@` is too long.

* 553 5.1.7 address incomplete  
  Expecting a domain.tld after the `@` sign and found none.

* 553 5.1.[37] invalid domain name  
  The domain after the `@` sign contains unacceptable characters.

* 451 4.4.3 HELO .+ from .+ SPF result .+: .*  
  There was a DNS lookup error for the `HELO` argument.  See `helo-policy=` option

* 452 4.5.3 too many untrusted recipients  
  The number of untrusted recipients was reached.  See `max-untrusted`.


Build & Install
---------------

* Install `SQLite` from a package if desired.  Prior to [LibSnert's](https://github.com/SirWumpus/libsnert) availability on GitHub, the old `libsnert` tarballs included SQLite, but the GitHub [libsnert](https://github.com/SirWumpus/libsnert) repository does not, so it needs to be installed separately.   `milter-spamc` does not require it, but other milters that need a cache will.

* If you have never built a milter for Sendmail, then please make sure that you build and install `libmilter` (or install a pre-built package), which is _not_ built by default when you build Sendmail.  Please read the `libmilter` documentation.  Briefly, it should be something like this:

        cd (path to)/sendmail-8.13.6/libmilter
        sh Build -c install

* [Build LibSnert](https://github.com/SirWumpus/libsnert#configuration--build) first, do *not* disable `sqlite3` support; it should find the pre-installed version of SQLite if any.

* Building `milter-spamc` should be:

        cd com/snert/src
        git clone https://github.com/SirWumpus/milter-spamc.git
        cd milter-spamc
        ./configure --help
        ./configure
        make
        sudo make install

* An example `/usr/local/share/examples/milter-spamc/milter-spamc.mc` is supplied.  This file should be reviewed and the necessary elements inserted into your Sendmail `.mc` file and `sendmail.cf` rebuilt.  Please note the comments on the general milter flags.

* Once installed and configured, start `milter-spamc` and then restart Sendmail.  An example startup script is provided in `/usr/local/share/examples/milter-spamc/milter-spamc.sh`.


Notes
-----

* The minimum desired file ownership and permissions are as follows for a typical Linux system.  For FreeBSD, NetBSD, and OpenBSD the binary and cache locations may differ, but have the same permissions.  Process user `milter` is primary member of group `milter` and secondary member of group `smmsp`.  Note that the milter should be started as `root`, so that it can create a _.pid file_ and _.socket file_ in `/var/run`; after which it will switch process ownership to `milter:milter` before starting the accept socket thread.

        /etc/mail/                              root:smmsp      0750 drwxr-x---
        /etc/mail/access.db                     root:smmsp      0640 -rw-r-----
        /etc/mail/sendmail.cf                   root:smmsp      0640 -rw-r-----
        /etc/mail/milter-spamc.cf               root:root       0644 -rw-r--r--
        /var/run/milter/milter-spamc.pid        milter:milter   0644 -rw-r--r--
        /var/run/milter/milter-spamc.socket     milter:milter   0644 srw-r--r--
        /var/db/milter-spamc                    milter:milter   0644 -rw-r--r-- (*BSD)
        /var/cache/milter-spamc                 milter:milter   0644 -rw-r--r-- (linux)
        /usr/local/libexec/milter-spamc         root:milter     0550 -r-xr-x---
