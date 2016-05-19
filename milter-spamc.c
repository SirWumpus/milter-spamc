/*
 * milter-spamc.c
 *
 * Copyright 2003, 2009 by Anthony Howe. All rights reserved.
 *
 * The following should be added to the sendmail.mc file:
 *
 *	INPUT_MAIL_FILTER(
 *		`milter-spamc',
 *		`S=unix:/var/lib/milter-spamc/socket, T=S:30s;R:3m'
 *	)dnl
 */

/***********************************************************************
 *** Leave this header alone. Its generate from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 *** You can change the stuff below if the configure script doesn't work.
 ***********************************************************************/

#ifndef RUN_AS_USER
#define RUN_AS_USER			"milter"
#endif

#ifndef RUN_AS_GROUP
#define RUN_AS_GROUP			"milter"
#endif

#ifndef MILTER_CF
#define MILTER_CF			"/etc/mail/" MILTER_NAME ".cf"
#endif

#ifndef PID_FILE
#define PID_FILE			"/var/run/milter/" MILTER_NAME ".pid"
#endif

#ifndef SOCKET_FILE
#define SOCKET_FILE			"/var/run/milter/" MILTER_NAME ".socket"
#endif

#ifndef WORK_DIR
#define WORK_DIR			"/var/tmp"
#endif

#ifndef SPAMD_PORT
#define SPAMD_PORT			783
#endif

#ifndef DEFAULT_HEADER_BUFFER_SIZE
#define DEFAULT_HEADER_BUFFER_SIZE	8192
#endif

#ifndef SIMPLE_JUNK_MAIL_REPLY
#define SIMPLE_JUNK_MAIL_REPLY		"message was identified as junk mail, score %.2f/%.2f"
#endif

/* Choose between CHECK, REPORT_IFSPAM, and REPORT.
 * PROCESS and SYMBOLS not supported.
 */

/***********************************************************************
 *** No configuration below this point.
 ***********************************************************************/

/* Re-assert this macro just in case. May cause a compiler warning. */
#define _REENTRANT	1

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>
#include <netdb.h>

#include <com/snert/lib/version.h>
#include <com/snert/lib/io/socket2.h>
#include <com/snert/lib/sys/Time.h>
#include <com/snert/lib/sys/sysexits.h>
#include <com/snert/lib/net/network.h>
#include <com/snert/lib/mail/limits.h>
#include <com/snert/lib/mail/smf.h>
#include <com/snert/lib/mail/smdb.h>
#include <com/snert/lib/util/Buf.h>
#include <com/snert/lib/util/Text.h>
#include <com/snert/lib/util/setBitWord.h>

#if LIBSNERT_MAJOR < 1 || LIBSNERT_MINOR < 69
# error "LibSnert/1.69 or better is required"
#endif

#define MILTER_STRING	MILTER_NAME "/" MILTER_VERSION

/***********************************************************************
 *** Constants
 ***********************************************************************/

#define	TAG_FORMAT		"%05d %s: "
#define	TAG_ARGS		data->work.cid, data->work.qid

#define NEWLINE_IS_LF		"\n"
#define NEWLINE_IS_CRLF		"\r\n"
#define X_SPAM_REPORT_NL	NEWLINE_IS_LF "  | "

/***********************************************************************
 *** Global Variables
 ***********************************************************************/

typedef struct {
	int length;
	char *header;
} Header;

typedef struct {
	int isLocal;				/* rcpt_mailer == 'local or 'cyrusv2' */
	long length;				/* address length */
	long capacity;				/* address buffer capacity */
	char *address;				/* recipient address with < and > */
} *Rcpt;

typedef struct {
	smfWork work;
	Socket2 *server;			/* per message */
	Vector rcpts;				/* per message */
	Vector report;				/* per message */
	Vector headers;				/* per message */
	Buf *long_string;			/* per message */
	time_t now;				/* per message */
	size_t bytesSent;			/* per message */
	int localRcptCount;			/* per message */
	int untrustedRcptCount;			/* per message */
	int hasSubject;				/* per message */
	int hasSpamFlag;			/* per message */
	int hasSpamLevel;			/* per message */
	int hasSpamReport;			/* per message */
	int hasSpamStatus;			/* per message */
	int precedence;				/* per message */
	char *localRcpt;			/* per message */
	char helo[SMTP_DOMAIN_LENGTH+1];	/* per connection */
	char line[SMTP_TEXT_LINE_LENGTH+1];	/* general purpose */
	char subject[SMTP_TEXT_LINE_LENGTH+1];	/* subject header */
	char client_name[SMTP_DOMAIN_LENGTH+1];	/* per connection */
	char client_addr[IPV6_TAG_LENGTH+IPV6_STRING_LENGTH];	/* per connection */
} *workspace;

#define USAGE_DISCARD_LOW_PRECEDENCE					\
  "If the message is spam and its Precedence: header is set to list,\n"	\
"# junk, or bulk, then discard the message instead of rejecting.\n"	\
"#"

#define USAGE_MAIL_POLICY						\
  "This policy specifies what to do with junk mail that is not going\n"	\
"# to be rejected or discarded. Specify one of: none, copy, redirect.\n"\
"# The mail-spam address will then be used.\n"				\
"#"

#define USAGE_MAIL_FORMAT						\
  "Format string used to transform recipient addresses of junk mail.\n"	\
"# This format is only applied if all recipients of the message are\n"	\
"# local. Specify an empty string to disable.\n"			\
"#"

static const char usage_spamd_command[] =
  "Specify one of CHECK, SYMBOLS, REPORT_IFSPAM, or REPORT to check\n"
"# the message for spam and never generate a report, report only the\n"
"# test names, generate a report if spam, or always generate a report\n"
"# respectively.\n"
"#"
;

#define USAGE_EXTRA_DISCARD						\
  "If the spam score returned by spamd exceeds the threshold by this\n"	\
"# many points, then discard the message. If the score is less than\n"	\
"# threshold + extra-discard, the message will be tagged or rejected\n"	\
"# depending on the value of extra-reject. Specify -1 to disable\n"	\
"# discards.\n"								\
"#"

#define USAGE_EXTRA_REJECT						\
  "If the spam score returned by spamd exceeds the threshold by this\n"	\
"# many points, then reject the message. If the score is less than\n"	\
"# threshold + extra-reject, then message will be tagged. Specify -1\n"	\
"# to disable rejections and perform subject tagging only.\n"		\
"#"

#define USAGE_EXTRA_LOW_SPAM						\
  "If the spam score returned by spamd exceeds the threshold by this\n"	\
"# many points, then redirect the message to mail-spam. If the score\n" \
"# is less than threshold + extra-low-spam, then message will be\n"	\
"# redirected to mail-low-spam. Specify -1 to disable split redirection.\n"		\
"#"

#define USAGE_GATEWAY							\
  "The server is a mail gateway. If the {rcpt_host} macro passed by\n"	\
"# Sendmail is an address-literal that is a local-use IP address\n"	\
"# defined by RFC 3330 or 3513, then spamd is given the local-part\n"	\
"# before the @-sign to select spamd user preferences.\n"		\
"#"

static Option optIntro			= { "",				NULL,			"\n# " MILTER_NAME "/" MILTER_VERSION  "\n#\n# " MILTER_COPYRIGHT "\n#\n" };
static Option optDiscardLowPrecedence	= { "discard-low-precedence"	"-",			USAGE_DISCARD_LOW_PRECEDENCE };
static Option optExtraDiscard		= { "extra-discard",		"-1",			USAGE_EXTRA_DISCARD };
static Option optExtraReject		= { "extra-reject",		"-1",			USAGE_EXTRA_REJECT };
static Option optExtraLowSpam		= { "extra-low-spam",		"-1",			USAGE_EXTRA_LOW_SPAM };
static Option optIsGateway		= { "is-gateway",		"-",			USAGE_GATEWAY };
static Option optLevelCharacter		= { "level-character",		"x",			"The X-Spam-Level header character to use; or empty to disable." };
static Option optMailArchive		= { "mail-archive",		"",			"Address where to archive a copy of all messages; empty to disable." };
static Option optMailFormat		= { "mail-format",		"",			USAGE_MAIL_FORMAT };
static Option optMailHam		= { "mail-ham",			"",			"Address where to copy good mail; empty to disable." };
static Option optMailPolicy		= { "mail-policy",		"none",			USAGE_MAIL_POLICY };
static Option optMailSpam		= { "mail-spam",		"",			"Address where to copy or redirect junk mail." };
static Option optMailLowSpam		= { "mail-low-spam",		"",			"Address where to copy or redirect junk mail." };
static Option optMaxUntrusted		= { "max-untrusted",		"-1",			"Max. number of untrusted recipients per message; -1 to disable." };
static Option optNoUserConfig		= { "no-user-config",		"-",			"Disable spamd user configurations and always use the default spamd-user." };
static Option optAlwaysAddFlag		= { "always-add-flag",		"-",			"Always add the X-Spam-Flag header for spam or ham." };
static Option optAlwaysAddLevel		= { "always-add-level",		"-",			"Always add the X-Spam-Level header for spam or ham." };
#ifdef USE_INSTEAD_OF_REPORT_IF_SPAM
static Option optAlwaysAddReport	= { "always-add-report",	"-",			"Always add the X-Spam-Report header for spam or ham." };
#endif
static Option optSpamdCommand		= { "spamd-command",		"REPORT",		usage_spamd_command };
static Option optSpamdMaxSize		= { "spamd-max-size",		"64",			"Max. number of kilobytes to pass to spamd, 0 for unlimited." };
static Option optSpamdSocket		= { "spamd-socket",		"127.0.0.1:783",	"The unix domain socket or internet host[,port] of the spamd server." };
static Option optSpamdTimeout		= { "spamd-timeout",		"120",			"The milter/spamd I/O timeout in seconds." };
static Option optSpamdUser		= { "spamd-user",		"",			"Default user account to process message with." };
static Option optSubjectTag		= { "subject-tag",		"[SPAM]",		"Subject tag for messages identified as spam." };
static Option optSubjectTagScore	= { "subject-tag-score", 	"-",			"Append the score to the subject tag." };
static Option optSmtpDetailedReply	= { "smtp-detailed-reply", 	"+",			"Provide informative SMTP rejection messages with SpamAssassin score and/or rules." };
static Option opt_version	= { "version",		NULL,		"Show version and copyright." };

static const char usage_info[] =
  "Write the configuration and compile time options to standard output\n"
"# and exit.\n"
"#"
;
Option opt_info			= { "info", 		NULL,		usage_info };


static Option *optTable[] = {
	&optIntro,
	&optAlwaysAddFlag,
	&optAlwaysAddLevel,
#ifdef USE_INSTEAD_OF_REPORT_IF_SPAM
	&optAlwaysAddReport,
#endif
	&optDiscardLowPrecedence,
	&optExtraDiscard,
	&optExtraReject,
	&optExtraLowSpam,
	&opt_info,
	&optIsGateway,
	&optLevelCharacter,
	&optMailArchive,
	&optMailFormat,
	&optMailHam,
	&optMailPolicy,
	&optMailSpam,
	&optMailLowSpam,
	&optMaxUntrusted,
	&optNoUserConfig,
	&optSmtpDetailedReply,
	&optSpamdCommand,
	&optSpamdMaxSize,
	&optSpamdSocket,
	&optSpamdTimeout,
	&optSpamdUser,
	&optSubjectTag,
	&optSubjectTagScore,
	&opt_version,
	NULL
};

#define X_SCANNED_BY			"X-Scanned-By"
#define X_SPAM_FLAG			"X-Spam-Flag"
#define X_SPAM_LEVEL			"X-Spam-Level"
#define X_SPAM_REPORT			"X-Spam-Report"
#define X_SPAM_STATUS			"X-Spam-Status"
#define X_ORIGINAL_RECIPIENT		"X-Original-Recipient"

/***********************************************************************
 *** Support routines.
 ***********************************************************************/

static void atExitCleanUp(void);

/*
 * Write buffer, logging only errors.
 */
int
writebuffer(workspace data, unsigned char *buf, long size)
{
	long nbytes;

	/* Do not block on sending to the spamd server just yet. */
	(void) socketSetNonBlocking(data->server, 1);
	nbytes = socketWrite(data->server, buf, size);
	(void) socketSetNonBlocking(data->server, 0);

	return nbytes != SOCKET_ERROR;
}

/*
 * Log line to be sent then write line.
 */
int
writeline(workspace data, char *line, long size)
{
	smfLog(SMF_LOG_DIALOG, TAG_FORMAT "> %s", TAG_ARGS, line);

	return writebuffer(data, (unsigned char *)line, size < 0 ? strlen(line) : size);
}

/*
 * Log amount of data sent then write data.
 */
int
writechunk(workspace data, unsigned char *chunk, long size)
{
	smfLog(SMF_LOG_DIALOG, TAG_FORMAT "> [%ld bytes of data]", TAG_ARGS, size);

	return writebuffer(data, chunk, size);
}

long
readline(workspace data, char *line, int linesize)
{
	long length;

	socketSetTimeout(data->server, optSpamdTimeout.value);
	length = socketReadLine(data->server, line, linesize);

	switch (length) {
	case SOCKET_ERROR:
		syslog(LOG_ERR, TAG_FORMAT "read error: %s (%d)", TAG_ARGS, strerror(errno), errno);
		break;
	case SOCKET_EOF:
		smfLog(SMF_LOG_DIALOG, TAG_FORMAT "EOF", TAG_ARGS);
		break;
	default:
		smfLog(SMF_LOG_DIALOG, TAG_FORMAT "< %s", TAG_ARGS, line);
	}

	return length;
}

static int
addheader(workspace data, const char *fmt, ...)
{
	int length;
	Header *hdr;
	va_list args;
	char empty[1];

	va_start(args, fmt);
	if ((length = vsnprintf(empty, sizeof (empty), fmt, args)) < 0) {
		smfLog(SMF_LOG_ERROR, TAG_FORMAT "printf encoding error", TAG_ARGS);
		return -1;
	}
	va_end(args);
	length++;

	if ((hdr = malloc(sizeof (*hdr) + length)) == NULL) {
		smfLog(SMF_LOG_ERROR, TAG_FORMAT "memory error: %s (%d)", TAG_ARGS, strerror(errno), errno);
		return -1;
	}

	if (VectorAdd(data->headers, hdr)) {
		smfLog(SMF_LOG_ERROR, TAG_FORMAT "memory error: %s (%d)", TAG_ARGS, strerror(errno), errno);
		free(hdr);
		return -1;
	}

	va_start(args, fmt);
	hdr->header = (char *) (hdr + 1);
	hdr->length = vsnprintf(hdr->header, length, fmt, args);
	va_end(args);

	return hdr->length;
}

/***********************************************************************
 *** Handlers
 ***********************************************************************/

/*
 * Open and allocate per-connection resources.
 */
static sfsistat
filterOpen(SMFICTX *ctx, char *client_name, _SOCK_ADDR *raw_client_addr)
{
	int access;
	workspace data;

	if (raw_client_addr == NULL) {
		smfLog(SMF_LOG_TRACE, "filterOpen() got NULL socket address, accepting connection");
		goto error0;
	}

	if (raw_client_addr->sa_family != AF_INET
#ifdef HAVE_STRUCT_SOCKADDR_IN6
	&& raw_client_addr->sa_family != AF_INET6
#endif
	) {
		smfLog(SMF_LOG_TRACE, "filterOpen() unsupported socket address type, accepting connection");
		goto error0;
	}

	if ((data = calloc(1, sizeof *data)) == NULL)
		goto error0;

	data->work.ctx = ctx;
	data->work.qid = smfNoQueue;
	TextCopy(data->client_name, sizeof (data->client_name), client_name);
	data->work.cid = smfOpenProlog(ctx, client_name, raw_client_addr, data->client_addr, sizeof (data->client_addr));

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterOpen(%lx, '%s', [%s])", TAG_ARGS, (long) ctx, client_name, data->client_addr);

	if ((data->rcpts = VectorCreate(10)) == NULL)
		goto error1;
	VectorSetDestroyEntry(data->rcpts, free);

#ifdef HAVE_SMFI_SETMLREPLY
	if ((data->report = VectorCreate(10)) == NULL)
		goto error2;
	VectorSetDestroyEntry(data->report, free);
#endif
	if ((data->headers = VectorCreate(50)) == NULL)
		goto error3;
	VectorSetDestroyEntry(data->headers, free);

	if ((data->long_string = BufCreate(256)) == NULL)
		goto error4;

	if (smfi_setpriv(ctx, (void *) data) == MI_FAILURE) {
		syslog(LOG_ERR, TAG_FORMAT "failed to save workspace", TAG_ARGS);
		goto error5;
	}

	access = smfAccessHost(&data->work, MILTER_NAME "-connect:", client_name, data->client_addr, SMDB_ACCESS_OK);

	switch (access) {
#ifdef ENABLE_BLACKLIST
	case SMDB_ACCESS_REJECT:
		return smfReply(&data->work, 550, "5.7.1", "connection %s [%s] blocked", client_name, data->client_addr);
#endif
	case SMDB_ACCESS_ERROR:
		return SMFIS_REJECT;
	}

	return SMFIS_CONTINUE;
error5:
	BufDestroy(data->long_string);
error4:
	VectorDestroy(data->headers);
error3:
#ifdef HAVE_SMFI_SETMLREPLY
	VectorDestroy(data->report);
error2:
#endif
	VectorDestroy(data->rcpts);
error1:
	free(data);
error0:
	return SMFIS_ACCEPT;
}

static sfsistat
filterHelo(SMFICTX * ctx, char *helohost)
{
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterHelo");

	/* Reset this again. A HELO/EHLO is treated like a RSET command,
	 * which means we arrive here after the connection but also after
	 * MAIL or RCPT, in which case $i (data->work.qid) is invalid.
	 */
	data->work.qid = smfNoQueue;

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterHelo(%lx, '%s')", TAG_ARGS, (long) ctx, helohost);

	if (helohost != NULL)
		TextCopy(data->helo, sizeof(data->helo), helohost);

	return SMFIS_CONTINUE;
}

static sfsistat
filterMail(SMFICTX *ctx, char **args)
{
	int access, n;
	workspace data;
	const char *if_name, *client_name, *client_resolve, *auth_authen, *space;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterMail");

	if ((data->work.qid = smfi_getsymval(ctx, "i")) == NULL)
		data->work.qid = smfNoQueue;

	auth_authen = smfi_getsymval(ctx, smMacro_auth_authen);

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterMail(%lx, %lx) MAIL='%s' auth='%s'", TAG_ARGS, (long) ctx, (long) args, args[0], TextEmpty(auth_authen));

	/* Reset per-message variables, since this function can be
	 * called several times per message or connection, ie.
	 * MAIL-RSET-MAIL or MAIL-RCPT-DATA-MAIL sequences.
	 */

	VectorRemoveAll(data->headers);
#ifdef HAVE_SMFI_SETMLREPLY
	VectorRemoveAll(data->report);
#endif
	VectorRemoveAll(data->rcpts);
	data->untrustedRcptCount = 0;
	data->localRcptCount = 0;

	if (data->localRcpt != optSpamdUser.string)
		free(data->localRcpt);

	data->work.skipMessage = data->work.skipConnection | (*optSpamdSocket.string == '\0');
	data->precedence = PRECEDENCE_FIRST_CLASS;
	data->localRcpt = NULL;
	data->bytesSent = 0;

	data->subject[0] = '\0';
	data->hasSubject = 0;
	data->hasSpamFlag = 0;
	data->hasSpamLevel = 0;
	data->hasSpamReport = 0;
	data->hasSpamStatus = 0;

	(void) time(&data->now);

	/* Make sure its closed before we start the next message. */
	socketClose(data->server);
	data->server = NULL;

	access = smfAccessMail(&data->work, MILTER_NAME "-from:", args[0], SMDB_ACCESS_UNKNOWN);

	switch (access) {
#ifdef ENABLE_BLACKLIST
	case SMDB_ACCESS_REJECT:
		return smfReply(&data->work, 550, "5.7.1", "sender %s blacklisted", args[0]);
#endif
	case SMDB_ACCESS_ERROR:
		return SMFIS_REJECT;
	case SMDB_ACCESS_OK:
		syslog(LOG_INFO, TAG_FORMAT "sender %s whitelisted, accept", TAG_ARGS, args[0]);
		data->work.skipConnection = data->work.skipMessage = 1;
		return SMFIS_ACCEPT;
	}

	access = smfAccessAuth(&data->work, MILTER_NAME "-auth:", auth_authen, args[0], NULL, NULL);

	switch (access) {
	case SMDB_ACCESS_ERROR:
		return SMFIS_REJECT;
	case SMDB_ACCESS_OK:
		syslog(LOG_INFO, TAG_FORMAT "sender %s authenticated, accept", TAG_ARGS, args[0]);
		data->work.skipConnection = data->work.skipMessage = 1;
		return SMFIS_ACCEPT;
	}

	/* Insert a simulated Received: header for this server into the
	 * header block being sent to spamd. It appears that this header
	 * is never given to the milter and without it, some tests in
	 * SpamAssassin concerning Received headers are skewed.
	 *
	 * This simulated header will be a stripped down version of
	 * what Sendmail would insert.
	 */

	if_name = smfi_getsymval(ctx, "{if_name}");
	if (if_name == NULL)
		if_name = "unknown";

	n = TimeStampAdd(data->line, sizeof (data->line));
	addheader(data, "Return-Path: <%s>", data->work.mail->address.string);

	space = " ";
	client_name = smfi_getsymval(ctx, "{client_name}");
	client_resolve = smfi_getsymval(ctx, "{client_resolve}");

	if (client_name == NULL) {
		/* When the {client_name} macro isn't defined... */
		if (*data->client_name == '[') {
			client_name = space = "";
			client_resolve = " (may be forged)";
		} else {
			client_name = data->client_name;
			client_resolve = "";
		}
	} else if (client_resolve == NULL) {
		/* When the {client_resolve} macro isn't defined... */
		if (*data->client_name == '[') {
			client_resolve = " (may be forged)";
		} else {
			client_resolve = "";
		}
	} else {
		switch (client_resolve[1]) {
		case 'K': /* OK */
			client_resolve = "";
			break;
		case 'A': /* FAIL */
		case 'E': /* TEMP */
			client_name = client_resolve = space = "";
			break;
		case 'O': /* FORGED */
			client_resolve = " (may be forged)";
			break;
		}
	}

	addheader(
		data, "Received: from %s (%s%s[%s]%s) by %s id %s; %s",
		data->helo, client_name, space, data->client_addr, client_resolve,
		if_name, data->work.qid, data->line
	);

	return SMFIS_CONTINUE;
}

static sfsistat
filterRcpt(SMFICTX *ctx, char **args)
{
	workspace data;
	char *rcpt_addr, *rcpt_host, *rcpt_mailer;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterRcpt");

	rcpt_addr = smfi_getsymval(ctx, "{rcpt_addr}");
	rcpt_host = smfi_getsymval(ctx, "{rcpt_host}");
	rcpt_mailer = smfi_getsymval(ctx, "{rcpt_mailer}");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterRcpt(%lx, %lx) RCPT='%s' rcpt_addr='%s' rcpt_host='%s' rcpt_mailer='%s'", TAG_ARGS, (long) ctx, (long) args, args[0], rcpt_addr, rcpt_host, rcpt_mailer);

	if (smfAccessRcpt(&data->work, MILTER_NAME "-to:", args[0]) == SMDB_ACCESS_ERROR)
		return SMFIS_REJECT;

	/* Maintain historical behaviour for now until I can study
	 * the impact of the following change to the content filter.
	 *
	 * TODO filterEndMessage() : Ideally if the message is spam
	 * and the sender/connection is not white listed and _some_
	 * RCPTs are not white listed, then delete those RCPTs from
	 * the delivery list, leaving only the white listed RCPTs
	 * and possibly the spambox address.
	 */
	if (data->work.skipRecipient)
		data->work.skipMessage = 1;

	/* TEST if the untrustedRcptCount has exceed the -l limit. */
	if (0 < optMaxUntrusted.value && optMaxUntrusted.value <= data->untrustedRcptCount)
		return smfReply(&data->work, 452, "4.5.3", "too many untrusted recipients");
/*		return smfReply(&data->work, 421, "4.3.2", "close connection"); */

	data->work.rcpt->isLocal =
	  	/* Local delivery agent Bat Book 3e section 21.9.78 */
		   rcpt_host == NULL
		|| *rcpt_host == '\0'
		/* Special case for Cyrus mail delivery agent. */
		|| (rcpt_mailer != NULL && strncmp(rcpt_mailer, "cyrus", 5) == 0)
		/* This case assumes a IP address-literal value. */
		|| (optIsGateway.value && isReservedIP(rcpt_host, IS_IP_LOCAL));

	/* Remember last local user. Ideally we should also attempt to
	 * expand mail aliases, but that means lots of Berkeley DB issues,
	 * so for the time being we'll ignore it and hope its not that
	 * important.
	 *
	 * Normally {rcpt_mailer} == 'local' or 'cyrusv2', {rcpt_host} == ''
	 * and {rcpt_addr} == account. However, some sites do some special
	 * rulesets for cyrus or cyrusv2 where the {rcpt_host} != '', yet
	 * the user is a local account.
	 */
	if (rcpt_addr != NULL && data->work.rcpt->isLocal) {
		int hasEntry;

		if (pthread_mutex_lock(&smfMutex))
			syslog(LOG_ERR, "mutex lock in filterRcpt() failed: %s (%d)", strerror(errno), errno);

		hasEntry = getpwnam(rcpt_addr) != NULL;

		if (pthread_mutex_unlock(&smfMutex))
			syslog(LOG_ERR, "mutex unlock in filterRcpt() failed: %s (%d)", strerror(errno), errno);

		if (hasEntry || optIsGateway.value) {
			/* Free NULL or a previous local recipient. */
			free(data->localRcpt);

			smfLog(SMF_LOG_TRACE, TAG_FORMAT "address %s has an account", TAG_ARGS, args[0]);

			/* Assign local recipient. Don't worry if NULL, handled in filterBody(). */
			data->localRcpt = TextDup(rcpt_addr);
		}
	}

	data->localRcptCount += data->work.rcpt->isLocal;

	if (!data->work.skipMessage)
		data->untrustedRcptCount++;

	if (VectorAdd(data->rcpts, data->work.rcpt))
		return smfReply(&data->work, 452, "4.3.2", "out of memory, cannot add recipient to list");

	data->work.rcpt = NULL;

	return SMFIS_CONTINUE;
}

static sfsistat
filterHeader(SMFICTX *ctx, char *name, char *value)
{
	int i;
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterHeader");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterHeader(%lx, '%s', '%s')", TAG_ARGS, (long) ctx, name, value);

	if (data->work.skipMessage || name == NULL || value == NULL)
		return SMFIS_CONTINUE;

	if (TextInsensitiveCompare(name, "Subject") == 0) {
		(void) strncpy(data->subject, value, sizeof (data->subject) - strlen(optSubjectTag.string) - 1);
		data->subject[sizeof (data->subject) - strlen(optSubjectTag.string) - 1] = '\0';
		data->hasSubject = 1;
	}

	/* There appears to be a bug in libmilter. smfi_chgheader() is
	 * suppose to change or add the header if missing, but it don't
	 * work as advertised, so we have to track the precense of these
	 * headers and call smfi_chgheader() or smfi_addheader() as required.
	 */
	if (TextInsensitiveCompare(name, X_SPAM_FLAG) == 0) {
		data->hasSpamFlag = 1;
		return SMFIS_CONTINUE;
	}
	if (TextInsensitiveCompare(name, X_SPAM_LEVEL) == 0) {
		data->hasSpamLevel = 1;
		return SMFIS_CONTINUE;
	}
	if (TextInsensitiveCompare(name, X_SPAM_REPORT) == 0) {
		data->hasSpamReport = 1;
		return SMFIS_CONTINUE;
	}
	if (TextInsensitiveCompare(name, X_SPAM_STATUS) == 0) {
		data->hasSpamStatus = 1;
		return SMFIS_CONTINUE;
	}

	if (TextInsensitiveCompare(name, "Precedence") == 0) {
		for (i = 0; i <= PRECEDENCE_SPECIAL_DELIVERY; i++) {
			if (TextInsensitiveCompare(value, smfPrecedence[i]) == 0) {
				data->precedence = i;
				break;
			}
		}
		return SMFIS_CONTINUE;
	}

	addheader(data, "%s: %s", name, value);

	return SMFIS_CONTINUE;
}

static sfsistat
filterEndHeaders(SMFICTX *ctx)
{
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterEndHeaders");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterEndHeaders(%lx)", TAG_ARGS, (long) ctx);

	if (!data->work.skipMessage)
		addheader(data, "");

	return SMFIS_CONTINUE;
}

static int
spamdConnect(workspace data)
{
	Header *hdr;
	long length, i;

	/* Start sending the headers for processing to SpamAssassin now.
	 * If there is no body after the headers filterBody() will not
	 * be called.
	 */
	errno = 0;
	if (socketOpenClient(optSpamdSocket.string, SPAMD_PORT, optSpamdTimeout.value, NULL, &data->server)) {
		syslog(LOG_ERR, TAG_FORMAT "failed to connect to spamd %s: %s (%d)", TAG_ARGS, optSpamdSocket.string, strerror(errno), errno);
		goto error0;
	}

	/* Ask for a CHECK or REPORT only and we'll handle adding the
	 * X-Spam-* headers.
	 *
	 * The SPAMD protocol documentation sucks. Only by reading the
	 * source do you find out that the Content-Length: header is
	 * actually optional. Open source peons write crap documentation.
	 */
	length = snprintf(data->line, SMTP_TEXT_LINE_LENGTH, "%s SPAMC/1.2\r\n", optSpamdCommand.string);
	if (!writeline(data, data->line, length))
		goto error1;

	/* If the spamd user is defined, then we'll use it if forced or
	 * multiple recipients given. Otherwise fall back on the last
	 * defined local recipient if any.
	 */
	if (*optSpamdUser.string != '\0' && (optNoUserConfig.value || 1 < VectorLength(data->rcpts))) {
		/* Free NULL or a previous local user. */
		free(data->localRcpt);
		data->localRcpt = NULL;
	}

	/* When no local recipient defined, then fallback on the default
	 * spamd user, which might be undefined.
	 */
	if (data->localRcpt == NULL)
		data->localRcpt = optSpamdUser.string;

	if (data->localRcpt != NULL) {
		smfLog(SMF_LOG_DIALOG, TAG_FORMAT "SPAMD User=%s", TAG_ARGS, data->localRcpt);
		length = snprintf(data->line, SMTP_TEXT_LINE_LENGTH, "User: %s\r\n", data->localRcpt);
		if (!writeline(data, data->line, length))
			goto error1;
	}

	if (!writeline(data, "\r\n", 2))
		goto error1;

	for (i = 0; i < VectorLength(data->headers); i++) {
		if ((hdr = VectorGet(data->headers, i)) == NULL)
			continue;

		if (0 < hdr->length && !writeline(data, hdr->header, hdr->length))
			goto error1;

		/* Assert RFC 2822 canonical newlines. */
		if (!writeline(data, NEWLINE_IS_CRLF, sizeof (NEWLINE_IS_CRLF)-1))
			goto error1;
	}

	return 0;
error1:
	socketClose(data->server);
	data->server = NULL;
error0:
	return -1;
}

static sfsistat
filterBody(SMFICTX *ctx, unsigned char *chunk, size_t size)
{
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterBody");

	if (size == 0)
		chunk = (unsigned char *)"";
	else if (size < 20)
		chunk[--size] = '\0';

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterBody(%lx, '%.20s...', %lu) optSpamdMaxSize.value=%ld bytesSent=%lu", TAG_ARGS, (long) ctx, chunk, size, optSpamdMaxSize.value, data->bytesSent);

	if (data->work.skipMessage)
		goto error0;

	if (0 < optSpamdMaxSize.value && optSpamdMaxSize.value <= data->bytesSent)
		goto error0;

	/* On first chunk, open connection and send headers. */
 	if (data->bytesSent == 0 && spamdConnect(data))
 		goto error0;

 	/* Keep track of how much of the body we process. */
 	data->bytesSent += size;

	if (!writechunk(data, chunk, size))
		goto error1;

	if (0 < optSpamdMaxSize.value && optSpamdMaxSize.value <= data->bytesSent) {
		/* Signal EOF to SPAMD so that it can begin processing now.
		 * This appears to dramatically improve spamd performance.
		 */
		smfLog(SMF_LOG_DIALOG, TAG_FORMAT "EOF (1) -> spamd", TAG_ARGS);
		socketShutdown(data->server, SHUT_WR);
	}

	return SMFIS_CONTINUE;
error1:
	socketClose(data->server);
	data->server = NULL;
error0:
	return SMFIS_CONTINUE;
}

static sfsistat
filterEndMessage(SMFICTX *ctx)
{
	char *s;
	float points;
	workspace data;
	ParsePath *rcpt;
	int i, length, iscore;
	float score, threshold;
	const char *if_name, *if_addr, *is_spam;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterEndMessage");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterEndMessage(%lx)", TAG_ARGS, (long) ctx);

	/* Send a copy of all mail to the archive address. */
	if (*optMailArchive.string != '\0' && smfi_addrcpt(ctx, optMailArchive.string) == MI_FAILURE)
		syslog(LOG_ERR, TAG_FORMAT "copy-all-to <%s> failed", TAG_ARGS, optMailArchive.string);

	/* We do not trust previous occurences of these headers, they could
	 * have been faked by a spammer to try and fool mail filters and/or
	 * mail client message rules.
	 */
	if (data->hasSpamFlag)
		(void) smfHeaderRemove(ctx, X_SPAM_FLAG);
	if (data->hasSpamLevel)
		(void) smfHeaderRemove(ctx, X_SPAM_LEVEL);
	if (data->hasSpamReport)
		(void) smfHeaderRemove(ctx, X_SPAM_REPORT);
	if (data->hasSpamStatus)
		(void) smfHeaderRemove(ctx, X_SPAM_STATUS);

	/* Skip the remainder of this function. */
	if (data->work.skipMessage)
		return SMFIS_CONTINUE;

	if (data->bytesSent == 0) {
		/* No spamd session started yet, because of no
		 * body content; send only the headers now.
		 */
		if (spamdConnect(data))
			goto error0;
	} else if (data->server == NULL) {
		/* Previous connection error in filterBody(). */
		goto error0;
	}

	/* Signal EOF to spamd so that it can start processing.
	 * Note this might have been sent already in filterBody().
	 */
	smfLog(SMF_LOG_DIALOG, TAG_FORMAT "EOF (2) -> spamd", TAG_ARGS);
	socketShutdown(data->server, SHUT_WR);

	socketSetNonBlocking(data->server, 1);

	/* Fetch spamd result and add it to the headers. */
	if (readline(data, data->line, SMTP_TEXT_LINE_LENGTH) <= 0) {
		syslog(LOG_ERR, TAG_FORMAT "SPAMD status line failure", TAG_ARGS);
		goto error0;
	}

	if (strncmp(data->line, "SPAMD/1.1 0 EX_OK", sizeof ("SPAMD/1.1 0 EX_OK")) != 0) {
		syslog(LOG_ERR, TAG_FORMAT "SPAMD failure: %s", TAG_ARGS, data->line);
		goto error0;
	}

	is_spam = smfUndefined;
	score = threshold = 0.0;

	while (0 < readline(data, data->line, SMTP_TEXT_LINE_LENGTH)) {
		if (0 < TextInsensitiveStartsWith(data->line, "Spam:")) {
			/* And the verdict is? */
			is_spam = TextMatch(data->line, "*yes*", -1, 1) || TextMatch(data->line, "*true*", -1, 1)
				? smfYes : smfNo;

			if (is_spam == smfYes || optAlwaysAddFlag.value)
				(void) smfHeaderSet(ctx, X_SPAM_FLAG, (char *) is_spam, 1, data->hasSpamFlag);

			/* Extract the score. */
			if (sscanf(data->line, "%*[^;]; %f / %f", &score, &threshold) != 2) {
				syslog(LOG_ERR, TAG_FORMAT "Spam: header parse error: %s", TAG_ARGS, data->line);
				goto error0;
			}
		}

		/* Ignore any other headers. */
	}

	if ((if_name = smfi_getsymval(ctx, "{if_name}")) == NULL)
		if_name = smfUndefined;
	if ((if_addr = smfi_getsymval(ctx, "{if_addr}")) == NULL)
		if_addr = "0.0.0.0";

	length = snprintf(data->line, sizeof (data->line), MILTER_STRING " (%s [%s]); ", if_name, if_addr);
	length += TimeStampAdd(data->line + length, SMTP_TEXT_LINE_LENGTH - length);
	(void) smfi_addheader(ctx, X_SCANNED_BY, data->line);

	if (is_spam == smfUndefined) {
		syslog(LOG_ERR, TAG_FORMAT "missing Spam: result header", TAG_ARGS);
		goto error0;
	}

	/* Add a pretty header. I think this one is useless. */
	(void) snprintf(data->line, sizeof (data->line), "%s, hits=%.2f required=%.2f", is_spam, score, threshold);
	(void) smfHeaderSet(ctx, X_SPAM_STATUS, data->line, 1, data->hasSpamStatus);

	/* Add another header that can be parsed with by a regular expression.
	 * This one is useful for filtering different levels of spam. Note that
	 * we initially use a non-regular-expression character for writing the
	 * level.
	 */
	if (SMTP_TEXT_LINE_LENGTH <= score)
		/* X-Spam-Level: xxx...x\r\n\0 */
		score = SMTP_TEXT_LINE_LENGTH - sizeof (X_SPAM_LEVEL) - 5;

	if (*optLevelCharacter.string != '\0' && (is_spam == smfYes || optAlwaysAddLevel.value)) {
		iscore = (int) score;
		for (i = 0; i < iscore; i++)
			data->line[i] = *optLevelCharacter.string;
		data->line[i] = '\0';

		(void) smfHeaderSet(ctx, X_SPAM_LEVEL, data->line, 1, data->hasSpamLevel);
	}

	BufSetLength(data->long_string, 0);

#ifdef HAVE_SMFI_SETMLREPLY
	/* Build possible SMTP multi-line response. */
	snprintf(data->line, sizeof data->line, SIMPLE_JUNK_MAIL_REPLY, score, threshold);
	VectorAdd(data->report, strdup(data->line));
#endif
	/* Collect report lines until read error or EOF. */
	while (0 <= (length = readline(data, data->line, SMTP_TEXT_LINE_LENGTH))) {
		/* Remove trailing whitespace. */
		while (0 < length-- && isspace(data->line[length]))
			data->line[length] = '\0';

#ifdef HAVE_SMFI_SETMLREPLY
		/* Save only those report lines that start with a score. */
		if (sscanf(data->line, "%f", &points) == 1 && points != 0.0) {
			for (s = data->line; *s != '\0'; s++) {
				if (*s == '%')
					*s = 'p';
			}
			(void) VectorAdd(data->report, strdup(data->line));
		}
#endif
		BufAddString(data->long_string, data->line);
		BufAddString(data->long_string, X_SPAM_REPORT_NL);
	}

	/* Done with spamd session. */
	socketClose(data->server);
	data->server = NULL;

	if (0 < BufLength(data->long_string)) {
		/* Remove our trailing whitespace "\r\n  ". */
		BufSetLength(data->long_string, BufLength(data->long_string) - (sizeof (X_SPAM_REPORT_NL)-1));
		(void) smfHeaderSet(ctx, X_SPAM_REPORT, (char *)BufBytes(data->long_string), 1, data->hasSpamReport);
	}

	if (is_spam == smfYes) {
		/* Tag the subject if not already. */
		if (TextInsensitiveStartsWith(data->subject, optSubjectTag.string) < 0) {
			if (optSubjectTagScore.value)
				(void) snprintf(data->line, sizeof data->line, "%s (%.2f/%.2f) %s", optSubjectTag.string, score, threshold, data->subject);
			else
				(void) snprintf(data->line, sizeof data->line, "%s %s", optSubjectTag.string, data->subject);

			(void) smfHeaderSet(ctx, "Subject", data->line, 1, data->hasSubject);
		}

		if (*optMailPolicy.string == 'c' || *optMailPolicy.string == 'r') {
			/* The format option can only redirect to individual mail folders when
			 * the entire recipient list is local. Otherwise send to the system
			 * spam box for processing.
			 *
			 * The reason for this restriction is that +detail information is
			 * site specific and so adding this information into outbound mail
			 * is useless. Also when the mail is a mix of local and outbound mail
			 * (for example local user sending to multiple addresses locally and
			 * off-site), then the question is what to do with the outbound mail
			 * addresses:
			 *
			 * a) drop addresses that can't be transformed; not ideal since some
			 * will receive the message in a spam folder and others won't recieve
			 * it at all.
			 *
			 * b) forward to the system collection box; this is more in line with
			 * previous behaviour of the milter and allows the postmaster to
			 * retrain or whitelist within SpamAssassin.
			 *
			 * c) reject the whole message outright; this is a nice choice, since
			 * the sender gets immediate feedback that there is a problem, but
			 * not so easy to retrain SpamAssassin.
			 *
			 * d) don't scan outbound mail; this involves determining whether the
			 * sender is truly a local user (login account, aliases database,
			 * virtual user box), which increases the code complexity.
			 */
			int applied_format = 0;

			if (*optMailPolicy.string == 'r') {
				/* Remove previous list of recipients from Sendmail's list
				 * and record them in the redirected message in case it was
				 * not spam and needs to be resent later. Sometimes the To:
				 * or Cc: headers are useless ie. undisclosed recipients.
				 */
				for (i = 0; i < VectorLength(data->rcpts); i++) {
					if ((rcpt = VectorGet(data->rcpts, i)) == NULL)
						continue;

					if (smfi_addheader(ctx, X_ORIGINAL_RECIPIENT, rcpt->address.string) == MI_SUCCESS)
						(void) smfi_delrcpt(ctx, rcpt->address.string);
				}

				/* If mail-format was given, then modify the recipient list
				 * so that each local recipient is modified according to a
				 * sepcified format.
				 */
				if (*optMailFormat.string != '\0' && VectorLength(data->rcpts) == data->localRcptCount) {
					applied_format = 1;

					for (i = 0; i < VectorLength(data->rcpts); i++) {
						if ((rcpt = VectorGet(data->rcpts, i)) == NULL)
							continue;

						/* We cannot modify non-local recipients, because
						 * plus details are a sendmail thang and the remote
						 * end might handle spam differently.
						 */
						if (!rcpt->isLocal)
							continue;

						(void) formatPath(data->line, sizeof(data->line), optMailFormat.string, rcpt);

						smfLog(SMF_LOG_TRACE, TAG_FORMAT "modified recipient=%s", TAG_ARGS, data->line);

						if (smfi_addrcpt(ctx, data->line) == MI_FAILURE)
							syslog(LOG_ERR, TAG_FORMAT "redirect-spam-to %s failed ", TAG_ARGS, data->line);
					}
				}
			}

			if (!applied_format && score <= threshold + optExtraLowSpam.value
			&& *optMailLowSpam.string != '\0' && smfi_addrcpt(ctx, optMailLowSpam.string) == MI_FAILURE) {
				syslog(LOG_ERR, TAG_FORMAT "copy-spam-to <%s> failed ", TAG_ARGS, optMailLowSpam.string);
				goto error1;
			} else
			if (!applied_format && *optMailSpam.string != '\0' && smfi_addrcpt(ctx, optMailSpam.string) == MI_FAILURE) {
				syslog(LOG_ERR, TAG_FORMAT "copy-spam-to <%s> failed ", TAG_ARGS, optMailSpam.string);
				goto error1;
			}
		}
	} else {
		/* Send a copy of clean mail to an archive address. */
		if (*optMailHam.string != '\0' && smfi_addrcpt(ctx, optMailHam.string) == MI_FAILURE)
			syslog(LOG_ERR, TAG_FORMAT "copy-ham-to <%s> failed ", TAG_ARGS, optMailHam.string);
	}

error1:
	/* REUSE this buffer to build RCPT list string. */
	BufSetLength(data->long_string, 0);

	/* Save copy of recipient list into a string for log information. */
	for (i = 0; i < VectorLength(data->rcpts); i++) {
		if ((rcpt = VectorGet(data->rcpts, i)) != NULL) {
			BufAddString(data->long_string, rcpt->address.string);
			BufAddString(data->long_string, ">,<");
		}
	}

	/* Remove trailing ",<". */
	BufSetLength(data->long_string, BufLength(data->long_string)-2);

	(void) TextTransliterate(data->subject, "\r\n\t", " ");
	syslog(
		LOG_INFO, TAG_FORMAT "spam=%s score=%.2f required=%.2f client_addr=%s client_name=%s subject='%s' mail=<%s> rcpts=<%s",
		TAG_ARGS, is_spam, score, threshold,
		data->client_addr, data->client_name, data->subject,
		data->work.mail->address.string, BufBytes(data->long_string)
	);

	if (is_spam == smfYes) {
		if (optSmtpDetailedReply.value) {
#ifdef HAVE_SMFI_SETMLREPLY
			(void) smfMultiLineReplyA(&data->work, 550, "5.7.1", (char **) VectorBase(data->report));

#else
			(void) smfReply(&data->work, 550, "5.7.1", SIMPLE_JUNK_MAIL_REPLY, score, threshold);
#endif
		} else {
			(void) smfReply(&data->work, 550, "5.7.1", "This looks like spam.");
		}

		if (threshold + optExtraDiscard.value <= score || (optDiscardLowPrecedence.value && data->precedence <= PRECEDENCE_LIST)) {
			syslog(LOG_INFO, TAG_FORMAT "discard message", TAG_ARGS);
			return SMFIS_DISCARD;
		}
		if (threshold + optExtraReject.value <= score)
			return SMFIS_REJECT;
	}
error0:
	return SMFIS_CONTINUE;
}

/*
 * Close and release per-connection resources.
 */
static sfsistat
filterClose(SMFICTX *ctx)
{
	workspace data;
	unsigned short cid = 0;

	if ((data = (workspace) smfi_getpriv(ctx)) != NULL) {
		cid = smfCloseEpilog(&data->work);

		if (data->localRcpt != optSpamdUser.string)
			free(data->localRcpt);

		BufDestroy(data->long_string);
		VectorDestroy(data->headers);
#ifdef HAVE_SMFI_SETMLREPLY
		VectorDestroy(data->report);
#endif
		VectorDestroy(data->rcpts);
		socketClose(data->server);

		free(data);
	}

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterClose(%lx)", cid, smfNoQueue, (long) ctx);

	return SMFIS_CONTINUE;
}

/***********************************************************************
 ***  Milter Definition Block
 ***********************************************************************/

static smfInfo milter = {
	MILTER_MAJOR,
	MILTER_MINOR,
	MILTER_BUILD,
	MILTER_NAME,
	MILTER_VERSION,
	MILTER_COPYRIGHT,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	SMF_STDIO_CLOSE,

	/* struct smfiDesc */
	{
		MILTER_NAME,		/* filter name */
		SMFI_VERSION,		/* version code -- do not change */
		SMFIF_ADDHDRS|SMFIF_CHGHDRS|SMFIF_ADDRCPT|SMFIF_DELRCPT,	/* flags */
		filterOpen,		/* connection info filter */
		filterHelo,		/* SMTP HELO command filter */
		filterMail,		/* envelope sender filter */
		filterRcpt,		/* envelope recipient filter */
		filterHeader,		/* header filter */
		filterEndHeaders,	/* end of header */
		filterBody,		/* body block filter */
		filterEndMessage,	/* end of message */
		NULL,			/* message aborted */
		filterClose		/* connection cleanup */
#if SMFI_VERSION > 2
		, NULL			/* Unknown/unimplemented commands */
#endif
#if SMFI_VERSION > 3
		, NULL			/* SMTP DATA command */
#endif
	}
};

/***********************************************************************
 *** Startup
 ***********************************************************************/

static void
atExitCleanUp()
{
	smdbClose(smdbAccess);
	smfAtExitCleanUp();
}

void
printVersion(void)
{
	printf(MILTER_NAME " " MILTER_VERSION " " MILTER_COPYRIGHT "\n");
	snertPrintVersion();
#ifdef _BUILT
	printf("Built on " _BUILT "\n");
#endif
}

void
printInfo(void)
{
#ifdef MILTER_NAME
	printVar(0, "MILTER_NAME", MILTER_NAME);
#endif
#ifdef MILTER_VERSION
	printVar(0, "MILTER_VERSION", MILTER_VERSION);
#endif
#ifdef MILTER_COPYRIGHT
	printVar(0, "MILTER_COPYRIGHT", MILTER_COPYRIGHT);
#endif
#ifdef MILTER_CONFIGURE
	printVar(LINE_WRAP, "MILTER_CONFIGURE", MILTER_CONFIGURE);
#endif
#ifdef _BUILT
	printVar(0, "MILTER_BUILT", _BUILT);
#endif
#ifdef LIBSNERT_VERSION
	printVar(0, "LIBSNERT_VERSION", LIBSNERT_VERSION);
#endif
#ifdef LIBSNERT_BUILD_HOST
	printVar(LINE_WRAP, "LIBSNERT_BUILD_HOST", LIBSNERT_BUILD_HOST);
#endif
#ifdef LIBSNERT_CONFIGURE
	printVar(LINE_WRAP, "LIBSNERT_CONFIGURE", LIBSNERT_CONFIGURE);
#endif
#ifdef SQLITE_VERSION
	printVar(0, "SQLITE3_VERSION", SQLITE_VERSION);
#endif
#ifdef MILTER_CFLAGS
	printVar(LINE_WRAP, "CFLAGS", MILTER_CFLAGS);
#endif
#ifdef MILTER_LDFLAGS
	printVar(LINE_WRAP, "LDFLAGS", MILTER_LDFLAGS);
#endif
#ifdef MILTER_LIBS
	printVar(LINE_WRAP, "LIBS", MILTER_LIBS);
#endif
}

int
main(int argc, char **argv)
{
	int argi;

	smfOptFile.initial = MILTER_CF;
	smfOptPidFile.initial = PID_FILE;
	smfOptRunUser.initial = RUN_AS_USER;
	smfOptRunGroup.initial = RUN_AS_GROUP;
	smfOptWorkDir.initial = WORK_DIR;
	smfOptMilterSocket.initial = "unix:" SOCKET_FILE;

	/* Parse command line options looking for a file= option. */
	optionInit(optTable, smfOptTable, NULL);
	argi = optionArrayL(argc, argv, optTable, smfOptTable, NULL);

	/* Parse the option file followed by the command line options again. */
	if (smfOptFile.string != NULL && *smfOptFile.string != '\0') {
		/* Do NOT reset this option. */
		smfOptFile.initial = smfOptFile.string;
		smfOptFile.string = NULL;

		optionInit(optTable, smfOptTable, NULL);
		(void) optionFile(smfOptFile.string, optTable, smfOptTable, NULL);
		(void) optionArrayL(argc, argv, optTable, smfOptTable, NULL);
	}

	if (opt_version.string != NULL) {
		printVersion();
		exit(EX_USAGE);
	}
	if (opt_info.string != NULL) {
		printInfo();
		exit(EX_USAGE);
	}
	if (smfOptHelp.string != NULL) {
		optionUsageL(optTable, smfOptTable, NULL);
		exit(EX_USAGE);
	}

	if (smfOptQuit.string != NULL) {
		/* Use SIGQUIT signal in order to avoid delays
		 * caused by libmilter's handling of SIGTERM.
		 * smfi_stop() takes too long since it waits
		 * for connections to terminate, which could
		 * be a several minutes or longer.
		 */
		exit(pidKill(smfOptPidFile.string, SIGQUIT) != 0);
	}

	if (smfOptRestart.string != NULL) {
		(void) pidKill(smfOptPidFile.string, SIGQUIT);
		sleep(2);
	}

	(void) smfi_settimeout((int) smfOptMilterTimeout.value);
	(void) smfSetLogDetail(smfOptVerbose.string);

#ifdef USE_INSTEAD_OF_REPORT_IF_SPAM
	optAlwaysAddReport.value = strcmp(optSpamdCommand.string, "REPORT") == 0;
#endif
	if (optSpamdCommand.initial != optSpamdCommand.string)
		TextUpper(optSpamdCommand.string, -1);

	if (optExtraDiscard.value < 0)
		optExtraDiscard.value = ~(unsigned long) 0 >> 1;
	if (optExtraReject.value < 0)
		optExtraReject.value = ~(unsigned long) 0 >> 1;

	optSpamdTimeout.value *= 1000;
	if (optSpamdTimeout.value < 0)
		optSpamdTimeout.value = 0;

	optSpamdMaxSize.value = optSpamdMaxSize.value * 1024 - optSpamdMaxSize.value / 64;

	openlog(MILTER_NAME, LOG_PID, LOG_MAIL);

	if (smfOptDaemon.value && smfStartBackgroundProcess())
		return 1;

	if (atexit(atExitCleanUp)) {
		syslog(LOG_ERR, "atexit() failed\n");
		return 1;
	}

	if (*smfOptAccessDb.string != '\0') {
		if (smfLogDetail & SMF_LOG_DATABASE)
			smdbSetDebugMask(SMDB_DEBUG_ALL);

		if ((smdbAccess = smdbOpen(smfOptAccessDb.string, 1)) == NULL) {
			syslog(LOG_ERR, "failed to open \"%s\"", smfOptAccessDb.string);
			return 1;
		}
	}

	if (smfLogDetail & SMF_LOG_SOCKET_ALL)
		socketSetDebug(10);
	else if (smfLogDetail & SMF_LOG_SOCKET_FD)
		socketSetDebug(1);

	if (socketInit()) {
		syslog(LOG_ERR, "socketInit() error\n");
		return 1;
	}

	return smfMainStart(&milter);
}
