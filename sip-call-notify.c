/*
 * sip-call-notify
 * ---------------
 *
 * Rudimentary SIP client based on eXosip/osip that shows a small notification
 * on each incoming call using libnotify.
 *
 * Author: Mario Kicherer (http://kicherer.org)
 * License: GPL v2 (http://www.gnu.org/licenses/gpl-2.0.txt)
 *
 * Modern wireless routers like a AVM FritzBox also include telephony features
 * like a DECT base station and VoIP connectivity. Consequently, an incoming
 * call can be routed to the DECT and VoIP phones in parallel. This tool acts
 * as a VoIP phone using the SIP protocol and just shows a small notification
 * for every incoming call. Hence, you can immediately see who is calling
 * without having to look for your DECT phone.
 *
 * For an introduction into eXosip, see:
 *    http://www.antisip.com/doc/exosip2/modules.html
 * 
 * Usage example:
 *    sip-call-notify -s sip.server.com -u my_user -p my_password \
 *       -f "echo displayname: %s username: %s (From: %s)"
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <netinet/in.h>
#include <error.h>
#include <argp.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>

#include <eXosip2/eXosip.h>

#define ERR(var, id) { if (var<0) { print("error: %s\n", id); return 0; } }

char stop = 0;
char verbose = 0;
char detach = 0;
char *username = 0;
char *password = 0;
char *server = 0;
char *format = "notify-send -i internet-telephony \"Incoming call\" \"%s %s\"";

void print(char *format, ...) {
	if (!verbose)
		return;
	
	va_list va;
	va_start(va, format);
	
	vprintf(format, va);
	
	va_end(va);
}

void signalHandler( int signum ) {
	print("received SIGINT, cleaning up...\n");
	stop = 1;
}

int init(struct eXosip_t **ctx, int port) {
	int i;
	
	TRACE_INITIALIZE (6, NULL);
	
	*ctx = eXosip_malloc();
	if (*ctx==NULL)
		return -1;
	
	i=eXosip_init(*ctx);
	if (i!=0)
		return -1;
	
	i = eXosip_listen_addr (*ctx, IPPROTO_UDP, NULL, port, AF_INET, 0);
	if (i!=0) {
		eXosip_quit(*ctx);
		fprintf (stderr, "could not initialize transport layer\n");
		return -1;
	}
	
	return 0;
}

int set_auth(struct eXosip_t *ctx, char *username, char *userid, char *password) {
	eXosip_lock(ctx);
	eXosip_add_authentication_info(ctx, username, userid, password, NULL, NULL);
	eXosip_unlock(ctx);
	
	return 0;
}

int initial_register(struct eXosip_t *ctx, char *from, char *proxy, int *rid) {
	osip_message_t *reg = NULL;
	int i;
	
	
	eXosip_lock (ctx);
	*rid = eXosip_register_build_initial_register (ctx, from, proxy, NULL, 1800, &reg);
	if (*rid < 0) {
		print("eXosip_register_build_initial_register failed: %d %s\n", *rid, osip_strerror(*rid));
		eXosip_unlock (ctx);
		return -1;
	}
	
	osip_message_set_supported (reg, "100rel");
	osip_message_set_supported (reg, "path");
	i = eXosip_register_send_register (ctx, *rid, reg);
	eXosip_unlock (ctx);
	
	return i;
}

int deregister(struct eXosip_t *ctx, int rid) {
	osip_message_t *reg = NULL;
	int i;
	
	
	eXosip_lock (ctx);
	i = eXosip_register_build_register (ctx, rid, 0, &reg);
	if (i < 0) {
		eXosip_unlock (ctx);
		return -1;
	}
	
	eXosip_register_send_register (ctx, rid, reg);
	eXosip_unlock (ctx);
}

void print_event_type(int type) {
	switch (type) {
		case EXOSIP_REGISTRATION_SUCCESS: print("EXOSIP_REGISTRATION_SUCCESS"); break;
		case EXOSIP_REGISTRATION_FAILURE: print("EXOSIP_REGISTRATION_FAILURE"); break;
		
		case EXOSIP_CALL_INVITE: print("EXOSIP_CALL_INVITE"); break;
		case EXOSIP_CALL_REINVITE: print("EXOSIP_CALL_REINVITE"); break;
		
		case EXOSIP_CALL_NOANSWER: print("EXOSIP_CALL_NOANSWER"); break;
		case EXOSIP_CALL_PROCEEDING: print("EXOSIP_CALL_PROCEEDING"); break;
		case EXOSIP_CALL_RINGING: print("EXOSIP_CALL_RINGING"); break;
		case EXOSIP_CALL_ANSWERED: print("EXOSIP_CALL_ANSWERED"); break;
		case EXOSIP_CALL_REDIRECTED: print("EXOSIP_CALL_REDIRECTED"); break;
		case EXOSIP_CALL_REQUESTFAILURE: print("EXOSIP_CALL_REQUESTFAILURE"); break;
		case EXOSIP_CALL_SERVERFAILURE: print("EXOSIP_CALL_SERVERFAILURE"); break;
		case EXOSIP_CALL_GLOBALFAILURE: print("EXOSIP_CALL_GLOBALFAILURE"); break;
		case EXOSIP_CALL_ACK: print("EXOSIP_CALL_ACK"); break;
		case EXOSIP_CALL_CANCELLED: print("EXOSIP_CALL_CANCELLED"); break;
		
		case EXOSIP_CALL_MESSAGE_NEW: print("EXOSIP_CALL_MESSAGE_NEW"); break;
		case EXOSIP_CALL_MESSAGE_PROCEEDING: print("EXOSIP_CALL_MESSAGE_PROCEEDING"); break;
		case EXOSIP_CALL_MESSAGE_ANSWERED: print("EXOSIP_CALL_MESSAGE_ANSWERED"); break;
		case EXOSIP_CALL_MESSAGE_REDIRECTED: print("EXOSIP_CALL_MESSAGE_REDIRECTED"); break;
		case EXOSIP_CALL_MESSAGE_REQUESTFAILURE: print("EXOSIP_CALL_MESSAGE_REQUESTFAILURE"); break;
		case EXOSIP_CALL_MESSAGE_SERVERFAILURE: print("EXOSIP_CALL_MESSAGE_SERVERFAILURE"); break;
		case EXOSIP_CALL_MESSAGE_GLOBALFAILURE: print("EXOSIP_CALL_MESSAGE_GLOBALFAILURE"); break;
		case EXOSIP_CALL_CLOSED: print("EXOSIP_CALL_CLOSED"); break;
		case EXOSIP_CALL_RELEASED: print("EXOSIP_CALL_RELEASED"); break;
		
		case EXOSIP_MESSAGE_NEW: print("EXOSIP_MESSAGE_NEW"); break;
		case EXOSIP_MESSAGE_PROCEEDING: print("EXOSIP_MESSAGE_PROCEEDING"); break;
		case EXOSIP_MESSAGE_ANSWERED: print("EXOSIP_MESSAGE_ANSWERED"); break;
		case EXOSIP_MESSAGE_REDIRECTED: print("EXOSIP_MESSAGE_REDIRECTED"); break;
		case EXOSIP_MESSAGE_REQUESTFAILURE: print("EXOSIP_MESSAGE_REQUESTFAILURE"); break;
		case EXOSIP_MESSAGE_SERVERFAILURE: print("EXOSIP_MESSAGE_SERVERFAILURE"); break;
		case EXOSIP_MESSAGE_GLOBALFAILURE: print("EXOSIP_MESSAGE_GLOBALFAILURE"); break;
		
		case EXOSIP_SUBSCRIPTION_NOANSWER: print("EXOSIP_SUBSCRIPTION_NOANSWER"); break;
		case EXOSIP_SUBSCRIPTION_PROCEEDING: print("EXOSIP_SUBSCRIPTION_PROCEEDING"); break;
		case EXOSIP_SUBSCRIPTION_ANSWERED: print("EXOSIP_SUBSCRIPTION_ANSWERED"); break;
		case EXOSIP_SUBSCRIPTION_REDIRECTED: print("EXOSIP_SUBSCRIPTION_REDIRECTED"); break;
		case EXOSIP_SUBSCRIPTION_REQUESTFAILURE: print("EXOSIP_SUBSCRIPTION_REQUESTFAILURE"); break;
		case EXOSIP_SUBSCRIPTION_SERVERFAILURE: print("EXOSIP_SUBSCRIPTION_SERVERFAILURE"); break;
		case EXOSIP_SUBSCRIPTION_GLOBALFAILURE: print("EXOSIP_SUBSCRIPTION_GLOBALFAILURE"); break;
		case EXOSIP_SUBSCRIPTION_NOTIFY: print("EXOSIP_SUBSCRIPTION_NOTIFY"); break;
		
		case EXOSIP_IN_SUBSCRIPTION_NEW: print("EXOSIP_IN_SUBSCRIPTION_NEW"); break;
		
		case EXOSIP_NOTIFICATION_NOANSWER: print("EXOSIP_NOTIFICATION_NOANSWER"); break;
		case EXOSIP_NOTIFICATION_PROCEEDING: print("EXOSIP_NOTIFICATION_PROCEEDING"); break;
		case EXOSIP_NOTIFICATION_ANSWERED: print("EXOSIP_NOTIFICATION_ANSWERED"); break;
		case EXOSIP_NOTIFICATION_REDIRECTED: print("EXOSIP_NOTIFICATION_REDIRECTED"); break;
		case EXOSIP_NOTIFICATION_REQUESTFAILURE: print("EXOSIP_NOTIFICATION_REQUESTFAILURE"); break;
		case EXOSIP_NOTIFICATION_SERVERFAILURE: print("EXOSIP_NOTIFICATION_SERVERFAILURE"); break;
		case EXOSIP_NOTIFICATION_GLOBALFAILURE: print("EXOSIP_NOTIFICATION_GLOBALFAILURE"); break;
		default:
			print("TODO\n");
	}
}

static struct argp_option options[] = {
	{"verbose",  'v', 0, 0, "Produce verbose output" },
	{"daemonize",  'D', 0, 0, "Daemonize process and detach from terminal" },
	{"username", 'u', "username", 0, "Login name for SIP account"},
	{"password", 'p', "password", 0, "Password for SIP account. If \"-\" \
is specified the password is read from stdin."},
	{"server", 's', "server", 0, "Server or SIP proxy"},
	{"format", 'f', "format", 0, "Format string to execute a custom command. \
The first three \"%s\" are replaced with the display name, username and the \
complete \"from\" header."},
	{ 0 }
};

error_t parse_opt(int key, char *arg, struct argp_state *state) {
	switch (key) {
		case 'v':
			verbose = 1;
			break;
		case 'u':
			username = arg;
			break;
		case 'p':
			password = arg;
			break;
		case 's':
			server = arg;
			break;
		case 'D':
			detach = 1;
			break;
		case 'f':
			format = arg;
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

void daemonize() {
	// see http://www.linuxprofilm.com/articles/linux-daemon-howto.html
	pid_t pid, sid;
	
	if (detach) {
		pid = fork();
		if (pid < 0)
			exit(EXIT_FAILURE);
		if (pid > 0)
			exit(EXIT_SUCCESS);
		
		umask(0);
		
		sid = setsid();
		if (sid < 0)
			exit(EXIT_FAILURE);
	}
	
	if ((chdir("/")) < 0)
		exit(EXIT_FAILURE);
	
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	
	open("/dev/null", O_RDWR);
	dup(0);
	dup(0);
}

ssize_t read_password(char **lineptr, size_t *n, FILE *stream) {
	struct termios old, new;
	int nread, fno;
	
	fno = fileno(stream);
	
	if (tcgetattr(fno, &old) != 0)
		return -1;
	new = old;
	new.c_lflag &= ~ECHO;
	if (tcsetattr(fno, TCSAFLUSH, &new) != 0)
		return -1;
	
	nread = getline(lineptr, n, stream);
	
	tcsetattr(fno, TCSAFLUSH, &old);
	
	return nread;
}

int main(int argc, char **argv) {
	struct eXosip_t *ctx;
	eXosip_event_t *evt;
	int rid, r;
	char *allocated_password;
	
	struct argp argp = {options, parse_opt, 0, "\nRudimentary SIP client based \
on eXosip/osip that shows a small notification on each incoming call using \
libnotify"};
	argp_parse(&argp, argc, argv, 0, 0, 0);
	
	if (!username || !password || !server) {
		fprintf(stderr, "Error: server, username and password required!\n");
		argp_help(&argp, stdout, ARGP_HELP_USAGE, argv[0]);
		return 1;
	}
	
	if (!strcmp(password, "-")) {
		size_t n, len;
		n=0;
		len = read_password(&allocated_password, &n, stdin);
		allocated_password[len-1] = 0;
		password = allocated_password;
	} else
		allocated_password = 0;
	
	if (!verbose)
		daemonize();
	
	r = init(&ctx, 5060);
	ERR(r, "init");
	
	r = set_auth(ctx, username, username, password);
	ERR(r, "set_auth");
	
	if (allocated_password)
		free(allocated_password);
	
	char from[256], proxy[256];
	snprintf(from, 255, "sip:%s@%s", username, server);
	snprintf(proxy, 255, "sip:%s", server);
	r = initial_register(ctx, from, proxy, &rid);
	ERR(r, "initial_register");
	
	signal(SIGINT, signalHandler);
	while(!stop) {
		evt = eXosip_event_wait (ctx, 0, 50);
		eXosip_lock(ctx);
		eXosip_automatic_action (ctx);
		eXosip_unlock(ctx);
		if (evt == NULL)
			continue;
		
		print_event_type(evt->type); print("\n");
		
		switch (evt->type) {
		case EXOSIP_REGISTRATION_SUCCESS:
			print("login success\n");
			break;
		case EXOSIP_REGISTRATION_FAILURE:
			print("login failed\n");
			break;
		case EXOSIP_CALL_INVITE:
			{
				char *tmp = NULL;
				osip_from_t *from;
				char *start, *at, *username, *display;
				int len;
				
				
				osip_from_to_str(evt->request->from, &tmp);
				
				// manually parse From line as the osip parser doesn't work here
				display = 0;
				start = strchr(tmp, '"');
				if (start) {
					start = start + 1;
					at = strchr(start, '"');
					if (at) {
						len = at - start + 1;
						display = (char*) malloc(len+1);
						strncpy(display, start, len);
						display[len-1] = 0;
					}
				}
				
				username = 0;
				start = strchr(tmp, '<')+1;
				if (start && !strncmp(start, "sip:", 4)) {
					at = strchr(start, '@');
					if (at) {
						len = at - start - 3;
						username = (char*) malloc(len+1);
						strncpy(username, start+4, len);
						username[len-1] = 0;
					}
				}
				
				print("new call %s %s %s \n", tmp, display, username);
				
				char notify[256];
				snprintf(notify, 255, format, display, username, tmp);
				system(notify);
				
				osip_free(tmp);
				
				if (display)
					free(display);
				if (username)
					free(username);
			}
			break;
		default:
			print("unhandled event %d\n", evt->type);
		}
		
		eXosip_event_free(evt);
	}
	
	deregister(ctx, rid);
	ERR(r, "deregister");
	
	eXosip_quit(ctx);
	
	print("exit\n");
}