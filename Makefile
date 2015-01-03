
APP=sip-call-notify

### enable debug output
# CFLAGS+=-DENABLE_TRACE -g

LDFLAGS+=-leXosip2 -losipparser2

.phony: clean

$(APP): sip-call-notify.c
	$(CC) $< -o $@ $(LDFLAGS) $(CFLAGS)

clean:
	rm $(APP)