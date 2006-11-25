include Makefile.conf

AGENT_OLD = config.o  agent_old.o
AGENT = config.o  agent.o

CMD = config.o cmd.o

all: agent cmd agent_old

cmd: ${CMD}
	$(CC)  -I. $(EXTRAOPTIONS) $(INCLUDE_LL)   -o bartlby_cmd ${CMD}
	
agent_old: ${AGENT_OLD} 
	$(CC)  -I. $(EXTRAOPTIONS) $(INCLUDE_LL)   -o bartlby_agent_old ${AGENT_OLD}
	
agent: ${AGENT} 
	$(CC)   -I. $(OPENSSL_ADDON) $(EXTRAOPTIONS) $(INCLUDE_LL)   -o bartlby_agent ${AGENT}


install:
	$(MKDIRP) $(BARTLBY_HOME);
	$(MKDIRP) $(PLUGIN_DIR);
	$(CPPVA) bartlby_agent_old $(BARTLBY_HOME)/
	$(CPPVA) bartlby_agent $(BARTLBY_HOME)/
	$(CPPVA) bartlby_cmd ${BARTLBY_HOME}/
	
	$(CPPVA) bartlby.cfg $(BARTLBY_HOME)/
	$(CPPVA) agent_sync.cfg $(BARTLBY_HOME)/
	$(CPPVA) agent_sync.sh $(BARTLBY_HOME)/

	



clean:
	$(RMVFR) *.o 
