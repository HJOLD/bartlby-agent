include Makefile.conf

AGENT = config.o  agent.o
CMD = config.o cmd.o

all: agent cmd

cmd: ${CMD}
	$(CC)   $(EXTRAOPTIONS) $(INCLUDE_LL)   -o bartlby_cmd ${CMD}
	
agent: ${AGENT} 
	$(CC)   $(EXTRAOPTIONS) $(INCLUDE_LL)   -o bartlby_agent ${AGENT}


install:
	$(MKDIRP) $(BARTLBY_HOME);
	$(MKDIRP) $(PLUGIN_DIR);
	$(CPPVA) bartlby_agent $(BARTLBY_HOME)/
	$(CPPVA) bartlby_cmd ${BARTLBY_HOME}/
	
	$(CPPVA) bartlby.cfg $(BARTLBY_HOME)/
	
	

	



clean:
	$(RMVFR) *.o 
