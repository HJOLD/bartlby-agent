include Makefile.conf

AGENT = config.o  agent.o

agent: ${AGENT} 
	$(CC)   $(EXTRAOPTIONS) $(INCLUDE_LL)   -o bartlby_agent ${AGENT}


install:
	$(MKDIRP) $(BARTLBY_HOME);
	$(CPPVA) bartlby_agent $(BARTLBY_HOME)/
	$(CPPVA) bartlby.cfg $(BARTLBY_HOME)/
	
	
all:    agent
	



clean:
	$(RMVFR) *.o 
