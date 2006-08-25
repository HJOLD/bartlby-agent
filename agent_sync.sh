#!/bin/sh
MY_PATH=`echo $0 | sed -e 's,[\\/][^\\/][^\\/]*$,,'`
cd $MY_PATH;
. agent_sync.cfg

function bartlby_dl_cfg {
	wget  -q --http-passwd=$BARTLBY_PW --http-user=$BARTLBY_USER -O bartlby.cfg "$BARTLBY_HTTP_HOST/extensions_wrap.php?script=AgentSyncer/getcfg.php"
	perl -i -pe "s#PLUGIN_DIR#$BARTLBY_PLUGIN_DIR#" bartlby.cfg
	echo "CFG updated";
}

function bartlby_dl_plg {
	wget  -q --http-passwd=$BARTLBY_PW --http-user=$BARTLBY_USER -O $BARTLBY_PLUGIN_DIR/$2 "$BARTLBY_HTTP_HOST/$1"
	chmod a+x $BARTLBY_PLUGIN_DIR/$2;
}	

function bartlby_get_plugin {
	if [ "$3" = "-" ];
	then
		echo "plugin: $2 missing on sync host";
		return;
	fi;
	if [ ! -f "$BARTLBY_PLUGIN_DIR/$2" ];
	then
		echo "DL: NEW PLG $2";
		bartlby_dl_plg $1 $2;
		return;
	fi;
	my_md=$(md5sum $BARTLBY_PLUGIN_DIR/$2|awk '{print $1}');
	
	if [ "$my_md" != "$3" ];
	then
		echo "DL: $url";
		bartlby_dl_plg $1 $2;
	else
		echo "plugin $2 is up-to-date";
	fi;
}


wget --http-passwd=$BARTLBY_PW --http-user=$BARTLBY_USER -q -O /dev/stdout "$BARTLBY_HTTP_HOST/extensions_wrap.php?script=AgentSyncer/sync.php&clientname=$BARTLBY_SYNC_CLIENTNAME"|while read cmd url fn md;
do
	if [ "$cmd" = "PLUGIN" ];
	then
		bartlby_get_plugin $url $fn $md
	fi;
	if [ "$cmd" = "ADDSERVER" ];
	then
		echo "client first time auto registered";
	fi;
	if [ "$cmd" = "SERVICEADD" ];
	then
		echo "$url service added";
	fi;
	if [ "$cmd" = "INSTPKG" ];
	then
		echo "Package $url installed";
	fi;
	if [ "$cmd" = "INFO" ];
	then
		echo "Info: $url";
	fi;
done;
bartlby_dl_cfg;