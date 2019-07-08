#!/bin/bash

if [ "${LOOP_ON_FAIL}" == "true" ]
then
  debug="bash -x"
  export PS4='\e[36m+ ${FUNCNAME:-main}\e[0m@\e[32m${BASH_SOURCE}:\e[35m${LINENO} \e[0m'
  set -x
fi

RUN_INIT=${1}
NOOBAA_SUPERVISOR="/data/noobaa_supervisor.conf"
NOOBAA_DATA_VERSION="/data/noobaa_version"
NOOBAA_PACKAGE_PATH="/root/node_modules/noobaa-core/package.json"

update_services_autostart() {
  local programs=(webserver bg_workers hosted_agents s3rver)
  local will_replace=false
    while read line; do
      if [[ ${line} =~ "program" ]]; then
        for program in ${programs[@]}; do
          if [[ ${line} =~ ${program} ]]; then
            will_replace=true
          fi
        done
      fi

      if [[ ${line} =~ "autostart" ]] && ${will_replace}; then
        echo ${line//true/false} >> ${NOOBAA_SUPERVISOR}.tmp
      else
        echo ${line} >> ${NOOBAA_SUPERVISOR}.tmp
      fi

      if [ "${line}" == "#endprogram" ]; then
        will_replace=false
      fi
    done < ${NOOBAA_SUPERVISOR}

  rm -rf ${NOOBAA_SUPERVISOR}
  mv ${NOOBAA_SUPERVISOR}.tmp ${NOOBAA_SUPERVISOR}
}

handle_unmanaged_upgrade() {
    #Container specific logic
    if grep -q PLATFORM=docker /data/.env; then
        code_version=$(grep version ${NOOBAA_PACKAGE_PATH} | awk -F'["|"]' '{print $4}')
        if [ ! -f ${NOOBAA_DATA_VERSION} ]; then 
            #New system, update data version file
            echo ${code_version} > ${NOOBAA_DATA_VERSION}
        else
            data_version=$(cat ${NOOBAA_DATA_VERSION})
            #verify if we need to start an un-managed upgrade
            if [ "${code_version}" != "${data_version}" ]; then
                logger -p local0.warn -t Superd "Code version ${code_version} differs from data version ${data_version}, initiating unmanaged upgrade"

                #code version differs from data version, need to initiate un-managed upgrade
                update_services_autostart
                cat >> ${NOOBAA_SUPERVISOR} << EOF

[program:upgrade_manager]
stopsignal=KILL
priority=1
autostart=true
directory=/root/node_modules/noobaa-core/
stdout_logfile=/dev/fd/1
stdout_logfile_maxbytes=0
stderr_logfile=/dev/fd/1
stderr_logfile_maxbytes=0
command=/usr/local/bin/node src/upgrade/upgrade_manager.js --old_version ${data_version} --unmanaged true
#endprogram
EOF
            fi
        fi
    fi
}

fix_non_root_user() {
  # in openshift, when not running as root - ensure that assigned uid has entry in /etc/passwd.
  if [ $(id -u) -ne 0 ]; then
      local NOOBAA_USER=noob
      if ! grep -q ${NOOBAA_USER}:x /etc/passwd; then
        echo "${NOOBAA_USER}:x:$(id -u):$(id -g):,,,:/home/$NOOBAA_USER:/bin/bash" >> /etc/passwd
      fi
  fi
}

extract_noobaa_in_docker() {
  local tar="noobaa-NVA.tar.gz"
  local noobaa_core_path="/root/node_modules/noobaa-core/"
  if [ "${container}" == "docker" ] && [ ! -d ${noobaa_core_path} ] ; then
    cd /root/node_modules
    tar -xzf /tmp/noobaa-NVA.tar.gz
    cd ~
    rm -rf /tmp/${tar}
  fi
}

run_kube_pv_chown() {
  local parameter=${1}
  # change ownership and permissions of /data and /log. 
  # assuming that uid is not changed between reboots.
  local path="/root/node_modules/noobaa-core/build/Release/"
  if [ "${container}" == "docker" ] ; then
      path="/noobaa_init_files/"
  fi
  ${path}/kube_pv_chown ${parameter}
}

run_init_scripts() {
  local script
  local scripts=(fix_server_plat.sh fix_mongo_ssl.sh)
  local path="/root/node_modules/noobaa-core/src/deploy/NVA_build/"
  ############## run init scripts
  run_kube_pv_chown server
  cd ${path}
  for script in ${scripts[@]} ; do
    ${debug} ./${script}
    if [ $? -ne 0 ] ; then
      #Providing an env variable with the name "LOOP_ON_FAIL=true" 
      #will trigger the condition below.
      while [ "${LOOP_ON_FAIL}" == "true" ]
      do
        echo "$(date) Failed to run ${script}"
        sleep 10
      done
    fi
  done
  cd - > /dev/null
}

run_agent_container() {
  AGENT_CONF_FILE="/noobaa_storage/agent_conf.json"
  if [ -z ${AGENT_CONFIG} ]
  then
    echo "AGENT_CONFIG is required ENV variable. AGENT_CONFIG is missing. Exit"
    exit 1
  else
    echo "Got base64 agent_conf: ${AGENT_CONFIG}"
    if [ ! -f $AGENT_CONF_FILE ]; then
      openssl enc -base64 -d -A <<<${AGENT_CONFIG} >${AGENT_CONF_FILE}
    fi
    echo "Written agent_conf.json: $(cat ${AGENT_CONF_FILE})"
  fi
  node ./src/agent/agent_cli
  # Providing an env variable with the name "LOOP_ON_FAIL=true" 
  # will trigger the condition below.
  # Currently we will loop on any exit of the agent_cli 
  # regurdless to the exit code
  while [ "${LOOP_ON_FAIL}" == "true" ] 
  do
    echo "$(date) Failed to run agent_cli" 
    sleep 10
  done
}

init_noobaa_server() {
  fix_non_root_user
  extract_noobaa_in_docker
  run_init_scripts

  #check if unmamnaged upgrade is required
  handle_unmanaged_upgrade
}

init_noobaa_agent() {
  fix_non_root_user
  extract_noobaa_in_docker
  
  mkdir -p /noobaa_storage
  run_kube_pv_chown agent

  cd /root/node_modules/noobaa-core/
  run_agent_container
}

if [ "${RUN_INIT}" == "agent" ]
then
  init_noobaa_agent
else
  init_noobaa_server
fi
