cmake_minimum_required(VERSION 3.16)
project(a2a_agent C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-unused-parameter -Wno-stringop-truncation -O2")

find_library(CJSON_LIB cjson REQUIRED)

include_directories(${CMAKE_SOURCE_DIR}/include)

add_executable(a2a_agent
    src/main.c

    # Agent core
    src/agent_core/a2a_agent.c
    src/agent_core/a2a_fsm.c
    src/agent_core/a2a_event.c
    src/agent_core/a2a_heartbeat.c

    # Messaging layer
    src/a2a_messaging/a2a_transport.c
    src/a2a_messaging/a2a_connpool.c
    src/a2a_messaging/a2a_framing.c

    # Serialization
    src/common/a2a_serialize.c
    src/common/a2a_log.c

    # L2 agent
    src/l2_agent/l2_agent.c

    # L3 agent + Netlink monitor
    src/l3_agent/l3_agent.c
    src/l3_agent/l3_netlink.c

    # OVS integration (OVSDB + OpenFlow native)
    src/ovs/ovs_interface.c
    src/ovs/ovs_ovsdb.c
    src/ovs/ovs_openflow.c
)

target_link_libraries(a2a_agent ${CJSON_LIB})

option(BUILD_TESTS "Build test binaries" OFF)
if(BUILD_TESTS)
    add_executable(test_transport tests/test_transport.c
                   src/a2a_messaging/a2a_transport.c
                   src/common/a2a_serialize.c
                   src/common/a2a_log.c
                   src/a2a_messaging/a2a_framing.c)
    target_link_libraries(test_transport ${CJSON_LIB})
endif()
