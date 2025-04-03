set(DEP_NAME            sparsehash-c11)
set(GIT_REPOSITORY      https://github.com/sparsehash/sparsehash-c11.git)
set(GIT_TAG             "edd6f1180156e76facc1c0449da245208ab39503" )

set(CLONE_DIR "${CMAKE_CURRENT_LIST_DIR}/${DEP_NAME}")
set(BUILD_DIR "${CLONE_DIR}/build/${VOLEPSI_CONFIG}")
set(LOG_FILE  "${CMAKE_CURRENT_LIST_DIR}/log-${DEP_NAME}.txt")


include("${CMAKE_CURRENT_LIST_DIR}/fetch.cmake")
execute_process(COMMAND chmod -R 755 ${LOG_DIR})

if(NOT SPARSEHASH_FOUND)

    if(EXISTS ${CLONE_DIR})
        message(WARNING "Removing existing directory: ${CLONE_DIR}")
        # For Linux, use rm -rf to remove the directory
        execute_process(COMMAND rm -rf ${CLONE_DIR})
    endif()

    find_program(GIT git REQUIRED)
    set(DOWNLOAD_CMD  ${GIT} clone ${GIT_REPOSITORY})
    set(CHECKOUT_CMD  ${GIT} checkout ${GIT_TAG})
    
    message("============= Building ${DEP_NAME} =============")
    if(NOT EXISTS ${CLONE_DIR})
        run(NAME "Cloning ${GIT_REPOSITORY}" CMD ${DOWNLOAD_CMD} WD ${CMAKE_CURRENT_LIST_DIR})
    endif()

    run(NAME "Checkout ${GIT_TAG} " CMD ${CHECKOUT_CMD}  WD ${CLONE_DIR})
    file(COPY ${CLONE_DIR}/sparsehash DESTINATION ${VOLEPSI_THIRDPARTY_DIR}/include/)
    #if(MSVC)
    #    message("Install")
    #    file(COPY ${CLONE_DIR}/src/windows/sparsehash DESTINATION ${VOLEPSI_THIRDPARTY_DIR}/include/)
    #else()
    #    file(COPY ${CLONE_DIR}/src/sparsehash DESTINATION ${VOLEPSI_THIRDPARTY_DIR}/include/)
    #    #run("Configure" CMD ./configure --prefix=${VOLEPSI_THIRDPARTY_DIR} WD ${CLONE_DIR})
    #    #run("make" CMD make -j ${PARALLEL_FETCH} WD ${CLONE_DIR})
    #    #run("install" CMD make install WD ${CLONE_DIR})
    #endif()
    message("log ${LOG_FILE}\n==========================================")
else()
    message("${DEP_NAME} already fetched.")
endif()


install(CODE "message(\"sparsehash begin ------------------\")")    
install(
    DIRECTORY "${CLONE_DIR}/sparsehash"
    DESTINATION "include")

install(CODE "message(\"sparsehash end ------------------\")")    
execute_process(COMMAND rm -rf ${CLONE_DIR})
